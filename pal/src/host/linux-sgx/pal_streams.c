/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to open, read, write and get attribute of streams.
 */

#include <asm/fcntl.h>
#include <asm/stat.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/types.h>
#include <stdalign.h>
#include <stdbool.h>

#include "api.h"
#include "asan.h"
#include "crypto.h"
#include "linux_socket.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "perm.h"

#define DUMMYPAYLOAD     "dummypayload"
#define DUMMYPAYLOADSIZE (sizeof(DUMMYPAYLOAD))

static int g_log_fd = PAL_LOG_DEFAULT_FD;

struct hdl_header {
    bool has_fd;       /* true if PAL handle has a corresponding host file descriptor */
    size_t  data_size; /* total size of serialized PAL handle */
};

static ssize_t handle_serialize(PAL_HANDLE handle, void** data) {
    int ret;
    const void* field = NULL;
    size_t field_size = 0;
    bool free_field = false;

    /* find a field to serialize (depends on the handle type); note that
     * no handle type has more than one such field, and some have none */
    switch (handle->hdr.type) {
        case PAL_TYPE_PIPE:
        case PAL_TYPE_PIPECLI:
            /* session key is part of handle but need to serialize SSL context */
            if (handle->pipe.ssl_ctx) {
                free_field = true;
                ret = _PalStreamSecureSave(handle->pipe.ssl_ctx, (const uint8_t**)&field,
                                           &field_size);
                if (ret < 0)
                    return -PAL_ERROR_DENIED;
            }
            /* no need to serialize handshake_helper_thread_hdl */
            break;
        case PAL_TYPE_PIPESRV:
            /* no need to serialize ssl_ctx and handshake_helper_thread_hdl */
            break;
        case PAL_TYPE_CONSOLE:
            /* console (stdin/stdout/stderr) has no fields to serialize */
            break;
        case PAL_TYPE_DEV:
            field = handle->dev.realpath;
            field_size = strlen(handle->dev.realpath) + 1;
            break;
        case PAL_TYPE_FILE:
            field = handle->file.realpath;
            field_size = strlen(handle->file.realpath) + 1;
            /* no need to serialize chunk_hashes & umem */
            break;
        case PAL_TYPE_DIR:
            field = handle->dir.realpath;
            field_size = strlen(handle->dir.realpath) + 1;
            /* no need to serialize buf/ptr/end */
            break;
        case PAL_TYPE_SOCKET:
            /* sock.ops field will be fixed in deserialize */
            break;
        case PAL_TYPE_PROCESS:
            /* session key is part of handle but need to serialize SSL context */
            if (handle->process.ssl_ctx) {
                free_field = true;
                ret = _PalStreamSecureSave(handle->process.ssl_ctx, (const uint8_t**)&field,
                                           &field_size);
                if (ret < 0)
                    return -PAL_ERROR_DENIED;
            }
            break;
        case PAL_TYPE_EVENTFD:
            /* eventfds have no fields to serialize */
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    size_t hdl_size = handle_size(handle);
    size_t buffer_size = hdl_size + field_size;
    void* buffer = malloc(buffer_size);
    if (!buffer) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    /* copy into buffer all handle fields and then serialized fields */
    memcpy(buffer, handle, hdl_size);
    if (field_size)
        memcpy(buffer + hdl_size, field, field_size);

    *data = buffer;
    ret = buffer_size;

out:
    if (free_field)
        free((void*)field);

    return ret;
}

static int handle_deserialize(PAL_HANDLE* handle, const void* data, size_t size, int host_fd) {
    int ret;

    size_t hdl_size = handle_size((PAL_HANDLE)data);
    PAL_HANDLE hdl = malloc(hdl_size);
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    memcpy(hdl, data, hdl_size);

    /* update handle fields to point to correct contents */
    assert(hdl_size <= size);
    switch (hdl->hdr.type) {
        case PAL_TYPE_PIPE:
        case PAL_TYPE_PIPECLI:
            /* session key is part of handle but need to deserialize SSL context */
            hdl->pipe.fd = host_fd; /* correct host FD must be passed to SSL context */
            ret = _PalStreamSecureInit(hdl, hdl->pipe.is_server, &hdl->pipe.session_key,
                                       (LIB_SSL_CONTEXT**)&hdl->pipe.ssl_ctx,
                                       (const uint8_t*)data + hdl_size, size - hdl_size);
            if (ret < 0) {
                free(hdl);
                return -PAL_ERROR_DENIED;
            }
            hdl->pipe.handshake_helper_thread_hdl = NULL;
            break;
        case PAL_TYPE_PIPESRV:
            hdl->pipe.ssl_ctx = NULL;
            hdl->pipe.handshake_helper_thread_hdl = NULL;
            break;
        case PAL_TYPE_CONSOLE:
            break;
        case PAL_TYPE_DEV: {
            hdl->dev.realpath = alloc_and_copy((const char*)data + hdl_size, size - hdl_size);
            if (!hdl->dev.realpath) {
                free(hdl);
                return -PAL_ERROR_NOMEM;
            }
            break;
        }
        case PAL_TYPE_FILE: {
            hdl->file.realpath = alloc_and_copy((const char*)data + hdl_size, size - hdl_size);
            if (!hdl->file.realpath) {
                free(hdl);
                return -PAL_ERROR_NOMEM;
            }
            hdl->file.chunk_hashes = hdl->file.umem = NULL; /* set up in below fixup function */
            hdl->file.fd = host_fd;   /* correct host FD must be set for below fixup function */
            fixup_file_handle_after_deserialization(hdl);
            break;
        }
        case PAL_TYPE_DIR: {
            hdl->dir.realpath = alloc_and_copy((const char*)data + hdl_size, size - hdl_size);
            if (!hdl->dir.realpath) {
                free(hdl);
                return -PAL_ERROR_NOMEM;
            }
            hdl->dir.buf = hdl->dir.ptr = hdl->dir.end = NULL;
            break;
        }
        case PAL_TYPE_SOCKET:
            fixup_socket_handle_after_deserialization(hdl);
            break;
        case PAL_TYPE_PROCESS:
            /* session key is part of handle but need to deserialize SSL context */
            hdl->process.stream = host_fd; /* correct host FD must be passed to SSL context */
            ret = _PalStreamSecureInit(hdl, hdl->process.is_server, &hdl->process.session_key,
                                       (LIB_SSL_CONTEXT**)&hdl->process.ssl_ctx,
                                       (const uint8_t*)data + hdl_size, size - hdl_size);
            if (ret < 0) {
                free(hdl);
                return -PAL_ERROR_DENIED;
            }
            break;
        case PAL_TYPE_EVENTFD:
            break;
        default:
            free(hdl);
            return -PAL_ERROR_BADHANDLE;
    }

    *handle = hdl;
    return 0;
}

int _PalSendHandle(PAL_HANDLE target_process, PAL_HANDLE cargo) {
    if (target_process->hdr.type != PAL_TYPE_PROCESS)
        return -PAL_ERROR_BADHANDLE;

    /* serialize cargo handle into a blob hdl_data */
    void* hdl_data = NULL;
    ssize_t hdl_data_size = handle_serialize(cargo, &hdl_data);
    if (hdl_data_size < 0)
        return hdl_data_size;

    ssize_t ret;
    struct hdl_header hdl_hdr = {
        .has_fd = cargo->flags & (PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE),
        .data_size = hdl_data_size
    };
    int fd = target_process->process.stream;

    /* first send hdl_hdr so recipient knows how many FDs were transferred + how large is cargo */
    struct iovec iov = {
        .iov_base = &hdl_hdr,
        .iov_len = sizeof(struct hdl_header),
    };
    ret = ocall_send(fd, &iov, 1, NULL, 0, NULL, 0, 0);
    if (ret < 0) {
        free(hdl_data);
        return unix_to_pal_error(ret);
    }

    /* construct ancillary data with FD-to-transfer in a control message */
    alignas(struct cmsghdr) char control_buf[CMSG_SPACE(sizeof(int))] = { 0 };

    struct cmsghdr* control_hdr = (struct cmsghdr*)control_buf;
    control_hdr->cmsg_level     = SOL_SOCKET;
    control_hdr->cmsg_type      = SCM_RIGHTS;
    if (hdl_hdr.has_fd) {
        /* XXX: change to `SAME_TYPE` once `PAL_HANDLE` uses `int` to store fds */
        static_assert(sizeof(cargo->generic.fd) == sizeof(int), "required");
        control_hdr->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(control_hdr), &cargo->generic.fd, sizeof(int));
    } else {
        control_hdr->cmsg_len = CMSG_LEN(0);
    }

    /* next send FD-to-transfer as ancillary data */
    iov.iov_base = (void*)DUMMYPAYLOAD;
    iov.iov_len = DUMMYPAYLOADSIZE;
    ret = ocall_send(fd, &iov, 1, NULL, 0, control_hdr, control_hdr->cmsg_len, 0);
    if (ret < 0) {
        free(hdl_data);
        return unix_to_pal_error(ret);
    }

    /* finally send the serialized cargo as payload (possibly encrypted) */
    if (target_process->process.ssl_ctx) {
        ret = _PalStreamSecureWrite(target_process->process.ssl_ctx, (uint8_t*)hdl_data,
                                    hdl_hdr.data_size,
                                    /*is_blocking=*/!target_process->process.nonblocking);
    } else {
        ret = ocall_write(fd, hdl_data, hdl_hdr.data_size);
        ret = ret < 0 ? unix_to_pal_error(ret) : ret;
    }

    free(hdl_data);
    return ret < 0 ? ret : 0;
}

int _PalReceiveHandle(PAL_HANDLE source_process, PAL_HANDLE* out_cargo) {
    if (source_process->hdr.type != PAL_TYPE_PROCESS)
        return -PAL_ERROR_BADHANDLE;

    ssize_t ret;
    struct hdl_header hdl_hdr;
    int fd = source_process->process.stream;

    /* first receive hdl_hdr so that we know how many FDs were transferred + how large is cargo */
    struct iovec iov = {
        .iov_base = &hdl_hdr,
        .iov_len = sizeof(hdl_hdr),
    };
    ret = ocall_recv(fd, &iov, 1, NULL, NULL, NULL, NULL, 0);
    if (ret < 0)
        return unix_to_pal_error(ret);

    if ((size_t)ret != sizeof(hdl_hdr)) {
        return -PAL_ERROR_DENIED;
    }

    alignas(struct cmsghdr) char control_buf[CMSG_SPACE(sizeof(int))] = { 0 };
    size_t control_buf_size = sizeof(control_buf);

    /* next receive FDs-to-transfer as ancillary data */
    char dummypayload[DUMMYPAYLOADSIZE];
    iov.iov_base = dummypayload;
    iov.iov_len = sizeof(dummypayload);
    ret = ocall_recv(fd, &iov, 1, NULL, NULL, control_buf, &control_buf_size, MSG_CMSG_CLOEXEC);
    if (ret < 0)
        return unix_to_pal_error(ret);
    if (control_buf_size < sizeof(struct cmsghdr)) {
        return -PAL_ERROR_DENIED;
    }

    /* finally receive the serialized cargo as payload (possibly encrypted) */
    char hdl_data[hdl_hdr.data_size];

    if (source_process->process.ssl_ctx) {
        ret = _PalStreamSecureRead(source_process->process.ssl_ctx,
                                   (uint8_t*)hdl_data, hdl_hdr.data_size,
                                   /*is_blocking=*/!source_process->process.nonblocking);
    } else {
        ret = ocall_read(fd, hdl_data, hdl_hdr.data_size);
        ret = ret < 0 ? unix_to_pal_error(ret) : ret;
    }
    if (ret < 0)
        return ret;

    struct cmsghdr* control_hdr = (struct cmsghdr*)control_buf;
    if (control_hdr->cmsg_type != SCM_RIGHTS)
        return -PAL_ERROR_DENIED;
    if (hdl_hdr.has_fd && control_hdr->cmsg_len != CMSG_LEN(sizeof(int))) {
        return -PAL_ERROR_DENIED;
    }

    int host_fd = -1;
    if (hdl_hdr.has_fd) {
        memcpy(&host_fd, CMSG_DATA(control_hdr), sizeof(int));
    }

    /* deserialize cargo handle from a blob hdl_data */
    PAL_HANDLE handle = NULL;
    ret = handle_deserialize(&handle, hdl_data, hdl_hdr.data_size, host_fd);
    if (ret < 0)
        return ret;

    /* restore cargo handle's FD from the received FD-to-transfer */
    if (hdl_hdr.has_fd) {
        handle->generic.fd = host_fd;
    } else {
        handle->flags &= ~(PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE);
    }

    *out_cargo = handle;
    return 0;
}

int _PalInitDebugStream(const char* path) {
    int ret;

    if (g_log_fd != PAL_LOG_DEFAULT_FD) {
        ret = ocall_close(g_log_fd);
        g_log_fd = PAL_LOG_DEFAULT_FD;
        if (ret < 0)
            return unix_to_pal_error(ret);
    }

    ret = ocall_open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, PERM_rw_______);
    if (ret < 0)
        return unix_to_pal_error(ret);
    g_log_fd = ret;
    return 0;
}

int _PalDebugLog(const void* buf, size_t size) {
    if (g_log_fd < 0)
        return -PAL_ERROR_BADHANDLE;

    // TODO: add retrying on EINTR
    ssize_t ret = ocall_write(g_log_fd, buf, size);
    if (ret < 0 || (size_t)ret != size) {
        return ret < 0 ? unix_to_pal_error(ret) : -PAL_ERROR_INTERRUPTED;
    }
    return 0;
}
