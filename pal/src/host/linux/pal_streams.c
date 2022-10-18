/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to open, read, write and get attribute of streams.
 */

#include <asm/fcntl.h>
#include <stdalign.h>
#include <stdbool.h>

#include "api.h"
#include "linux_socket.h"
#include "linux_utils.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "perm.h"
#include "stat.h"

static int g_log_fd = PAL_LOG_DEFAULT_FD;

struct hdl_header {
    bool has_fd;       /* true if PAL handle has a corresponding host file descriptor */
    size_t  data_size; /* total size of serialized PAL handle */
};

int handle_set_cloexec(PAL_HANDLE handle, bool enable) {
    if (handle->flags & (PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE)) {
        long flags = enable ? FD_CLOEXEC : 0;
        int ret = DO_SYSCALL(fcntl, handle->generic.fd, F_SETFD, flags);
        if (ret < 0 && ret != -EBADF)
            return -PAL_ERROR_DENIED;
    }

    return 0;
}

/* _PalStreamUnmap for internal use. Unmap stream at certain memory address. The memory is unmapped
 *  as a whole.*/
int _PalStreamUnmap(void* addr, uint64_t size) {
    /* Just let the kernel tell us if the mapping isn't good. */
    int ret = DO_SYSCALL(munmap, addr, size);

    if (ret < 0)
        return -PAL_ERROR_DENIED;

    return 0;
}

int handle_serialize(PAL_HANDLE handle, void** data) {
    const void* field = NULL;
    size_t field_size = 0;

    /* find a field to serialize (depends on the handle type); note that
     * no handle type has more than one such field, and some have none */
    switch (handle->hdr.type) {
        case PAL_TYPE_FILE:
            field = handle->file.realpath;
            field_size = strlen(handle->file.realpath) + 1;
            break;
        case PAL_TYPE_PIPE:
        case PAL_TYPE_PIPESRV:
        case PAL_TYPE_PIPECLI:
            /* pipes have no fields to serialize */
            break;
        case PAL_TYPE_DEV:
            /* devices have no fields to serialize */
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
            /* processes have no fields to serialize */
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
    if (!buffer)
        return -PAL_ERROR_NOMEM;

    /* copy into buffer all handle fields and then serialized fields */
    memcpy(buffer, handle, hdl_size);
    if (field_size)
        memcpy(buffer + hdl_size, field, field_size);

    *data = buffer;
    return buffer_size;
}

int handle_deserialize(PAL_HANDLE* handle, const void* data, size_t size) {
    size_t hdl_size = handle_size((PAL_HANDLE)data);
    PAL_HANDLE hdl = malloc(hdl_size);
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    memcpy(hdl, data, hdl_size);

    /* update handle fields to point to correct contents */
    switch (hdl->hdr.type) {
        case PAL_TYPE_FILE: {
            assert(hdl_size < size);

            size_t path_size = size - hdl_size;
            char* path = malloc(path_size);
            if (!path) {
                free(hdl);
                return -PAL_ERROR_NOMEM;
            }

            memcpy(path, (const char*)data + hdl_size, path_size);

            hdl->file.realpath = path;
            break;
        }
        case PAL_TYPE_PIPE:
        case PAL_TYPE_PIPESRV:
        case PAL_TYPE_PIPECLI:
            break;
        case PAL_TYPE_DEV:
            break;
        case PAL_TYPE_DIR: {
            assert(hdl_size < size);

            size_t path_size = size - hdl_size;
            char* path = malloc(path_size);
            if (!path) {
                free(hdl);
                return -PAL_ERROR_NOMEM;
            }

            memcpy(path, (const char*)data + hdl_size, path_size);

            hdl->dir.realpath = path;
            hdl->dir.buf = hdl->dir.ptr = hdl->dir.end = NULL;
            break;
        }
        case PAL_TYPE_SOCKET:
            fixup_socket_handle_after_deserialization(hdl);
            break;
        case PAL_TYPE_PROCESS:
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

    /* first send hdl_hdr so the recipient knows if a FD is transferred + how large is cargo */
    struct msghdr message_hdr = {0};
    struct iovec iov[1];

    iov[0].iov_base    = &hdl_hdr;
    iov[0].iov_len     = sizeof(hdl_hdr);
    message_hdr.msg_iov    = iov;
    message_hdr.msg_iovlen = 1;

    ret = DO_SYSCALL(sendmsg, fd, &message_hdr, MSG_NOSIGNAL);
    if (ret < 0) {
        free(hdl_data);
        return unix_to_pal_error(ret);
    }

    /* construct ancillary data with FD-to-transfer in a control message */
    alignas(struct cmsghdr) char control_buf[CMSG_SPACE(sizeof(int))] = { 0 };
    message_hdr.msg_control    = control_buf;
    message_hdr.msg_controllen = sizeof(control_buf);

    struct cmsghdr* control_hdr = CMSG_FIRSTHDR(&message_hdr);
    control_hdr->cmsg_level = SOL_SOCKET;
    control_hdr->cmsg_type  = SCM_RIGHTS;
    if (hdl_hdr.has_fd) {
        /* XXX: change to `SAME_TYPE` once `PAL_HANDLE` uses `int` to store fds */
        static_assert(sizeof(cargo->generic.fd) == sizeof(int), "required");
        control_hdr->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(control_hdr), &cargo->generic.fd, sizeof(int));
    } else {
        control_hdr->cmsg_len = CMSG_LEN(0);
    }

    /* finally send the serialized cargo as payload and FDs-to-transfer as ancillary data */
    iov[0].iov_base = hdl_data;
    iov[0].iov_len  = hdl_data_size;
    message_hdr.msg_iov    = iov;
    message_hdr.msg_iovlen = 1;

    ret = DO_SYSCALL(sendmsg, fd, &message_hdr, 0);
    if (ret < 0) {
        free(hdl_data);
        return unix_to_pal_error(ret);
    }

    free(hdl_data);
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

int _PalReceiveHandle(PAL_HANDLE source_process, PAL_HANDLE* out_cargo) {
    if (source_process->hdr.type != PAL_TYPE_PROCESS)
        return -PAL_ERROR_BADHANDLE;

    ssize_t ret;
    struct hdl_header hdl_hdr;
    int fd = source_process->process.stream;

    /* first receive hdl_hdr so that we know how many FDs were transferred + how large is cargo */
    struct msghdr message_hdr = {0};
    struct iovec iov[1];

    iov[0].iov_base = &hdl_hdr;
    iov[0].iov_len  = sizeof(hdl_hdr);
    message_hdr.msg_iov    = iov;
    message_hdr.msg_iovlen = 1;

    ret = DO_SYSCALL(recvmsg, fd, &message_hdr, 0);
    if (ret < 0)
        return unix_to_pal_error(ret);

    if ((size_t)ret != sizeof(hdl_hdr)) {
        return -PAL_ERROR_DENIED;
    }

    alignas(struct cmsghdr) char control_buf[CMSG_SPACE(sizeof(int))] = { 0 };
    message_hdr.msg_control    = control_buf;
    message_hdr.msg_controllen = sizeof(control_buf);

    /* finally receive the serialized cargo as payload and FDs-to-transfer as ancillary data */
    char hdl_data[hdl_hdr.data_size];

    iov[0].iov_base = hdl_data;
    iov[0].iov_len  = hdl_hdr.data_size;
    message_hdr.msg_iov    = iov;
    message_hdr.msg_iovlen = 1;

    ret = DO_SYSCALL(recvmsg, fd, &message_hdr, MSG_CMSG_CLOEXEC);
    if (ret < 0)
        return unix_to_pal_error(ret);

    struct cmsghdr* control_hdr = CMSG_FIRSTHDR(&message_hdr);
    if (!control_hdr || control_hdr->cmsg_type != SCM_RIGHTS)
        return -PAL_ERROR_DENIED;

    /* deserialize cargo handle from a blob hdl_data */
    PAL_HANDLE handle = NULL;
    ret = handle_deserialize(&handle, hdl_data, hdl_hdr.data_size);
    if (ret < 0)
        return ret;

    /* restore cargo handle's FDs from the received FDs-to-transfer */
    if (hdl_hdr.has_fd) {
        assert(control_hdr->cmsg_len == CMSG_LEN(sizeof(int)));
        memcpy(&handle->generic.fd, CMSG_DATA(control_hdr), sizeof(int));
    } else {
        handle->flags &= ~(PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE);
        handle->generic.fd = -1;
    }

    *out_cargo = handle;
    return 0;
}

int _PalInitDebugStream(const char* path) {
    int ret;

    if (g_log_fd != PAL_LOG_DEFAULT_FD) {
        ret = DO_SYSCALL(close, g_log_fd);
        g_log_fd = PAL_LOG_DEFAULT_FD;
        if (ret < 0)
            return unix_to_pal_error(ret);
    }

    ret = DO_SYSCALL(open, path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, PERM_rw_______);
    if (ret < 0)
        return unix_to_pal_error(ret);
    g_log_fd = ret;
    return 0;
}

int _PalDebugLog(const void* buf, size_t size) {
    if (g_log_fd < 0)
        return -PAL_ERROR_BADHANDLE;

    int ret = write_all(g_log_fd, buf, size);
    if (ret < 0)
        return unix_to_pal_error(ret);
    return 0;
}
