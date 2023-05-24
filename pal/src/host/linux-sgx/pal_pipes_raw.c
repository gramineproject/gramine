/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

/*
 * This file contains operands to handle streams with URIs that start with "pipe.raw:" or
 * "pipe.raw.srv:".
 */

#include <asm/fcntl.h>
#include <asm/poll.h>
#include <linux/types.h>
#include <linux/un.h>

#include "api.h"
#include "linux_utils.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_flags_conv.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"

/*!
 * \brief Create a listening abstract UNIX socket as preparation for connecting two ends of a pipe.
 *
 * \param[out] handle   PAL handle of type `piperawsrv` with abstract UNIX socket opened for
 *                      listening.
 * \param      name     String uniquely identifying the pipe.
 * \param      options  May contain PAL_OPTION_NONBLOCK.
 *
 * \returns 0 on success, negative PAL error code otherwise.
 *
 * An abstract UNIX socket with name "/gramine/<pipename>" is opened for listening. A corresponding
 * PAL handle with type `piperawsrv` is created. This PAL handle typically serves only as an
 * intermediate step to connect two ends of the pipe (`piperawcli` and `piperaw`). As soon as the
 * other end of the pipe connects to this listening socket, a new accepted socket and the
 * corresponding PAL handle are created, and this `piperawsrv` handle can be closed.
 */
static int pipe_listen(PAL_HANDLE* handle, const char* name, pal_stream_options_t options) {
    int ret;

    struct sockaddr_un addr;
    ret = get_gramine_unix_socket_addr(name, &addr);
    if (ret < 0)
        return -PAL_ERROR_DENIED;

    size_t addrlen = sizeof(struct sockaddr_un);
    int nonblock = options & PAL_OPTION_NONBLOCK ? SOCK_NONBLOCK : 0;

    ret = ocall_listen(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | nonblock, 0, /*ipv6_v6only=*/0,
                       (struct sockaddr*)&addr, &addrlen);
    if (ret < 0)
        return unix_to_pal_error(ret);

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(pipe));
    if (!hdl) {
        ocall_close(ret);
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(hdl, PAL_TYPE_PIPERAWSRV);
    hdl->flags |= PAL_HANDLE_FD_READABLE; /* cannot write to a listening socket */
    hdl->pipe.fd          = ret;
    hdl->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);

    *handle = hdl;
    return 0;
}

/*!
 * \brief Accept the other end of the pipe and create PAL handle for our end of the pipe.
 *
 * \param      handle   PAL handle of type `piperawsrv` with abstract UNIX socket opened for
 *                      listening.
 * \param[out] client   PAL handle of type `piperawcli` connected to the other end of the pipe
 *                      (`piperaw`).
 * \param      options  flags to set on \p client handle.
 *
 * \returns 0 on success, negative PAL error code otherwise.
 *
 * Caller creates a `piperawsrv` PAL handle with the underlying abstract UNIX socket opened for
 * listening, and then calls this function to wait for the other end of the pipe to connect.
 * When the connection request arrives, a new `piperawcli` PAL handle is created with the
 * corresponding underlying socket and is returned in `client`. This `piperawcli` PAL handle denotes
 * our end of the pipe. Typically, `piperawsrv` handle is not needed after this and can be closed.
 */
static int pipe_waitforclient(PAL_HANDLE handle, PAL_HANDLE* client, pal_stream_options_t options) {
    if (handle->hdr.type != PAL_TYPE_PIPERAWSRV)
        return -PAL_ERROR_NOTSERVER;

    if (handle->pipe.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    assert(WITHIN_MASK(options, PAL_OPTION_NONBLOCK));
    int flags = PAL_OPTION_TO_LINUX_OPEN(options) | SOCK_CLOEXEC;
    int ret = ocall_accept(handle->pipe.fd, /*addr=*/NULL, /*addrlen=*/NULL, /*local_addr=*/NULL,
                           /*local_addrlen=*/NULL, flags);

    PAL_HANDLE clnt = calloc(1, HANDLE_SIZE(pipe));
    if (!clnt) {
        ocall_close(ret);
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(clnt, PAL_TYPE_PIPERAWCLI);
    clnt->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
    clnt->pipe.fd          = ret;
    clnt->pipe.nonblocking = !!(flags & SOCK_NONBLOCK);

    *client = clnt;
    return 0;
}

/*!
 * \brief Connect to the other end of the pipe and create PAL handle for our end of the pipe.
 *
 * \param[out] handle   PAL handle of type `piperaw` with abstract UNIX socket connected to another
 *                      end.
 * \param      name     String uniquely identifying the pipe.
 * \param      options  May contain PAL_OPTION_NONBLOCK.
 *
 * \returns 0 on success, negative PAL error code otherwise.
 *
 * This function connects to the other end of the pipe, represented as an abstract UNIX socket
 * "/gramine/<pipename>" opened for listening. When the connection succeeds, a new `piperaw` PAL
 * handle is created with the corresponding underlying socket and is returned in `handle`.
 * The other end of the pipe is typically of type `piperawcli`.
 */
static int pipe_connect(PAL_HANDLE* handle, const char* name, pal_stream_options_t options) {
    int ret;

    struct sockaddr_un addr;
    ret = get_gramine_unix_socket_addr(name, &addr);
    if (ret < 0)
        return -PAL_ERROR_DENIED;

    assert(WITHIN_MASK(options, PAL_OPTION_NONBLOCK));
    unsigned int addrlen = sizeof(struct sockaddr_un);
    int nonblock = options & PAL_OPTION_NONBLOCK ? SOCK_NONBLOCK : 0;
    ret = ocall_connect(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | nonblock, 0, /*ipv6_v6only=*/0,
                        (const struct sockaddr*)&addr, addrlen, NULL, NULL);

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(pipe));
    if (!hdl) {
        ocall_close(ret);
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(hdl, PAL_TYPE_PIPERAW);
    hdl->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
    hdl->pipe.fd          = ret;
    hdl->pipe.nonblocking = !!(options & PAL_OPTION_NONBLOCK);

    *handle = hdl;
    return 0;
}

/*!
 * \brief Create PAL handle of type `piperawsrv` or `piperaw` depending on `type` and `uri`.
 *
 * \param[out] handle   Created PAL handle of type `piperawsrv` or `piperaw`.
 * \param      type     Can be URI_TYPE_PIPE_RAW or URI_TYPE_PIPE_RAW_SRV.
 * \param      uri      Content is either NUL (for anonymous pipe) or a string with pipe name.
 * \param      access   Not used.
 * \param      share    Not used.
 * \param      create   Not used.
 * \param      options  May contain PAL_OPTION_NONBLOCK.
 *
 * \returns 0 on success, negative PAL error code otherwise.
 *
 * Depending on the combination of `type` and `uri`, the following PAL handles are created:
 *
 * - `type` is URI_TYPE_PIPE_RAW_SRV: create `piperawsrv` handle (intermediate listening socket)
 *                                    with the name created by `get_gramine_unix_socket_addr`.
 *                                    Caller is expected to call pipe_waitforclient() afterwards.
 *
 * - `type` is URI_TYPE_PIPE_RAW: create `piperaw` handle (connecting socket) with the name created
 *                                by `get_gramine_unix_socket_addr`.
 */
static int pipe_open(PAL_HANDLE* handle, const char* type, const char* uri, enum pal_access access,
                     pal_share_flags_t share, enum pal_create_mode create,
                     pal_stream_options_t options) {
    __UNUSED(access);
    __UNUSED(create);
    assert(create == PAL_CREATE_IGNORED);

    if (!WITHIN_MASK(share, PAL_SHARE_MASK) || !WITHIN_MASK(options, PAL_OPTION_MASK))
        return -PAL_ERROR_INVAL;

    if (!strcmp(type, URI_TYPE_PIPE_RAW_SRV))
        return pipe_listen(handle, uri, options);

    if (!strcmp(type, URI_TYPE_PIPE_RAW))
        return pipe_connect(handle, uri, options);

    return -PAL_ERROR_INVAL;
}

/*!
 * \brief Read from pipe.
 *
 * \param      handle  PAL handle of type `piperawcli` or `piperaw`.
 * \param      offset  Not used.
 * \param      len     Size of user-supplied buffer.
 * \param[out] buffer  User-supplied buffer to read data to.
 *
 * \returns Number of bytes read on success, negative PAL error code otherwise.
 */
static int64_t pipe_read(PAL_HANDLE handle, uint64_t offset, uint64_t len, void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (handle->hdr.type != PAL_TYPE_PIPERAWCLI && handle->hdr.type != PAL_TYPE_PIPERAW)
        return -PAL_ERROR_NOTCONNECTION;

    ssize_t bytes = ocall_read(handle->pipe.fd, buffer, len);
    if (bytes < 0)
        return unix_to_pal_error(bytes);

    return bytes;
}

/*!
 * \brief Write to pipe.
 *
 * \param handle  PAL handle of type `piperawcli` or `piperaw`.
 * \param offset  Not used.
 * \param len     Size of user-supplied buffer.
 * \param buffer  User-supplied buffer to write data from.
 *
 * \returns Number of bytes written on success, negative PAL error code otherwise.
 */
static int64_t pipe_write(PAL_HANDLE handle, uint64_t offset, size_t len, const void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    if (handle->hdr.type != PAL_TYPE_PIPERAWCLI && handle->hdr.type != PAL_TYPE_PIPERAW)
        return -PAL_ERROR_NOTCONNECTION;

    ssize_t bytes = ocall_write(handle->pipe.fd, buffer, len);
    if (bytes < 0)
        return unix_to_pal_error(bytes);

    return bytes;
}

/*!
 * \brief Close pipe.
 *
 * \param handle  PAL handle of type `piperawsrv`, `piperawcli`, or `piperaw`.
 *
 * \returns 0 on success, negative PAL error code otherwise.
 */
static int pipe_close(PAL_HANDLE handle) {
    if (handle->pipe.fd != PAL_IDX_POISON) {
        ocall_close(handle->pipe.fd);
        handle->pipe.fd = PAL_IDX_POISON;
    }
    return 0;
}

/*!
 * \brief Shut down pipe.
 *
 * \param handle       PAL handle of type `piperawsrv`, `piperawcli`, or `piperaw`.
 * \param delete_mode  See #pal_delete_mode.
 *
 * \returns 0 on success, negative PAL error code otherwise.
 */
static int pipe_delete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    int shutdown;
    switch (delete_mode) {
        case PAL_DELETE_ALL:
            shutdown = SHUT_RDWR;
            break;
        case PAL_DELETE_READ:
            shutdown = SHUT_RD;
            break;
        case PAL_DELETE_WRITE:
            shutdown = SHUT_WR;
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    if (handle->pipe.fd != PAL_IDX_POISON) {
        ocall_shutdown(handle->pipe.fd, shutdown);
    }

    return 0;
}

/*!
 * \brief Retrieve attributes of PAL handle.
 *
 * \param      handle  PAL handle of type `piperawsrv`, `piperawcli`, or `piperaw`.
 * \param[out] attr    User-supplied buffer to store handle's current attributes.
 *
 * \returns 0 on success, negative PAL error code otherwise.
 */
static int pipe_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    int ret;

    if (handle->pipe.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    attr->handle_type  = handle->hdr.type;
    attr->nonblocking  = handle->pipe.nonblocking;

    /* get number of bytes available for reading (doesn't make sense for "listening" pipes) */
    attr->pending_size = 0;
    if (handle->hdr.type != PAL_TYPE_PIPERAWSRV) {
        ret = ocall_fionread(handle->pipe.fd);
        if (ret < 0)
            return unix_to_pal_error(ret);

        attr->pending_size = ret;
    }

    return 0;
}

/*!
 * \brief Set attributes of PAL handle.
 *
 * \param handle  PAL handle of type `piperawsrv`, `piperawcli`, or `piperaw`.
 * \param attr    User-supplied buffer with new handle's attributes.
 *
 * \returns 0 on success, negative PAL error code otherwise.
 *
 * Currently only `nonblocking` attribute can be set.
 */
static int pipe_attrsetbyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (handle->pipe.fd == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    bool* nonblocking = &handle->pipe.nonblocking;

    if (attr->nonblocking != *nonblocking) {
        int ret = ocall_fsetnonblock(handle->pipe.fd, attr->nonblocking);
        if (ret < 0)
            return unix_to_pal_error(ret);

        *nonblocking = attr->nonblocking;
    }

    return 0;
}

struct handle_ops g_pipe_raw_ops = {
    .open           = &pipe_open,
    .waitforclient  = &pipe_waitforclient,
    .read           = &pipe_read,
    .write          = &pipe_write,
    .close          = &pipe_close,
    .delete         = &pipe_delete,
    .attrquerybyhdl = &pipe_attrquerybyhdl,
    .attrsetbyhdl   = &pipe_attrsetbyhdl,
};
