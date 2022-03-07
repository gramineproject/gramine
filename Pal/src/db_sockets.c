/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "pal.h"
#include "pal_internal.h"

int DkSocketCreate(enum pal_socket_domain domain, enum pal_socket_type type,
                   pal_stream_options_t options, PAL_HANDLE* out_handle) {
    return _DkSocketCreate(domain, type, options, out_handle);
}

int DkSocketBind(PAL_HANDLE handle, struct pal_socket_addr* addr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    return _DkSocketBind(handle, addr);
}

int DkSocketListen(PAL_HANDLE handle, unsigned int backlog) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    return _DkSocketListen(handle, backlog);
}

int DkSocketAccept(PAL_HANDLE handle, pal_stream_options_t options, PAL_HANDLE* out_client,
                   struct pal_socket_addr* out_client_addr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    return _DkSocketAccept(handle, options, out_client, out_client_addr);
}

int DkSocketConnect(PAL_HANDLE handle, struct pal_socket_addr* addr,
                    struct pal_socket_addr* local_addr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    return _DkSocketConnect(handle, addr, local_addr);
}

int DkSocketSend(PAL_HANDLE handle, struct pal_iovec* iov, size_t iov_len, size_t* out_size,
                 struct pal_socket_addr* addr) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    return _DkSocketSend(handle, iov, iov_len, out_size, addr);
}

int DkSocketRecv(PAL_HANDLE handle, struct pal_iovec* iov, size_t iov_len, size_t* out_total_size,
                 struct pal_socket_addr* addr, bool force_nonblocking) {
    assert(PAL_GET_TYPE(handle) == PAL_TYPE_SOCKET);
    return _DkSocketRecv(handle, iov, iov_len, out_total_size, addr, force_nonblocking);
}
