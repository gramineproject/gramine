/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "pal.h"
#include "pal_internal.h"

int PalSocketCreate(enum pal_socket_domain domain, enum pal_socket_type type,
                    pal_stream_options_t options, PAL_HANDLE* out_handle) {
    return _PalSocketCreate(domain, type, options, out_handle);
}

int PalSocketBind(PAL_HANDLE handle, struct pal_socket_addr* addr) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);
    return _PalSocketBind(handle, addr);
}

int PalSocketListen(PAL_HANDLE handle, unsigned int backlog) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);
    return _PalSocketListen(handle, backlog);
}

int PalSocketAccept(PAL_HANDLE handle, pal_stream_options_t options, PAL_HANDLE* out_client,
                    struct pal_socket_addr* out_client_addr,
                    struct pal_socket_addr* out_local_addr) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);
    return _PalSocketAccept(handle, options, out_client, out_client_addr, out_local_addr);
}

int PalSocketConnect(PAL_HANDLE handle, struct pal_socket_addr* addr,
                     struct pal_socket_addr* local_addr) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);
    return _PalSocketConnect(handle, addr, local_addr);
}

int PalSocketSend(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t* out_size,
                  struct pal_socket_addr* addr, bool force_nonblocking) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);
    return _PalSocketSend(handle, iov, iov_len, out_size, addr, force_nonblocking);
}

int PalSocketRecv(PAL_HANDLE handle, struct iovec* iov, size_t iov_len, size_t* out_total_size,
                  struct pal_socket_addr* addr, bool force_nonblocking) {
    assert(handle->hdr.type == PAL_TYPE_SOCKET);
    return _PalSocketRecv(handle, iov, iov_len, out_total_size, addr, force_nonblocking);
}
