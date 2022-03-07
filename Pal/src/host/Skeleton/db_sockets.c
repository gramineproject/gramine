/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "pal_internal.h"

int _DkSocketCreate(enum pal_socket_domain domain, enum pal_socket_type type,
                    pal_stream_options_t options, PAL_HANDLE* handle_ptr) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSocketBind(PAL_HANDLE handle, struct pal_socket_addr* addr) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSocketListen(PAL_HANDLE handle, unsigned int backlog) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSocketAccept(PAL_HANDLE handle, pal_stream_options_t options, PAL_HANDLE* client_ptr,
                    struct pal_socket_addr* client_addr) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSocketConnect(PAL_HANDLE handle, struct pal_socket_addr* addr,
                     struct pal_socket_addr* local_addr) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSocketSend(PAL_HANDLE handle, struct pal_iovec* iov, size_t iov_len, size_t* size_out,
                  struct pal_socket_addr* addr) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _DkSocketRecv(PAL_HANDLE handle, struct pal_iovec* iov, size_t iov_len, size_t* size_out,
                  struct pal_socket_addr* addr) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}
