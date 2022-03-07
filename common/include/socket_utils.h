/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "linux_socket.h"

void pal_to_linux_sockaddr(const struct pal_socket_addr* pal_addr,
                           struct sockaddr_storage* linux_addr, size_t* linux_addr_len);
void linux_to_pal_sockaddr(const struct sockaddr_storage* linux_addr,
                           struct pal_socket_addr* pal_addr);
