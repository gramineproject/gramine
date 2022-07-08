/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#pragma once

#include "linux_socket.h"

extern const struct in6_addr in6addr_any;        /* :: */
#define IN6ADDR_ANY_INIT { { { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 } } }

void pal_to_linux_sockaddr(const struct pal_socket_addr* pal_addr,
                           struct sockaddr_storage* linux_addr, size_t* linux_addr_len);
void linux_to_pal_sockaddr(const void* linux_addr, struct pal_socket_addr* pal_addr);
bool is_linux_sockaddr_any(const void* linux_addr);
