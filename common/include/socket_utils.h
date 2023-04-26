/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#pragma once

#include "linux_socket.h"

void pal_to_linux_sockaddr(const struct pal_socket_addr* pal_addr,
                           struct sockaddr_storage* linux_addr, size_t* linux_addr_len);
void linux_to_pal_sockaddr(const void* linux_addr, struct pal_socket_addr* pal_addr);

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
static inline uint16_t htons(uint16_t x) {
    return x;
}
static inline uint32_t htonl(uint32_t x) {
    return x;
}
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static inline uint16_t htons(uint16_t x) {
    return __builtin_bswap16(x);
}
static inline uint32_t htonl(uint32_t x) {
    return __builtin_bswap32(x);
}
#else
#error "System is not big-endian or little-endian"
#endif

static inline uint16_t ntohs(uint16_t x) {
    return htons(x);
}
static inline uint32_t ntohl(uint32_t x) {
    return htonl(x);
}
