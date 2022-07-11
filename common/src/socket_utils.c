/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "api.h"
#include "linux_socket.h"
#include "pal.h"
#include "socket_utils.h"

void pal_to_linux_sockaddr(const struct pal_socket_addr* pal_addr,
                           struct sockaddr_storage* linux_addr, size_t* linux_addr_len) {
    switch (pal_addr->domain) {
        case PAL_DISCONNECT:
            linux_addr->ss_family = AF_UNSPEC;
            *linux_addr_len = sizeof(linux_addr->ss_family);
            break;
        case PAL_IPV4:;
            struct sockaddr_in sa_ipv4 = {
                .sin_family = AF_INET,
                .sin_port = pal_addr->ipv4.port,
                .sin_addr.s_addr = pal_addr->ipv4.addr,
            };
            memcpy(linux_addr, &sa_ipv4, sizeof(sa_ipv4));
            *linux_addr_len = sizeof(sa_ipv4);
            break;
        case PAL_IPV6:;
            struct sockaddr_in6 sa_ipv6 = {
                .sin6_family = AF_INET6,
                .sin6_flowinfo = pal_addr->ipv6.flowinfo,
                .sin6_scope_id = pal_addr->ipv6.scope_id,
                .sin6_port = pal_addr->ipv6.port,
            };
            static_assert(sizeof(pal_addr->ipv6.addr) == sizeof(sa_ipv6.sin6_addr.s6_addr), "ops");
            memcpy(sa_ipv6.sin6_addr.s6_addr, pal_addr->ipv6.addr,
                   sizeof(sa_ipv6.sin6_addr.s6_addr));
            memcpy(linux_addr, &sa_ipv6, sizeof(sa_ipv6));
            *linux_addr_len = sizeof(sa_ipv6);
            break;
        default:
            BUG();
    }
}

void linux_to_pal_sockaddr(const void* linux_addr, struct pal_socket_addr* pal_addr) {
    /* `linux_addr` can actually be of any socket address type, but it always has this
     * `unsigned short family` at the begining. */
    unsigned short family;
    memcpy(&family, linux_addr, sizeof(family));

    switch (family) {
        case AF_INET:;
            struct sockaddr_in sa_ipv4;
            memcpy(&sa_ipv4, linux_addr, sizeof(sa_ipv4));
            pal_addr->domain = PAL_IPV4;
            pal_addr->ipv4.port = sa_ipv4.sin_port;
            pal_addr->ipv4.addr = sa_ipv4.sin_addr.s_addr;
            break;
        case AF_INET6:;
            struct sockaddr_in6 sa_ipv6;
            memcpy(&sa_ipv6, linux_addr, sizeof(sa_ipv6));
            pal_addr->domain = PAL_IPV6;
            pal_addr->ipv6.flowinfo = sa_ipv6.sin6_flowinfo;
            pal_addr->ipv6.scope_id = sa_ipv6.sin6_scope_id;
            static_assert(sizeof(pal_addr->ipv6.addr) == sizeof(sa_ipv6.sin6_addr.s6_addr), "ops");
            memcpy(pal_addr->ipv6.addr, sa_ipv6.sin6_addr.s6_addr, sizeof(pal_addr->ipv6.addr));
            pal_addr->ipv6.port = sa_ipv6.sin6_port;
            break;
        case AF_UNSPEC:
            pal_addr->domain = PAL_DISCONNECT;
            break;
        default:
            BUG();
    }
}
