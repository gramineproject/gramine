/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#ifndef GRAMINE_LINUX_SOCKET_H
#define GRAMINE_LINUX_SOCKET_H

#include <asm/fcntl.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <stddef.h>

#define SOCKADDR_MAX_SIZE 128

struct sockaddr_storage {
    union {
        unsigned short ss_family;
        char _size[SOCKADDR_MAX_SIZE];
        void* _align;
    };
};

struct iovec {
    void* iov_base;
    size_t iov_len;
};

struct msghdr {
    void* msg_name;
    int msg_namelen;
    struct iovec* msg_iov;
    size_t msg_iovlen;
    void* msg_control;
    size_t msg_controllen;
    unsigned int msg_flags;
};

struct mmsghdr {
    struct msghdr msg_hdr;
    unsigned int msg_len;
};

#define AF_UNSPEC 0
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10
#define AF_NETLINK 16
#define AF_PACKET 17

#define SOCK_TYPE_MASK 0xf
#define SOCK_STREAM 1
#define SOCK_DGRAM 2

#define SOCK_CLOEXEC O_CLOEXEC
#define SOCK_NONBLOCK O_NONBLOCK

#define SOL_SOCKET 1
#define SOL_TCP 6

/* Socket options. */
#define SO_REUSEADDR 2
#define SO_TYPE 3
#define SO_ERROR 4
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_KEEPALIVE 9
#define SO_LINGER 13
#define SO_RCVTIMEO 20
#define SO_SNDTIMEO 21
#define SO_ACCEPTCONN 30
#define SO_PROTOCOL 38
#define SO_DOMAIN 39

/* TCP options. */
#define TCP_NODELAY 1
#define TCP_CORK 3

struct linger {
    int l_onoff;
    int l_linger;
};

#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2

#endif /* GRAMINE_LINUX_SOCKET_H */
