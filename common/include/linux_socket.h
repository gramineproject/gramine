/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#pragma once

#include <asm/fcntl.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/un.h>
#include <stddef.h>

#include "iovec.h"

#define SOCKADDR_MAX_SIZE 128

struct sockaddr_storage {
    union {
        unsigned short ss_family;
        char _size[SOCKADDR_MAX_SIZE];
        void* _align;
    };
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

struct cmsghdr {
    size_t cmsg_len;
    int cmsg_level;
    int cmsg_type;
    unsigned char __cmsg_data[];
};

#define CMSG_DATA(cmsg) ((cmsg)->__cmsg_data)
#define CMSG_FIRSTHDR(mhdr)                                   \
    ((size_t)(mhdr)->msg_controllen >= sizeof(struct cmsghdr) \
         ? (struct cmsghdr*)(mhdr)->msg_control               \
         : (struct cmsghdr*)0)
#define CMSG_ALIGN(len) ALIGN_UP(len, sizeof(size_t))
#define CMSG_SPACE(len) (CMSG_ALIGN(sizeof(struct cmsghdr)) + CMSG_ALIGN(len))
#define CMSG_LEN(len)   (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))

#define SCM_RIGHTS 1
#define SCM_CREDENTIALS 2
#define SCM_SECURITY 3

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

/* Flags. */
#define MSG_OOB 0x01
#define MSG_PEEK 0x02
#define MSG_TRUNC 0x20
#define MSG_DONTWAIT 0x40
#define MSG_NOSIGNAL 0x4000
#define MSG_MORE 0x8000
#define MSG_CMSG_CLOEXEC 0x40000000

/* Option levels. */
#define SOL_SOCKET 1
#define SOL_TCP 6

/* Socket options. */
#define SO_REUSEADDR 2
#define SO_TYPE 3
#define SO_ERROR 4
#define SO_BROADCAST 6
#define SO_SNDBUF 7
#define SO_RCVBUF 8
#define SO_KEEPALIVE 9
#define SO_LINGER 13
#define SO_REUSEPORT 15
#define SO_RCVTIMEO 20
#define SO_SNDTIMEO 21
#define SO_ACCEPTCONN 30
#define SO_MARK 36
#define SO_TIMESTAMPING_OLD 37
#define SO_PROTOCOL 38
#define SO_DOMAIN 39

#define SO_TXTIME 61
#define SCM_TXTIME SO_TXTIME

/* TCP options. */
#define TCP_NODELAY 1       /* Turn off Nagle's algorithm */
#define TCP_CORK 3          /* Never send partially complete segments */
#define TCP_KEEPIDLE 4      /* Start keeplives after this period */
#define TCP_KEEPINTVL 5     /* Interval between keepalives */
#define TCP_KEEPCNT 6       /* Number of keepalives before death */
#define TCP_USER_TIMEOUT 18 /* How long for loss retry before timeout */

#define MAX_TCP_KEEPIDLE 32767
#define MAX_TCP_KEEPINTVL 32767
#define MAX_TCP_KEEPCNT 127

#define DEFAULT_TCP_KEEPIDLE (2 * 60 * 60) /* 2 hours */
#define DEFAULT_TCP_KEEPINTVL 75           /* 75 seconds */
#define DEFAULT_TCP_KEEPCNT 9              /* 9 keepalive probes */
#define DEFAULT_TCP_USER_TIMEOUT 0         /* use system default */

struct linger {
    int l_onoff;
    int l_linger;
};

#define SHUT_RD 0
#define SHUT_WR 1
#define SHUT_RDWR 2
