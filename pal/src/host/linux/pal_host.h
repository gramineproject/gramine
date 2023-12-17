/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains definition of PAL host ABI.
 */

#pragma once

#ifndef IN_PAL
#error "cannot be included outside PAL"
#endif

#include <stdbool.h>
#include <stdint.h>

#include "spinlock.h"

typedef struct {
    /* TSAI: Here we define the internal types of PAL_HANDLE
     * in PAL design, user has not to access the content inside the
     * handle, also there is no need to allocate the internal
     * handles, so we hide the type name of these handles on purpose.
     */
    PAL_HDR hdr;
    /* Bitmask of `PAL_HANDLE_FD_*` flags. */
    uint32_t flags;

    union {
        /* Common field for accessing underlying host fd. See also `PAL_HANDLE_FD_READABLE`. */
        struct {
            PAL_IDX fd;
        } generic;

        struct {
            PAL_IDX fd;
            char* realpath;
            bool encrypted; /* flag to indicate encrypted files */
            void* addr;     /* mapped address, used only for encrypted files */
            size_t total;   /* file size, used only for encrypted files */
            bool seekable;  /* regular files are seekable, FIFO pipes are not */
        } file;

        struct {
            PAL_IDX fd;
            bool nonblocking;
        } pipe;

        struct {
            PAL_IDX fd;
            /* TODO: add other flags in future, if needed (e.g., semaphore) */
            bool nonblocking;
        } eventfd;

        struct {
            PAL_IDX fd;
        } console;

        struct {
            PAL_IDX fd;
            char* realpath;
            bool nonblocking;
        } dev;

        struct {
            PAL_IDX fd;
            char* realpath;
            void* buf;
            void* ptr;
            void* end;
            bool endofstream;
        } dir;

        struct {
            PAL_IDX fd;
            enum pal_socket_domain domain;
            enum pal_socket_type type;
            struct socket_ops* ops;
            uint64_t linger;
            size_t recv_buf_size;
            size_t send_buf_size;
            uint64_t recvtimeout_us;
            uint64_t sendtimeout_us;
            bool is_nonblocking;
            bool reuseaddr;
            bool reuseport;
            bool broadcast;
            bool keepalive;
            bool tcp_cork;
            uint32_t tcp_user_timeout;
            uint32_t tcp_keepidle;
            uint32_t tcp_keepintvl;
            uint8_t tcp_keepcnt;
            bool tcp_nodelay;
            bool ipv6_v6only;
        } sock;

        struct {
            PAL_IDX stream;
            bool nonblocking;
        } process;

        struct {
            PAL_IDX tid;
            void* stack;
        } thread;

        struct {
            spinlock_t lock;
            uint32_t waiters_cnt;
            uint32_t signaled;
            bool auto_clear;
        } event;
    };
}* PAL_HANDLE;

#define HANDLE_TYPE(handle) ((handle)->hdr.type)

/* These two flags indicate whether the underlying host fd of `PAL_HANDLE` is readable and/or
 * writable respectively. If none of these is set, then the handle has no host-level fd. */
#define PAL_HANDLE_FD_READABLE  1
#define PAL_HANDLE_FD_WRITABLE  2
/* Set if an error was seen on this handle. */
#define PAL_HANDLE_FD_ERROR     4
/* Set if a hang-up was seen on this handle. */
#define PAL_HANDLE_FD_HANG_UP   8

int arch_do_rt_sigprocmask(int sig, int how);
int arch_do_rt_sigaction(int sig, void* handler,
                         const int* async_signals, size_t async_signals_cnt);
