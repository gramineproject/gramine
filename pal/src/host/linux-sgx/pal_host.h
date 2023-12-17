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
#include <stddef.h>
#include <stdint.h>

#include "enclave_tf_structs.h"
#include "list.h"
#include "spinlock.h"

DEFINE_LIST(pal_handle_thread);
struct pal_handle_thread {
    PAL_HDR reserved;
    void* tcs;
    LIST_TYPE(pal_handle_thread) list;
    void* param;
};

/* RPC streams are encrypted with 256-bit AES keys */
typedef uint8_t PAL_SESSION_KEY[32];

typedef struct {
    /*
     * Here we define the internal structure of PAL_HANDLE.
     * user has no access to the content inside these handles.
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
            size_t total;
            bool encrypted;                 /* flag to indicate encrypted files */
            void* addr;                     /* mapped address, used only for encrypted files */
            /* below fields are used only for trusted files */
            sgx_chunk_hash_t* chunk_hashes; /* array of hashes of file chunks */
            void* umem;                     /* valid only when chunk_hashes != NULL */
            bool seekable;                  /* regular files are seekable, FIFO pipes are not */
        } file;

        struct {
            PAL_IDX fd;
            bool nonblocking;
            bool is_server;
            PAL_SESSION_KEY session_key;
            bool handshake_done;
            void* ssl_ctx;
            void* handshake_helper_thread_hdl;
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
            bool keepalive;
            bool broadcast;
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
            bool is_server;
            PAL_SESSION_KEY session_key;
            void* ssl_ctx;
        } process;

        struct pal_handle_thread thread;

        struct {
            /* Guards accesses to the rest of the fields.
             * We need to be able to set `signaled` and `signaled_untrusted` atomically, which is
             * impossible without a lock. They are essentialy the same field, but we need two
             * separate copies, because we need to guard against malicious host modifications yet
             * still be able to call futex on it. */
            spinlock_t lock;
            /* Current number of waiters - used solely as an optimization. `uint32_t` because futex
             * syscall does not allow for more than `INT_MAX` waiters anyway. */
            uint32_t waiters_cnt;
            bool signaled;
            bool auto_clear;
            /* Access to the *content* of this field should be atomic, because it's used as futex
             * word on the untrusted host. We use 8-byte ints instead of classic 4-byte ints for
             * this futex word. This is to mitigate CVE-2022-21166 (INTEL-SA-00615) which requires
             * all writes to untrusted memory from within the enclave to be done in 8-byte chunks
             * aligned to 8-bytes boundary. We can safely typecast this 8-byte int to a 4-byte futex
             * word because Intel SGX implies a little-endian CPU. */
            uint64_t* signaled_untrusted;
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
