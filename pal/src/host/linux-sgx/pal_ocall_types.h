/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation */

#pragma once

/*
 * These structures are used in trusted -> untrusted world calls (OCALLS).
 */

#include <stdbool.h>
#include <stddef.h>

#include "pal.h"
#include "pal_linux_types.h"
#include "sgx_arch.h"
#include "sgx_attest.h"

/*
 * These structures must be packed, otherwise will leak data in their padding when copied to
 * untrusted world.
 */
#pragma pack(push, 1)

typedef long (*sgx_ocall_fn_t)(void*);

enum {
    OCALL_EXIT = 0,
    OCALL_MMAP_UNTRUSTED,
    OCALL_MUNMAP_UNTRUSTED,
    OCALL_CPUID,
    OCALL_OPEN,
    OCALL_CLOSE,
    OCALL_READ,
    OCALL_WRITE,
    OCALL_PREAD,
    OCALL_PWRITE,
    OCALL_FSTAT,
    OCALL_FIONREAD,
    OCALL_FSETNONBLOCK,
    OCALL_FCHMOD,
    OCALL_FSYNC,
    OCALL_FTRUNCATE,
    OCALL_MKDIR,
    OCALL_GETDENTS,
    OCALL_RESUME_THREAD,
    OCALL_SCHED_SETAFFINITY,
    OCALL_SCHED_GETAFFINITY,
    OCALL_CLONE_THREAD,
    OCALL_CREATE_PROCESS,
    OCALL_FUTEX,
    OCALL_SOCKET,
    OCALL_BIND,
    OCALL_LISTEN_SIMPLE,
    OCALL_LISTEN,
    OCALL_ACCEPT,
    OCALL_CONNECT,
    OCALL_CONNECT_SIMPLE,
    OCALL_RECV,
    OCALL_SEND,
    OCALL_SETSOCKOPT,
    OCALL_SHUTDOWN,
    OCALL_GETTIME,
    OCALL_SCHED_YIELD,
    OCALL_POLL,
    OCALL_RENAME,
    OCALL_DELETE,
    OCALL_DEBUG_MAP_ADD,
    OCALL_DEBUG_MAP_REMOVE,
    OCALL_DEBUG_DESCRIBE_LOCATION,
    OCALL_EVENTFD,
    OCALL_GET_QUOTE,
    OCALL_NR,
};

typedef struct {
    int exitcode;
    int is_exitgroup;
} ocall_exit_t;

typedef struct {
    void* addr;
    size_t size;
    int prot;
    int flags;
    int fd;
    off_t offset;
} ocall_mmap_untrusted_t;

typedef struct {
    const void* addr;
    size_t size;
} ocall_munmap_untrusted_t;

typedef struct {
    unsigned int leaf;
    unsigned int subleaf;
    unsigned int values[4];
} ocall_cpuid_t;

typedef struct {
    const char* pathname;
    int flags;
    unsigned short mode;
} ocall_open_t;

typedef struct {
    int fd;
} ocall_close_t;

typedef struct {
    int fd;
    void* buf;
    unsigned int count;
} ocall_read_t;

typedef struct {
    int fd;
    const void* buf;
    unsigned int count;
} ocall_write_t;

typedef struct {
    int fd;
    void* buf;
    size_t count;
    off_t offset;
} ocall_pread_t;

typedef struct {
    int fd;
    const void* buf;
    size_t count;
    off_t offset;
} ocall_pwrite_t;

typedef struct {
    int fd;
    struct stat stat;
} ocall_fstat_t;

typedef struct {
    int fd;
} ocall_fionread_t;

typedef struct {
    int fd;
    int nonblocking;
} ocall_fsetnonblock_t;

typedef struct {
    int fd;
    unsigned short mode;
} ocall_fchmod_t;

typedef struct {
    int fd;
} ocall_fsync_t;

typedef struct {
    int fd;
    uint64_t length;
} ocall_ftruncate_t;

typedef struct {
    const char* pathname;
    unsigned short mode;
} ocall_mkdir_t;

typedef struct {
    int fd;
    struct linux_dirent64* dirp;
    size_t size;
} ocall_getdents_t;

typedef struct {
    int stream_fd;
    size_t nargs;
    const char* args[];
} ocall_create_process_t;

typedef struct {
    void* tcs;
    size_t cpumask_size;
    void* cpu_mask;
} ocall_sched_setaffinity_t;

typedef struct {
    void* tcs;
    size_t cpumask_size;
    void* cpu_mask;
} ocall_sched_getaffinity_t;

typedef struct {
    uint32_t* futex;
    int op;
    int val;
    uint64_t timeout_us;
} ocall_futex_t;

typedef struct {
    int family;
    int type;
    int protocol;
} ocall_socket_t;

typedef struct {
    int fd;
    struct sockaddr* addr;
    size_t addrlen;
    uint16_t new_port;
} ocall_bind_t;

typedef struct {
    int fd;
    unsigned int backlog;
} ocall_listen_simple_t;

typedef struct {
    int domain;
    int type;
    int protocol;
    int ipv6_v6only;
    const struct sockaddr* addr;
    size_t addrlen;
} ocall_listen_t;

typedef struct {
    int sockfd;
    int options;
    struct sockaddr* addr;
    size_t addrlen;
    struct sockaddr* local_addr;
    size_t local_addrlen;
} ocall_accept_t;

typedef struct {
    int domain;
    int type;
    int protocol;
    int ipv6_v6only;
    const struct sockaddr* addr;
    size_t addrlen;
    struct sockaddr* bind_addr;
    size_t bind_addrlen;
} ocall_connect_t;

typedef struct {
    int fd;
    struct sockaddr_storage* addr;
    size_t addrlen;
} ocall_connect_simple_t;

typedef struct {
    PAL_IDX sockfd;
    void* buf;
    size_t count;
    struct sockaddr* addr;
    size_t addrlen;
    void* control;
    size_t controllen;
    unsigned int flags;
} ocall_recv_t;

typedef struct {
    PAL_IDX sockfd;
    const void* buf;
    size_t count;
    const struct sockaddr* addr;
    size_t addrlen;
    void* control;
    size_t controllen;
    unsigned int flags;
} ocall_send_t;

typedef struct {
    int sockfd;
    int level;
    int optname;
    const void* optval;
    size_t optlen;
} ocall_setsockopt_t;

typedef struct {
    int sockfd;
    int how;
} ocall_shutdown_t;

typedef struct {
    uint64_t microsec;
} ocall_gettime_t;

typedef struct {
    struct pollfd* fds;
    size_t nfds;
    uint64_t timeout_us;
} ocall_poll_t;

typedef struct {
    const char* oldpath;
    const char* newpath;
} ocall_rename_t;

typedef struct {
    const char* pathname;
} ocall_delete_t;

typedef struct {
    const char* name;
    void* addr;
} ocall_debug_map_add_t;

typedef struct {
    void* addr;
} ocall_debug_map_remove_t;

typedef struct {
    uintptr_t addr;
    char* buf;
    size_t buf_size;
} ocall_debug_describe_location_t;

typedef struct {
    int          flags;
} ocall_eventfd_t;

typedef struct {
    bool              is_epid;
    sgx_spid_t        spid;
    bool              linkable;
    sgx_report_t      report;
    sgx_quote_nonce_t nonce;
    char*             quote;
    size_t            quote_len;
} ocall_get_quote_t;

#pragma pack(pop)
