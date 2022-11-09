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
    OCALL_EDMM_RESTRICT_PAGES_PERM,
    OCALL_EDMM_MODIFY_PAGES_TYPE,
    OCALL_EDMM_REMOVE_PAGES,
    OCALL_NR,
};

struct ocall_exit {
    int exitcode;
    int is_exitgroup;
};

struct ocall_mmap_untrusted {
    void* addr;
    size_t size;
    int prot;
    int flags;
    int fd;
    off_t offset;
};

struct ocall_munmap_untrusted {
    const void* addr;
    size_t size;
};

struct ocall_cpuid {
    unsigned int leaf;
    unsigned int subleaf;
    unsigned int values[4];
};

struct ocall_open {
    const char* pathname;
    int flags;
    unsigned short mode;
};

struct ocall_close {
    int fd;
};

struct ocall_read {
    int fd;
    void* buf;
    unsigned int count;
};

struct ocall_write {
    int fd;
    const void* buf;
    unsigned int count;
};

struct ocall_pread {
    int fd;
    void* buf;
    size_t count;
    off_t offset;
};

struct ocall_pwrite {
    int fd;
    const void* buf;
    size_t count;
    off_t offset;
};

struct ocall_fstat {
    int fd;
    struct stat stat;
};

struct ocall_fionread {
    int fd;
};

struct ocall_fsetnonblock {
    int fd;
    int nonblocking;
};

struct ocall_fchmod {
    int fd;
    unsigned short mode;
};

struct ocall_fsync {
    int fd;
};

struct ocall_ftruncate {
    int fd;
    uint64_t length;
};

struct ocall_mkdir {
    const char* pathname;
    unsigned short mode;
};

struct ocall_getdents {
    int fd;
    struct linux_dirent64* dirp;
    size_t size;
};

struct ocall_create_process {
    int stream_fd;
    void* reserved_mem_ranges;
    size_t reserved_mem_ranges_size;
    size_t nargs;
    const char* args[];
};

struct ocall_sched_setaffinity {
    void* tcs;
    size_t cpumask_size;
    void* cpu_mask;
};

struct ocall_sched_getaffinity {
    void* tcs;
    size_t cpumask_size;
    void* cpu_mask;
};

struct ocall_futex {
    uint32_t* futex;
    int op;
    int val;
    uint64_t timeout_us;
};

struct ocall_socket {
    int family;
    int type;
    int protocol;
};

struct ocall_bind {
    int fd;
    struct sockaddr* addr;
    size_t addrlen;
    uint16_t new_port;
};

struct ocall_listen_simple {
    int fd;
    unsigned int backlog;
};

struct ocall_listen {
    int domain;
    int type;
    int protocol;
    int ipv6_v6only;
    const struct sockaddr* addr;
    size_t addrlen;
};

struct ocall_accept {
    int sockfd;
    int options;
    struct sockaddr* addr;
    size_t addrlen;
    struct sockaddr* local_addr;
    size_t local_addrlen;
};

struct ocall_connect {
    int domain;
    int type;
    int protocol;
    int ipv6_v6only;
    const struct sockaddr* addr;
    size_t addrlen;
    struct sockaddr* bind_addr;
    size_t bind_addrlen;
};

struct ocall_connect_simple {
    int fd;
    struct sockaddr_storage* addr;
    size_t addrlen;
};

struct ocall_recv {
    PAL_IDX sockfd;
    void* buf;
    size_t count;
    struct sockaddr* addr;
    size_t addrlen;
    void* control;
    size_t controllen;
    unsigned int flags;
};

struct ocall_send {
    PAL_IDX sockfd;
    const void* buf;
    size_t count;
    const struct sockaddr* addr;
    size_t addrlen;
    void* control;
    size_t controllen;
    unsigned int flags;
};

struct ocall_setsockopt {
    int sockfd;
    int level;
    int optname;
    const void* optval;
    size_t optlen;
};

struct ocall_shutdown {
    int sockfd;
    int how;
};

struct ocall_gettime {
    uint64_t microsec;
};

struct ocall_poll {
    struct pollfd* fds;
    size_t nfds;
    uint64_t timeout_us;
};

struct ocall_rename {
    const char* oldpath;
    const char* newpath;
};

struct ocall_delete {
    const char* pathname;
};

struct ocall_debug_map_add {
    const char* name;
    void* addr;
};

struct ocall_debug_map_remove {
    void* addr;
};

struct ocall_debug_describe_location {
    uintptr_t addr;
    char* buf;
    size_t buf_size;
};

struct ocall_eventfd {
    int          flags;
};

struct ocall_get_quote {
    bool              is_epid;
    sgx_spid_t        spid;
    bool              linkable;
    sgx_report_t      report;
    sgx_quote_nonce_t nonce;
    char*             quote;
    size_t            quote_len;
};

struct ocall_edmm_restrict_pages_perm {
    uint64_t addr;
    size_t count;
    uint64_t prot;
};

struct ocall_edmm_modify_pages_type {
    uint64_t addr;
    size_t count;
    uint64_t type;
};

struct ocall_edmm_remove_pages {
    uint64_t addr;
    size_t count;
};

#pragma pack(pop)
