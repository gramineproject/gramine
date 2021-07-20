/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation */

#ifndef ECALL_TYPES_H
#define ECALL_TYPES_H

#include <stddef.h>

enum {
    ECALL_ENCLAVE_START = 0,
    ECALL_THREAD_START,
    ECALL_NR,
};

struct pal_sec;
struct rpc_queue;

typedef struct {
    char*             ms_libpal_uri;
    size_t            ms_libpal_uri_len;
    char*             ms_args;
    size_t            ms_args_size;
    char*             ms_env;
    size_t            ms_env_size;
    struct pal_sec*   ms_sec_info;
    struct rpc_queue* rpc_queue; /* pointer to RPC queue in untrusted mem */
    void*             ocall_args_ptr;
} ms_ecall_enclave_start_t;

#endif /* ECALL_TYPES_H */
