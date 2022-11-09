/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation */

#pragma once

#include <stddef.h>

#include "pal.h"
#include "sgx_arch.h"

enum {
    ECALL_ENCLAVE_START = 0,
    ECALL_THREAD_START,
    ECALL_THREAD_RESET,
    ECALL_NR,
};

struct rpc_queue;

struct ecall_enclave_start {
    char*                     libpal_uri;
    size_t                    libpal_uri_len;
    char*                     args;
    size_t                    args_size;
    char*                     env;
    size_t                    env_size;
    int                       parent_stream_fd;
    sgx_target_info_t*        qe_targetinfo;
    struct pal_topo_info*     topo_info;
    struct pal_dns_host_conf* dns_host_conf;
    unsigned char             edmm_enabled;
    void*                     reserved_mem_ranges;
    size_t                    reserved_mem_ranges_size;

    struct rpc_queue*         rpc_queue; /* pointer to RPC queue in untrusted mem */
};
