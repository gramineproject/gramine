/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#include "host_ecalls.h"
#include "host_internal.h"
#include "pal_ecall_types.h"
#include "pal_rpc_queue.h"

int ecall_enclave_start(char* libpal_uri, char* args, size_t args_size, char* env,
                        size_t env_size, int parent_stream_fd, sgx_target_info_t* qe_targetinfo,
                        struct pal_topo_info* topo_info, struct pal_dns_host_conf* dns_conf,
                        void* reserved_mem_ranges, size_t reserved_mem_ranges_size) {
    g_rpc_queue = NULL;

    if (g_pal_enclave.rpc_thread_num > 0) {
        int ret = start_rpc(g_pal_enclave.rpc_thread_num);
        if (ret < 0) {
            /* failed to create RPC threads */
            return ret;
        }
        /* after this point, g_rpc_queue != NULL */
    }

    ms_ecall_enclave_start_t ms = {
        .ms_libpal_uri               = libpal_uri,
        .ms_libpal_uri_len           = strlen(ms.ms_libpal_uri),
        .ms_args                     = args,
        .ms_args_size                = args_size,
        .ms_env                      = env,
        .ms_env_size                 = env_size,
        .ms_parent_stream_fd         = parent_stream_fd,
        .ms_qe_targetinfo            = qe_targetinfo,
        .ms_topo_info                = topo_info,
        .ms_dns_host_conf            = dns_conf,
        .ms_reserved_mem_ranges      = reserved_mem_ranges,
        .ms_reserved_mem_ranges_size = reserved_mem_ranges_size,
        .rpc_queue                   = g_rpc_queue,
    };
    return sgx_ecall(ECALL_ENCLAVE_START, &ms);
}

int ecall_thread_start(void) {
    return sgx_ecall(ECALL_THREAD_START, NULL);
}

int ecall_thread_reset(void) {
    return sgx_ecall(ECALL_THREAD_RESET, NULL);
}
