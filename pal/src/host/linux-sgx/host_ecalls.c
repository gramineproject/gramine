/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#include "host_ecalls.h"

#include "host_internal.h"
#include "pal_ecall_types.h"
#include "pal_rpc_queue.h"

int ecall_enclave_start(char* libpal_uri, char* args, size_t args_size, char* env,
                        size_t env_size, int parent_stream_fd, sgx_target_info_t* qe_targetinfo,
                        struct pal_topo_info* topo_info) {
    g_rpc_queue = NULL;

    if (g_pal_enclave.rpc_thread_num > 0) {
        int ret = start_rpc(g_pal_enclave.rpc_thread_num);
        if (ret < 0) {
            /* failed to create RPC threads */
            return ret;
        }
        /* after this point, g_rpc_queue != NULL */
    }

    ecall_enclave_start_t ms;
    ms.libpal_uri       = libpal_uri;
    ms.libpal_uri_len   = strlen(ms.libpal_uri);
    ms.args             = args;
    ms.args_size        = args_size;
    ms.env              = env;
    ms.env_size         = env_size;
    ms.parent_stream_fd = parent_stream_fd;
    ms.qe_targetinfo    = qe_targetinfo;
    ms.topo_info        = topo_info;
    ms.rpc_queue        = g_rpc_queue;
    return sgx_ecall(ECALL_ENCLAVE_START, &ms);
}

int ecall_thread_start(void) {
    return sgx_ecall(ECALL_THREAD_START, NULL);
}

int ecall_thread_reset(void) {
    return sgx_ecall(ECALL_THREAD_RESET, NULL);
}
