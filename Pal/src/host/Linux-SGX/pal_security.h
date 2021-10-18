/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#ifndef PAL_SECURITY_H
#define PAL_SECURITY_H

#include "pal.h"
#include "sgx_arch.h"

struct pal_sec {
    PAL_IDX uid, gid;

    /* enclave information */
    sgx_target_info_t qe_targetinfo;
    sgx_report_body_t enclave_info;
    /* Thread creation ECALL is allowed only after this is set. */
    bool enclave_initialized;

    /* remaining heap usable by application */
    PAL_PTR heap_min, heap_max;

    /* Child's stream FD created and sent over by parent.
     * If set to `PAL_IDX_POISON`, we have no parent (this is the first process). */
    PAL_IDX stream_fd;

    PAL_NUM online_logical_cores;
    PAL_NUM possible_logical_cores;
    PAL_NUM physical_cores_per_socket;
    int* cpu_socket;
    PAL_TOPO_INFO topo_info;
};

#ifdef IN_ENCLAVE
extern struct pal_sec g_pal_sec;
#endif

#endif /* PAL_SECURITY_H */
