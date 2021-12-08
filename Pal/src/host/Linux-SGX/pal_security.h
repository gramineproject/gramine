/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#ifndef PAL_SECURITY_H
#define PAL_SECURITY_H

#include "pal.h"
#include "sgx_arch.h"

struct pal_sec {
    /* topology information - received from untrusted host, but sanitized */
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
