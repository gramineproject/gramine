/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */
#pragma once

/* Types and structure used by various Linux ABIs (e.g. syscalls). */
/* These need to be binary-identical with the ones used by Linux. */

#include <stdint.h>

#include "linux_abi/time.h"

struct __kernel_rusage {
    struct __kernel_timeval ru_utime; /* user time used */
    struct __kernel_timeval ru_stime; /* system time used */
    long ru_maxrss;                   /* maximum resident set size */
    long ru_ixrss;                    /* integral shared memory size */
    long ru_idrss;                    /* integral unshared data size */
    long ru_isrss;                    /* integral unshared stack size */
    long ru_minflt;                   /* page reclaims */
    long ru_majflt;                   /* page faults */
    long ru_nswap;                    /* swaps */
    long ru_inblock;                  /* block input operations */
    long ru_oublock;                  /* block output operations */
    long ru_msgsnd;                   /* messages sent */
    long ru_msgrcv;                   /* messages received */
    long ru_nsignals;                 /* signals received */
    long ru_nvcsw;                    /* voluntary context switches */
    long ru_nivcsw;                   /* involuntary " */
};

struct __kernel_rlimit {
    unsigned long rlim_cur, rlim_max;
};

struct __kernel_rlimit64 {
    uint64_t rlim_cur, rlim_max;
};
