/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#pragma once

/* Types and structures used by various Linux ABIs (e.g. syscalls). */
/* These need to be binary-identical with the ones used by Linux. */

// TODO: remove all of these includes and make this header libc-independent.
#include <linux/times.h>
#include <linux/timex.h>
#include <linux/utime.h>
#include <linux/version.h>

typedef __kernel_time_t time_t;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
struct __kernel_timespec {
    __kernel_time_t tv_sec; /* seconds */
    long tv_nsec;           /* nanoseconds */
};
#endif

struct __kernel_timeval {
    __kernel_time_t tv_sec;       /* seconds */
    __kernel_suseconds_t tv_usec; /* microsecond */
};

struct __kernel_itimerval {
    struct __kernel_timeval it_interval; /* time interval */
    struct __kernel_timeval it_value;    /* current value */
};

struct __kernel_timezone {
    int tz_minuteswest; /* minutes west of Greenwich */
    int tz_dsttime;     /* type of dst correction */
};
