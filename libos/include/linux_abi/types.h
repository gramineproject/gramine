/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#pragma once

/* Types and structures used by various Linux ABIs (e.g. syscalls). */
/* These need to be binary-identical with the ones used by Linux. */

// TODO: remove all of these includes and make this header libc-independent.
#include <asm/errno.h>
#include <asm/poll.h>
#include <asm/posix_types.h>
#include <asm/siginfo.h>
#include <asm/signal.h>
#include <asm/stat.h>
#include <asm/statfs.h>
#include <linux/aio_abi.h>
#include <linux/eventpoll.h>
#include <linux/futex.h>
#include <linux/msg.h>
#include <linux/perf_event.h>
#include <linux/sem.h>
#include <linux/types.h>
#include <linux/utsname.h>
#include <linux/version.h>

typedef __kernel_uid_t     uid_t;
typedef __kernel_gid_t     gid_t;
typedef __kernel_pid_t     pid_t;
typedef __kernel_mode_t    mode_t;
typedef __kernel_off_t     off_t;
typedef __kernel_loff_t    loff_t;
typedef __kernel_old_dev_t dev_t;
typedef __kernel_ino_t     ino_t;
typedef __kernel_clockid_t clockid_t;
typedef __kernel_fd_set    fd_set;

typedef unsigned int __kernel_uid_t;
