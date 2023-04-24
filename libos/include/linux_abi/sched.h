/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#pragma once

#include <linux/sched.h>

/* Types and structures used by various Linux ABIs (e.g. syscalls). */
/* These need to be binary-identical with the ones used by Linux. */

struct __kernel_sched_param {
    int __sched_priority;
};
