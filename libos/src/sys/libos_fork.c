/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <stddef.h> // without this header we are missing `size_t` definition in "signal.h" ...
#include <linux/sched.h>
#include <linux/signal.h>

#include "libos_table.h"

long libos_syscall_fork(void) {
    return libos_syscall_clone(SIGCHLD, 0, NULL, NULL, 0);
}

long libos_syscall_vfork(void) {
    return libos_syscall_clone(CLONE_VFORK | CLONE_VM | SIGCHLD, 0, NULL, NULL, 0);
}
