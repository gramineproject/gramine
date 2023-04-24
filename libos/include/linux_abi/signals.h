/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#pragma once

/* Types and structures used by various Linux ABIs (e.g. syscalls). */
/* These need to be binary-identical with the ones used by Linux. */

// TODO: remove all of these includes and make this header libc-independent.
#include <asm/siginfo.h>
#include <stddef.h>  // FIXME(mkow): Without this we get:
                     //     asm/signal.h:126:2: error: unknown type name ‘size_t’
                     // It definitely shouldn't behave like this...
#include <linux/signal.h>

#include "linux_abi/signals_arch.h"

struct __kernel_sigaction {
    __sighandler_t k_sa_handler;
    unsigned long sa_flags;
    void (*sa_restorer)(void);
    __sigset_t sa_mask;
};
