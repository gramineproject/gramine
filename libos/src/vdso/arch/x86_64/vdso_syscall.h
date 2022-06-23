/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */
#pragma once

#include "gramine_entry_api.h"

#ifdef ASAN
#error This code should be compiled without AddressSanitizer.
#endif

static inline long vdso_arch_syscall(long nr, long arg1, long arg2) {
    long ret;
    __asm__ volatile(
        "lea .Lret%=(%%rip), %%rcx\n"
        "jmp *%%gs:%c[libos_syscall_entry]\n"
        ".Lret%=:\n"
        : "=a" (ret)
        : "0" (nr), "D"(arg1), "S"(arg2), [libos_syscall_entry] "i"(GRAMINE_SYSCALL_OFFSET)
        : "memory", "rcx", "r11"
    );
    return ret;
}
