/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <asm/errno.h>

#include "api.h"
#include "assert.h"
#include "host_syscall.h"
#include "pal_tcb.h"

/* `offsetof` is evaluated at compile time, which happens only after the preprocessor is run, so it
 * cannot be used in `XSTRINGIFY()`, hence we have to use an immediate value. */
#define PAL_HOST_TCB_LAST_ASYNC_EVENT_OFFSET 0x58
static_assert(offsetof(PAL_HOST_TCB, last_async_event) == PAL_HOST_TCB_LAST_ASYNC_EVENT_OFFSET,
              "error");

__asm__ (
".pushsection .text\n"
".global do_syscall_intr\n"
".type do_syscall_intr, @function\n"
".global do_syscall_intr_after_check1\n"
".type do_syscall_intr_after_check1, @function\n"
".global do_syscall_intr_after_check2\n"
".type do_syscall_intr_after_check2, @function\n"
".global do_syscall_intr_eintr\n"
".type do_syscall_intr_eintr, @function\n"
"do_syscall_intr:\n"
    "mov %rdi, %rax\n"
    "mov %rsi, %rdi\n"
    "mov %rdx, %rsi\n"
    "mov %rcx, %rdx\n"
    "mov %r8, %r10\n"
    "mov %r9, %r8\n"
    "mov 8(%rsp), %r9\n"
    "cmpl $0, %gs:" XSTRINGIFY(PAL_HOST_TCB_LAST_ASYNC_EVENT_OFFSET) "\n"
"do_syscall_intr_after_check1:\n"
    "jne do_syscall_intr_eintr\n"
"do_syscall_intr_after_check2:\n"
    "syscall\n"
    "ret\n"
"do_syscall_intr_eintr:\n"
    "mov $" XSTRINGIFY(-EINTR) ", %rax\n"
    "ret\n"
".popsection\n"
);
