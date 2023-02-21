/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Fortanix Inc
 *                    Nirjhar Roy <nirjhar.roy@fortanix.com>
 */

/*
 * Verify that IN/OUT/INS/OUTS instructions generate SIGSEGV (and not SIGILL).
 *
 * This test is important for SGX PAL: IN/OUT/INS/OUTS instructions result in a #UD fault when
 * executed in SGX enclaves, but result in a #GP fault when executed by normal userspace code.
 * Gramine is supposed to transform the #UD fault into a #GP fault, which ends up as a SIGSEGV in
 * the application.
 */

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

#include "common.h"

#ifndef __x86_64__
#error Unsupported architecture
#endif

#define EXPECTED_NUM_SIGSEGVS 2

static int g_sigsegv_triggered = 0;

uint8_t inb_func(uint16_t port) __attribute__((visibility("internal")));
void outb_func(uint8_t value, uint16_t port) __attribute__((visibility("internal")));
void inb_instruction_addr(void) __attribute__((visibility("internal")));
void outb_instruction_addr(void) __attribute__((visibility("internal")));
void ret(void) __attribute__((visibility("internal")));

__asm__ (
".pushsection .text\n"
".type inb_func, @function\n"
".type outb_func, @function\n"
".type inb_instruction_addr, @function\n"
".type outb_instruction_addr, @function\n"
".type ret, @function\n"
"inb_func:\n"
    "mov %rdi, %rdx\n"
"inb_instruction_addr:\n"
    "inb %dx, %al\n"
    "ret\n"
"outb_func:\n"
    "mov %rsi, %rdx\n"
    "mov %rdi, %rax\n"
"outb_instruction_addr:\n"
    "outb %al, %dx\n"
"ret:\n"
    "ret\n"
".popsection\n"
);

static void handler(int signum, siginfo_t* si, void* uc) {
    if (signum != SIGSEGV) {
        /* we registered a SIGSEGV handler but got another signal?! */
        _Exit(1);
    }

    uint64_t rip = ((ucontext_t*)uc)->uc_mcontext.gregs[REG_RIP];
    if (g_sigsegv_triggered == 0) {
        /* must be a fault on inb instruction */
        if (rip != (uint64_t)(inb_instruction_addr))
            _Exit(1);
    } else if (g_sigsegv_triggered == 1) {
        /* must be a fault on outb instruction */
        if (rip != (uint64_t)(outb_instruction_addr))
            _Exit(1);
    } else {
        /* too many segfaults?! */
        _Exit(1);
    }

    g_sigsegv_triggered++;

    /* no need to fixup the context (other than RIP) as we only modified caller-saved RDX and RAX in
     * inb_func() and outb_func() */
    ((ucontext_t*)uc)->uc_mcontext.gregs[REG_RIP] = (uint64_t)ret;
}

int main(void) {
    struct sigaction sa = {
        .sa_sigaction = handler,
        .sa_flags = SA_RESTART | SA_SIGINFO,
    };
    CHECK(sigaction(SIGSEGV, &sa, NULL));

    uint8_t value = 0;
    uint16_t port = 0x3F8;

    inb_func(port);
    outb_func(value, port);

    if (g_sigsegv_triggered != EXPECTED_NUM_SIGSEGVS)
        errx(1, "Expected %d SIGSEGVs, got %d", EXPECTED_NUM_SIGSEGVS, g_sigsegv_triggered);

    puts("TEST OK");
    return 0;
}
