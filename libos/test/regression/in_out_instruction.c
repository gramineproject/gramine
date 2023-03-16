/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Fortanix Inc
 *                    Nirjhar Roy <nirjhar.roy@fortanix.com>
 */

/* Test description: this test verifies that in and out instructions correctly generate SIGSEGV.
 * This raises SIGSEGV once for IN and once for OUT and then counts if number of SIGSEGVs is 2.
 */

#define _GNU_SOURCE
#define EXPECTED_NUM_SIGSEGVS 2

#include <err.h>
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

#include "common.h"

static int g_sigsegv_triggered = 0;
static sigjmp_buf g_point;

unsigned char inb_func(unsigned short port) __attribute__((visibility("internal")));
void outb_func(unsigned char value, unsigned short port) __attribute__((visibility("internal")));
void inb_instruction_addr(void) __attribute__((visibility("internal")));
void outb_instruction_addr(void) __attribute__((visibility("internal")));

__asm__ (
".pushsection .text\n"
".type inb_func, @function\n"
".type outb_func, @function\n"
".type inb_instruction_addr, @function\n"
".type outb_instruction_addr, @function\n"
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
    "ret\n"
".popsection\n"
);

static void fault_handler(int signum, siginfo_t* si, void* uc) {
    assert(signum == SIGSEGV);
    uintptr_t rip = (uintptr_t)(((ucontext_t*)uc)->uc_mcontext.gregs[REG_RIP]);
    if (g_sigsegv_triggered == 0) {
        /* must be a fault on inb instruction */
        if (rip != (uintptr_t)(inb_instruction_addr))
            _Exit(1);
    } else if (g_sigsegv_triggered == 1) {
        /* must be a fault on outb instruction */
        if (rip != (uintptr_t)(outb_instruction_addr))
            _Exit(1);
    } else {
        /* too many segfaults?! */
        _Exit(1);
    }
    g_sigsegv_triggered++;
    siglongjmp(g_point, 1);
}

int main(void) {
    struct sigaction int_handler = {
        .sa_sigaction = fault_handler,
        .sa_flags = SA_RESTART | SA_SIGINFO
    };
    CHECK(sigaction(SIGSEGV, &int_handler, NULL));

    unsigned char value = 0;
    unsigned short port = 0x3F8;

    if (sigsetjmp(g_point, 1) == 0) {
        inb_func(port);
    }
    if (sigsetjmp(g_point, 1) == 0) {
        outb_func(value, port);
    }

    if (g_sigsegv_triggered != EXPECTED_NUM_SIGSEGVS)
        errx(1, "Expected %d number of SIGSEGVs, but got only %d", EXPECTED_NUM_SIGSEGVS,
             g_sigsegv_triggered);
    puts("TEST OK");
    return 0;
}
