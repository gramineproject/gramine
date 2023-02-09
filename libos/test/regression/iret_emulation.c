/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

#define _GNU_SOURCE 1

#include <err.h>
#include <signal.h>
#include <stdio.h>
#include <ucontext.h>

static void sigfpe_handler(int sig, siginfo_t* info, void* arg) {
    ucontext_t* context = (ucontext_t*)arg;

    __asm__ volatile (
        "mov %%ss, %%rax\n"
        "pushq %%rax\n"
        "pushq %0\n"
        "pushq %1\n"
        "pushq %2\n"
        "pushq %3\n"
        "movq %4, %%rbp\n"
        "iretq\n"
        :
        : "r" (context->uc_mcontext.gregs[REG_RSP]),
          "r" (context->uc_mcontext.gregs[REG_EFL]),
          "r" (context->uc_mcontext.gregs[REG_CSGSFS] & 0xFF),
          "r" (context->uc_mcontext.gregs[REG_RIP] + 3),
          "r" (context->uc_mcontext.gregs[REG_RBP])
        : "rax"
    );
}

int main(void) {
    struct sigaction action = { .sa_sigaction = &sigfpe_handler, .sa_flags = SA_SIGINFO };

    if (sigaction(SIGFPE, &action, NULL) < 0) {
        err(1, "unable to set singal handler");
    }

    __asm__ volatile (
        "mov $0, %%rax\n"
        "mov $0, %%rdx\n"
        "idiv %%rdx"
        :
        :
        : "rax", "rcx", "rdx", "rbx", "rsi", "rdi"
    );

    printf("TEST OK\n");
    return 0;
}
