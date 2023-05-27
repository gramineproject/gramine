/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * This file contains code for calling Gramine from userspace. It can be used in patched
 * applications and libraries (e.g. glibc).
 *
 * To use, include this file in patched code and replace SYSCALL instructions with invocations of
 * GRAMINE_SYSCALL assembly macro.
 */

/* We don't use `#pragma once` here because this header is used by our custom glibc build, and
 * glibc's codebase and buildsystem is a mess. */
#ifndef GRAMINE_ENTRY_API_H_
#define GRAMINE_ENTRY_API_H_

/* Offsets for GS register at which entry vectors can be found */
#define GRAMINE_SYSCALL_OFFSET 24

#ifdef __ASSEMBLER__

.macro GRAMINE_SYSCALL
leaq .Lafter_gramine_syscall\@(%rip), %rcx
jmpq *%gs:GRAMINE_SYSCALL_OFFSET
.Lafter_gramine_syscall\@:
.endm

#else /* !__ASSEMBLER__ */

#include <stdbool.h>
#include <stdint.h>

#define GRAMINE_STR(x)  #x
#define GRAMINE_XSTR(x) GRAMINE_STR(x)

__asm__(
    ".macro GRAMINE_SYSCALL\n"
    "leaq .Lafter_gramine_syscall\\@(%rip), %rcx\n"
    "jmpq *%gs:" GRAMINE_XSTR(GRAMINE_SYSCALL_OFFSET) "\n"
    ".Lafter_gramine_syscall\\@:\n"
    ".endm\n"
);

/* Magic syscall number for Gramine custom calls */
#define GRAMINE_CUSTOM_SYSCALL_NR 0x100000

/* Some GCC versions warn about unused parameters in naked functions. Bug? */
__attribute__((naked)) static int gramine_call(int number __attribute__((unused)),
                                               unsigned long arg1 __attribute__((unused)),
                                               unsigned long arg2 __attribute__((unused))) {
    __asm__ (
        "mov $" GRAMINE_XSTR(GRAMINE_CUSTOM_SYSCALL_NR) ", %eax\n"
        "GRAMINE_SYSCALL\n"
        "ret\n"
    );
}

#undef GRAMINE_XSTR
#undef GRAMINE_STR

/* Custom call numbers */
enum {
    GRAMINE_CALL_REGISTER_LIBRARY = 1,
    GRAMINE_CALL_RUN_TEST,
    /* For RW locks test. GRAMINE_CALL_RUN_TEST is not suitable for it, because we need full control
     * over locks from multiple threads. Additionally, this test is non-trivial in size, so it
     * doesn't seem right to always compile it into our LibOS. */
    GRAMINE_CALL_RWLOCK_CREATE,
    GRAMINE_CALL_RWLOCK_DESTROY,
    GRAMINE_CALL_RWLOCK_READ_LOCK,
    GRAMINE_CALL_RWLOCK_READ_UNLOCK,
    GRAMINE_CALL_RWLOCK_WRITE_LOCK,
    GRAMINE_CALL_RWLOCK_WRITE_UNLOCK,
};

static inline int gramine_register_library(const char* name, unsigned long load_address) {
    return gramine_call(GRAMINE_CALL_REGISTER_LIBRARY, (unsigned long)name, load_address);
}

static inline int gramine_run_test(const char* test_name) {
    return gramine_call(GRAMINE_CALL_RUN_TEST, (unsigned long)test_name, 0);
}

static inline bool gramine_rwlock_create(void** out_lock) {
    return gramine_call(GRAMINE_CALL_RWLOCK_CREATE, (unsigned long)out_lock, 0);
}

static inline void gramine_rwlock_destroy(void* lock) {
    gramine_call(GRAMINE_CALL_RWLOCK_DESTROY, (unsigned long)lock, 0);
}

static inline void gramine_rwlock_read_lock(void* lock) {
    gramine_call(GRAMINE_CALL_RWLOCK_READ_LOCK, (unsigned long)lock, 0);
}

static inline void gramine_rwlock_read_unlock(void* lock) {
    gramine_call(GRAMINE_CALL_RWLOCK_READ_UNLOCK, (unsigned long)lock, 0);
}

static inline void gramine_rwlock_write_lock(void* lock) {
    gramine_call(GRAMINE_CALL_RWLOCK_WRITE_LOCK, (unsigned long)lock, 0);
}

static inline void gramine_rwlock_write_unlock(void* lock){
    gramine_call(GRAMINE_CALL_RWLOCK_WRITE_UNLOCK, (unsigned long)lock, 0);
}

#endif /* __ASSEMBLER__ */

#endif /* GRAMINE_ENTRY_API_H_ */
