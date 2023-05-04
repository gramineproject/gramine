/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/* This file implements Gramine custom calls from userspace. See `libos_entry.h` for details. */

#include <limits.h>

#include "api.h"
#include "asan.h"
#include "gramine_entry_api.h"
#include "libos_entry.h"
#include "libos_rwlock.h"
#include "libos_utils.h"

/* Test: do nothing, return success */
static int run_test_pass(void) {
    return 0;
}

/* Test: invoke undefined behavior (UBSan only) */
#ifdef UBSAN
static int run_test_ubsan_int_overflow(void) {
    volatile int x = INT_MAX;
    x++;
    return 0;
}
#endif

#ifdef ASAN

/*
 * ASan tests: write past a heap/stack/global buffer. We use a volatile pointer in order to bypass
 * compiler optimizations and warnings.
 */

__attribute__((no_sanitize("undefined")))
static int run_test_asan_heap(void) {
    char* buf = malloc(30);
    char* volatile c = buf + 30;
    *c = 1;
    free(buf);
    return 0;
}

__attribute__((no_sanitize("undefined")))
static int run_test_asan_stack(void) {
    char buf[30];
    char* volatile c = buf + 30;
    *c = 1;
    return 0;
}

__attribute__((no_sanitize("undefined")))
static int run_test_asan_global(void) {
    static char buf[30];
    char* volatile c = buf + 30;
    *c = 1;
    return 0;
}

#endif /* ASAN */

static const struct libos_test {
    const char* name;
    int (*func)(void);
} tests[] = {
    { "pass", &run_test_pass },
#ifdef UBSAN
    { "ubsan_int_overflow", &run_test_ubsan_int_overflow },
#endif
#ifdef ASAN
    { "asan_heap", &run_test_asan_heap },
    { "asan_stack", &run_test_asan_stack },
    { "asan_global", &run_test_asan_global },
#endif
    { NULL, NULL },
};

static int run_test(const char* test_name) {
    int ret;

    log_always("run_test(\"%s\") ...", test_name);

    const struct libos_test* test;
    for (test = &tests[0]; test->name; test++) {
        if (strcmp(test_name, test->name) == 0)
            break;
    }
    if (test->name) {
        ret = test->func();
    } else {
        log_warning("run_test: invalid test name: \"%s\"", test_name);
        ret = -EINVAL;
    }
    log_always("run_test(\"%s\") = %d", test_name, ret);
    return ret;
}

long handle_libos_call(int number, unsigned long arg1, unsigned long arg2) {
    switch (number) {
        case GRAMINE_CALL_REGISTER_LIBRARY:
            return register_library((const char*)arg1, arg2);

        case GRAMINE_CALL_RUN_TEST:
            return run_test((const char*)arg1);

        case GRAMINE_CALL_RWLOCK_CREATE: {
            /* TODO: Change rwlock_create() to return `int` and then change this place analogously
             * (currently it's interpreted as true/false). */
            struct libos_rwlock* lock = malloc(sizeof(*lock));
            if (!lock)
                return 0;
            if (!rwlock_create(lock)) {
                free(lock);
                return 0;
            }
            *(struct libos_rwlock**)arg1 = lock;
            return 1;
        }
        case GRAMINE_CALL_RWLOCK_DESTROY:
            rwlock_destroy((struct libos_rwlock*)arg1);
            free((void*)arg1);
            return 0;
        case GRAMINE_CALL_RWLOCK_READ_LOCK:
            rwlock_read_lock((struct libos_rwlock*)arg1);
            return 0;
        case GRAMINE_CALL_RWLOCK_READ_UNLOCK:
            rwlock_read_unlock((struct libos_rwlock*)arg1);
            return 0;
        case GRAMINE_CALL_RWLOCK_WRITE_LOCK:
            rwlock_write_lock((struct libos_rwlock*)arg1);
            return 0;
        case GRAMINE_CALL_RWLOCK_WRITE_UNLOCK:
            rwlock_write_unlock((struct libos_rwlock*)arg1);
            return 0;

        default:
            log_warning("handle_libos_call: invalid number: %d", number);
            return -EINVAL;
    }
}
