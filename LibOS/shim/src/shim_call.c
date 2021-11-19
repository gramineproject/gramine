/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/* This file implements Gramine custom calls from userspace. See `shim_entry.h` for details. */

#include <linux/errno.h>
#include <limits.h>

#include "api.h"
#include "asan.h"
#include "gramine_entry_api.h"
#include "shim_entry.h"
#include "shim_thread.h"
#include "shim_utils.h"

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
/* Test: allocate a buffer on heap, write past the end of buffer (ASan only) */
__attribute__((no_sanitize("undefined")))
static int run_test_asan_heap(void) {
    uint8_t* buf = malloc(30);
    buf[30] = 1;
    free(buf);
    return 0;
}

/* Test: write past the end of a stack buffer (ASan only) */
__attribute__((no_sanitize("undefined")))
static int run_test_asan_stack(void) {
    char buf[30];
    /* Take a pointer: direct assignment such as `buf[30] = 1;` triggers a compiler warning */
    char* c = buf + 30;
    *c = 1;

    return 0;
}
#endif /* ASAN */

static const struct shim_test {
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
#endif
    { NULL, NULL },
};

static int run_test(const char* test_name) {
    int ret;

    log_always("run_test(\"%s\") ...", test_name);

    const struct shim_test* test;
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

long handle_call(int number, unsigned long arg1, unsigned long arg2) {
    switch (number) {
        case GRAMINE_CALL_REGISTER_LIBRARY:
            return register_library((const char*)arg1, arg2);

        case GRAMINE_CALL_RUN_TEST:
            return run_test((const char*)arg1);

        default:
            log_warning("handle_call: invalid number: %d", number);
            return -EINVAL;
    }
}
