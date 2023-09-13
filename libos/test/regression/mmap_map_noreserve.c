/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

/*
 * Test for creating and accessing anonymous mappings with `MAP_NORESERVE`.
 *
 * This test works on both EDMM and non-EDMM platforms, but if EDMM (and EXINFO) is enabled, the
 * enclave pages are not actually committed on mmap requests, but instead they are lazily committed
 * on first access. This test also stresses the lazy-allocation logic on fork (again, only the
 * actually-accessed enclave pages will be copied to the child enclave).
 *
 * Therefore, on EDMM-enabled platforms, the test is supposed to be significantly faster than on
 * non-EDMM-enabled platforms. But functionality-wise it will be the same. For example, on an ICX
 * machine, this test takes ~0.7s with EDMM enabled and ~17s with EDMM disabled.
 */

#define _GNU_SOURCE
#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

#define TEST_LENGTH  0xC0000000
#define TEST_LENGTH2 0xC000000

int main(void) {
    const char expected_val = 0xff;
    unsigned int seed = time(NULL);
    srand(seed);

    /* test anonymous mappings with `MAP_NORESERVE` */
    void* a = mmap(NULL, TEST_LENGTH, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    if (a == MAP_FAILED)
        err(1, "mmap 1");

    size_t offset = rand() % TEST_LENGTH;
    ((char*)a)[offset] = expected_val;

    CHECK(munmap(a, TEST_LENGTH));

    /* test anonymous mappings with `MAP_NORESERVE` on fork */
    a = mmap(NULL, TEST_LENGTH2, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    if (a == MAP_FAILED)
        err(1, "mmap 2");

    offset = rand() % TEST_LENGTH2;
    ((char*)a)[offset] = expected_val;
    pid_t pid = CHECK(fork());
    if (pid == 0) {
        char data = ((char*)a)[offset];
        if (data != expected_val)
            errx(1, "child: unexpected value read (expected: %x, actual: %x)", expected_val, data);
        exit(0);
    }

    int status;
    CHECK(wait(&status));
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        errx(1, "child wait status: %#x", status);

    CHECK(munmap(a, TEST_LENGTH2));

    puts("TEST OK");
    return 0;
}
