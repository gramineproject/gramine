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
 * machine, this test takes ~0.7s with EDMM enabled and ~19s with EDMM disabled.
 */

#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

#define NUM_THREADS 5
#define TEST_LENGTH  0xC0000000
#define TEST_LENGTH2 0xC000000
#define TEST_NUM_PAGES 100
#define TEST_FILE "testfile_map_noreserve"

static long g_page_size = 0;

static void* thread_func(void* arg) {
    char data;
    for (size_t i = 0; i < TEST_NUM_PAGES; i++) {
        memcpy(&data, arg + i * g_page_size, sizeof(data));
        if (data != 0)
            return (void*)1;
    }
    return (void*)0;
}

int main(void) {
    const char expected_val = 0xff;
    unsigned int seed = time(NULL);
    srand(seed);

    g_page_size = sysconf(_SC_PAGESIZE);
    if (g_page_size < 0)
        err(1, "sysconf");

    /* test anonymous mappings with `MAP_NORESERVE` */
    void* a = mmap(NULL, TEST_LENGTH, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1,
                   0);
    if (a == MAP_FAILED)
        err(1, "mmap 1");

    size_t offset = rand() % TEST_LENGTH;
    char data = ((char*)a)[offset];
    if (data != 0)
        errx(1, "unexpected value read (expected: %x, actual: %x)", 0, data);

    CHECK(mprotect(a, TEST_LENGTH, PROT_READ | PROT_WRITE));

    offset = rand() % TEST_LENGTH;
    ((char*)a)[offset] = expected_val;

    CHECK(madvise(a, TEST_LENGTH, MADV_DONTNEED));
    if (((char*)a)[offset] != 0)
        errx(1, "unexpected value read after 'madvise(MADV_DONTNEED)' (expected: %x, actual: %x)",
             0, ((char*)a)[offset]);

    CHECK(munmap(a, TEST_LENGTH));

    /* test threads racing to access the same page in anonymous mappings with `MAP_NORESERVE` */
    a = mmap(NULL, TEST_NUM_PAGES * g_page_size, PROT_READ | PROT_WRITE,
            MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    if (a == MAP_FAILED)
        err(1, "mmap 2");

    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        if (pthread_create(&threads[i], NULL, thread_func, a))
            errx(1, "pthread_create failed");
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        intptr_t ret;
        if (pthread_join(threads[i], (void**)&ret))
            errx(1, "pthread_join failed");
        if (ret)
            errx(1, "threads returned error");
    }

    CHECK(munmap(a, TEST_NUM_PAGES * g_page_size));

    /* test anonymous mappings with `MAP_NORESERVE` accessed via file read/write
     *
     * note: we test this because the `read(fd, <mmapped buffer>)` reads into a buffer that was
     * allocated with `MAP_NORESERVE` and thus will commit the enclave pages on demand, while
     * executing the code in the PAL layer (this code writes the host-provided bytes from the file
     * into the mmapped buffer) */
    a = mmap(NULL, TEST_LENGTH2, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    if (a == MAP_FAILED)
        err(1, "mmap 3");

    int fd = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));

    ssize_t n = CHECK(write(fd, &expected_val, sizeof(expected_val)));
    if (n != sizeof(expected_val))
        err(1, "write");

    CHECK(lseek(fd, 0, SEEK_SET));

    offset = rand() % TEST_LENGTH2;
    n = CHECK(read(fd, &((char*)a)[offset], sizeof(expected_val)));
    if (n != sizeof(expected_val))
        err(1, "read");
    if (((char*)a)[offset] != expected_val)
        errx(1, "unexpected value read from file (expected: %x, actual: %x)", expected_val,
             ((char*)a)[offset]);

    CHECK(munmap(a, TEST_LENGTH2));
    CHECK(close(fd));

    /* test anonymous mappings with `MAP_NORESERVE` on fork */
    a = mmap(NULL, TEST_LENGTH2, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
    if (a == MAP_FAILED)
        err(1, "mmap 4");

    offset = rand() % TEST_LENGTH2;
    ((char*)a)[offset] = expected_val;
    pid_t pid = CHECK(fork());
    if (pid == 0) {
        data = ((char*)a)[offset];
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
