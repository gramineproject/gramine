/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation */

/*
 * Pipes in e.g. Linux-SGX PAL are automatically encrypted using mbedTLS's SSL/TLS sessions (aka
 * contexts). By design, an mbedTLS SSL/TLS context is assumed to be used within a single thread and
 * thus does not use any locking. In Gramine, though, the pipe and its associated SSL/TLS context
 * can be used in multiple threads. Without protecting pipe read/write operations with a lock,
 * mbedTLS internal handling of the context would exhibit data races, leading to e.g. -EACCES in
 * Gramine. This test checks that locking is correct and that no data races occur.
 */

#define _XOPEN_SOURCE 700
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "common.h"

#define WRITER_THREADS 4
#define ITERATIONS     100000
#define BUF_SIZE       64 /* must be safe to not overflow, see users of this macro */

static uint32_t threads_started  = 0;
static uint32_t threads_finished = 0;

static void pthread_check(int x) {
    if (x) {
        errx(1, "pthread failed with %d", x);
    }
}

static void* writer_thread_func(void* arg) {
    int* pipefds = arg;
    uint32_t writer_thread_idx = __atomic_fetch_add(&threads_started, 1, __ATOMIC_SEQ_CST);

    char buf[BUF_SIZE] = {0};
    CHECK(sprintf(buf, "WRITER THREAD %u\n", writer_thread_idx));

    for (uint64_t i = 0; i < ITERATIONS; i++)
        CHECK(write(pipefds[1], buf, strlen(buf)));

    if (__atomic_add_fetch(&threads_finished, 1, __ATOMIC_SEQ_CST) == WRITER_THREADS) {
        /* last writer thread closes the write end of pipe */
        CHECK(close(pipefds[1]));
    }
    return NULL;
}

int main(int argc, char** argv) {
    int pipefds[2];
    CHECK(pipe(pipefds));

    pthread_t th[WRITER_THREADS];
    for (int i = 0; i < WRITER_THREADS; i++)
        pthread_check(pthread_create(&th[i], NULL, writer_thread_func, pipefds));

    while (__atomic_load_n(&threads_started, __ATOMIC_SEQ_CST) != WRITER_THREADS)
        ;

    char buf[BUF_SIZE] = {0};
    while (true) {
        ssize_t bytes_read = CHECK(read(pipefds[0], buf, sizeof(buf) - 1));
        if (!bytes_read)
            break;
#ifdef DEBUG_TEST /* declare to see the test output during debugging */
        printf("%s", buf);
#endif
    }
    CHECK(close(pipefds[0]));

    for (int i = 0; i < WRITER_THREADS; i++)
        pthread_check(pthread_join(th[i], NULL));

    puts("TEST OK");
    return 0;
}
