/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <threads.h>
#include <unistd.h>

#include "common.h"
#include "gramine_entry_api.h"

#define CHECK_IF_TRUE(x) CHECK((x) ? 0 : -1)

/* Large enough to make naive modifications non-atomic on x64. */
struct shared_state {
    uint64_t a, b; // first fibonacci sequence
    uint64_t c, d; // second fibonacci sequence (one step ahead of the first)
};

struct reader_args {
    void* lock;
    struct shared_state* m;
    size_t total_iterations;
};

struct writer_args {
    void* lock;
    struct shared_state* m;
    size_t iterations;
    size_t writers_delay_us;
};

/* Keeps its own fibonacci sequence and synchronizes it with the shared ones. */
static void reader(void* lock, struct shared_state* m, size_t total_iterations) {
    uint64_t a = 0, b = 1;
    size_t current_it = 0;
    while (current_it < total_iterations) {
        gramine_rwlock_read_lock(lock);
        CHECK_IF_TRUE(m->b == m->c);
        CHECK_IF_TRUE(m->a + m->b == m->d);
        while (b != m->d) {
            /* Advance local sequence to the global state */
            uint64_t sum = a + b;
            a = b;
            b = sum;
            current_it++;
            CHECK_IF_TRUE(current_it <= total_iterations);
        }
        gramine_rwlock_read_unlock(lock);
    }
}

static int reader_(void* args_) {
    const struct reader_args* args = (const struct reader_args*)args_;
    reader(args->lock, args->m, args->total_iterations);
    return 0;
}

static void writer(void* lock, struct shared_state* m, size_t iterations, size_t writers_delay_us) {
    for (size_t i = 0; i < iterations; i++) {
        gramine_rwlock_write_lock(lock);
        /* Computing fibonacci this exact way doesn't make much sense, but we need some workload
         * to be executed for testing. */
        m->b += m->a;
        m->a = m->b - m->a;
        thrd_yield();
        m->d += m->c;
        m->c = m->d - m->c;
        gramine_rwlock_write_unlock(lock);

        CHECK(usleep(writers_delay_us));
    }
}

static int writer_(void* args_) {
    const struct writer_args* args = (const struct writer_args*)args_;
    writer(args->lock, args->m, args->iterations, args->writers_delay_us);
    return 0;
}

static void run_test(size_t iterations, size_t readers_num, size_t writers_num,
                     size_t writers_delay_us) {
    struct shared_state m = {1, 0, 0, 1};
    void* lock;
    if (!gramine_rwlock_create(&lock))
        errx(1, "gramine_rwlock_create failed");

    thrd_t* threads = calloc(sizeof(*threads), readers_num + writers_num);
    if (!threads)
        errx(1, "calloc failed");

    struct reader_args reader_args = {
        .lock = lock,
        .m = &m,
        .total_iterations = iterations * writers_num,
    };
    struct writer_args writer_args = {
        .lock = lock,
        .m = &m,
        .iterations = iterations,
        .writers_delay_us = writers_delay_us,
    };

    /* Spawn readers */
    for (size_t i = 0; i < readers_num; i++) {
        int ret = thrd_create(&threads[i], reader_, &reader_args);
        if (ret != thrd_success)
            errx(1, "thrd_create failed with ret = %d", ret);
    }
    /* Spawn writers */
    for (size_t i = readers_num; i < readers_num + writers_num; i++) {
        int ret = thrd_create(&threads[i], writer_, &writer_args);
        if (ret != thrd_success)
            errx(1, "thrd_create failed with ret = %d", ret);
    }

    /* Wait for all */
    for (size_t i = 0; i < readers_num + writers_num; i++) {
        int ret = thrd_join(threads[i], NULL);
        if (ret != thrd_success)
            errx(1, "thrd_join failed with ret = %d", ret);
    }
    gramine_rwlock_destroy(lock);
    free(threads);
}

struct run_test_args {
    size_t iterations;
    size_t readers_num;
    size_t writers_num;
    size_t writers_delay_us;
};

static int run_test_(void* args_) {
    const struct run_test_args* args = (const struct run_test_args*)args_;
    run_test(args->iterations, args->readers_num, args->writers_num, args->writers_delay_us);
    return 0;
}

static size_t str_to_size_t(const char* str) {
    errno = 0;
    size_t res = strtoul(str, /*str_end=*/NULL, 10);
    CHECK_IF_TRUE(errno == 0);
    return res;
}

int main(int argc, char* argv[]) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc != 6)
        errx(2, "Usage: %s <instances> <iterations> <readers_num> <writers_num> <writers_delay_us>\n", argv[0]);

    size_t instances_num = str_to_size_t(argv[1]);
    size_t iterations = str_to_size_t(argv[2]);
    size_t readers_num = str_to_size_t(argv[3]);
    size_t writers_num = str_to_size_t(argv[4]);
    size_t writers_delay_us = str_to_size_t(argv[5]);

    thrd_t* threads = calloc(sizeof(*threads), instances_num);
    if (!threads)
        errx(1, "calloc failed");

    struct run_test_args run_test_args = {
        .iterations = iterations,
        .readers_num = readers_num,
        .writers_num = writers_num,
        .writers_delay_us = writers_delay_us,
    };

    for (size_t i = 0; i < instances_num; i++) {
        int ret = thrd_create(&threads[i], run_test_, &run_test_args);
        if (ret != thrd_success)
            errx(1, "thrd_create failed with ret = %d", ret);
    }

    for (size_t i = 0; i < instances_num; i++) {
        int ret = thrd_join(threads[i], NULL);
        if (ret != thrd_success)
            errx(1, "thrd_join failed with ret = %d", ret);
    }

    puts("TEST OK");
    return 0;
}
