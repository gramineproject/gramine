/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <threads.h>

#include "common.h"
#include "gramine_entry_api.h"

#define RUNTIME_ASSERT(x) do {if (!(x)) errx(1, "Assertion failure: `" #x "` is false"); } while (0)

/* A simple 2x2 matrix, large enough to make naive modifications non-atomic on x64. */
struct matrix {
    uint64_t a, b;
    uint64_t c, d;
};

struct reader_args {
    void* lock;
    struct matrix* m;
    size_t total_iterations;
};

struct writer_args {
    void* lock;
    struct matrix* m;
    size_t iterations;
    size_t writers_delay_us;
};

static void reader(void* lock, struct matrix* m, size_t total_iterations) {
    uint64_t a = 0, b = 1;
    size_t current_it = 0;
    while (current_it < total_iterations) {
        gramine_rwlock_read_lock(lock);
        RUNTIME_ASSERT(m->b == m->c);
        RUNTIME_ASSERT(m->a + m->b == m->d);
        while (b != m->d) {
            /* Advance local sequence to the global state */
            uint64_t sum = a + b;
            a = b;
            b = sum;
            current_it++;
            RUNTIME_ASSERT(current_it <= total_iterations);
        }
        gramine_rwlock_read_unlock(lock);
    }
}

static int reader_(void* args_) {
    struct reader_args* args = (struct reader_args*)args_;
    reader(args->lock, args->m, args->total_iterations);
    return 0;
}

static void writer(void* lock, struct matrix* m, size_t iterations, size_t writers_delay_us) {
    for (size_t i = 0; i < iterations; i++) {
        gramine_rwlock_write_lock(lock);
        /* Computing fibonacci this exact way doesn't make much sense, but we need some workload
         * to be executed for testing. */
        /* *= [0, 1] */
        /*    [1, 1] */
        *m = (struct matrix) {
            m->b, m->a + m->b,
            m->d, m->c + m->d
        };
        gramine_rwlock_write_unlock(lock);
        if (thrd_sleep(&(struct timespec){.tv_nsec = writers_delay_us * 1000}, NULL) < -1)
            errx(1, "thrd_sleep failed");
    }
}

static int writer_(void* args_) {
    struct writer_args* args = (struct writer_args*)args_;
    writer(args->lock, args->m, args->iterations, args->writers_delay_us);
    return 0;
}

static void run_test(size_t iterations, size_t readers_num, size_t writers_num,
                     size_t writers_delay_us) {
    struct matrix m = {1, 0, 0, 1};
    void* lock;
    if (!gramine_rwlock_create(&lock))
        errx(1, "gramine_rwlock_create failed");

    thrd_t* threads = calloc(sizeof(*threads), readers_num + writers_num);
    if (!threads)
        errx(1, "calloc failed");

    /* Spawn readers */
    for (size_t i = 0; i < readers_num; i++) {
        int ret = thrd_create(&threads[i], reader_, &(struct reader_args) {
            .lock = lock,
            .m = &m,
            .total_iterations = iterations * writers_num,
        });
        if (ret != thrd_success)
            errx(1, "thrd_create failed with ret = %d", ret);
    }
    /* Spawn writers */
    for (size_t i = readers_num; i < readers_num + writers_num; i++) {
        int ret = thrd_create(&threads[i], writer_, &(struct writer_args) {
            .lock = lock,
            .m = &m,
            .iterations = iterations,
            .writers_delay_us = writers_delay_us,
        });
        if (ret < 0)
            errx(1, "thrd_create failed with ret = %d", ret);
    }

    /* Wait for all */
    for (size_t i = 0; i < readers_num + writers_num; i++) {
        int ret = thrd_join(threads[i], NULL);
        if (ret < 0)
            errx(1, "thrd_join failed with ret = %d", ret);
    }
    gramine_rwlock_destroy(lock);
}

struct run_test_args {
    size_t iterations;
    size_t readers_num;
    size_t writers_num;
    size_t writers_delay_us;
};

static int run_test_(void* args_) {
    struct run_test_args* args = (struct run_test_args*)args_;
    run_test(args->iterations, args->readers_num, args->writers_num, args->writers_delay_us);
    return 0;
}

int main(int argc, char* argv[]) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc != 6)
        errx(2, "Usage: %s <instances> <iterations> <readers_num> <writers_num> <writers_delay_us>\n", argv[0]);
    size_t instances_num = atoi(argv[1]);
    size_t iterations = atoi(argv[2]);
    size_t readers_num = atoi(argv[3]);
    size_t writers_num = atoi(argv[4]);
    size_t writers_delay_us = atoi(argv[5]);

    thrd_t* threads = calloc(sizeof(*threads), instances_num);
    if (!threads)
        errx(1, "calloc failed");

    for (size_t i = 0; i < instances_num; i++) {
        int ret = thrd_create(&threads[i], run_test_, &(struct run_test_args) {
            .iterations = iterations,
            .readers_num = readers_num,
            .writers_num = writers_num,
            .writers_delay_us = writers_delay_us,
        });
        if (ret < 0)
            errx(1, "thrd_create failed with ret = %d", ret);
    }

    for (size_t i = 0; i < instances_num; i++) {
        int ret = thrd_join(threads[i], NULL);
        if (ret < 0)
            errx(1, "thrd_join failed with ret = %d", ret);
    }

    puts("TEST OK");
    return 0;
}
