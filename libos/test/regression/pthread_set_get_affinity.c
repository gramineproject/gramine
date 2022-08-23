/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation */

/*
 * Test to set/get cpu affinity by parent process on behalf of its child threads.
 */

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

#define min(a, b)               (((a) < (b)) ? (a) : (b))
#define MAIN_THREAD_CNT         1
#define INTERNAL_THREAD_CNT     2
#define MANIFEST_SGX_THREAD_CNT 8 /* corresponds to sgx.thread_num in the manifest template */

struct parent_to_child_args {
    unsigned long thread_affinity;
};

/* barrier to synchronize between parent and children */
pthread_barrier_t barrier;

/* Run a busy loop for some iterations, so that we can verify affinity with htop manually */
static void* dowork(void* args) {
    struct parent_to_child_args* thread_args = (struct parent_to_child_args*)args;

    int ret = pthread_barrier_wait(&barrier);
    if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
        errx(EXIT_FAILURE, "Child did not wait on barrier!");
    }

    unsigned int cpu, node;
    ret = syscall(SYS_getcpu, &cpu, &node);
    if (ret < 0)
        err(EXIT_FAILURE, "getcpu failed!");

    unsigned long cpumask = (1UL << cpu);
    if ((cpumask & thread_args->thread_affinity) == 0) {
        errx(EXIT_FAILURE, "Expected cpumask = %ld returned cpumask = %d",
             thread_args->thread_affinity, cpu);
    }

    printf("Thread %ld is running on cpu: %u, node: %u\n", syscall(SYS_gettid), cpu, node);

    return NULL;
}

int main(int argc, const char** argv) {
    int ret;
    long onlineprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (onlineprocs < 0) {
        err(EXIT_FAILURE, "Failed to retrieve the number of logical processors!");
    }

    /* If you want to run on all cores then increase sgx.thread_num in the manifest.template and
     * also set MANIFEST_SGX_THREAD_CNT to the same value.
     */
    long numthreads = min(onlineprocs, (MANIFEST_SGX_THREAD_CNT - (INTERNAL_THREAD_CNT + MAIN_THREAD_CNT)));

    /* Each thread will be affinitized to run on 2 distinct cores (e.g., thread 0 will be
     * affinitized to run on cpus 0,1 and thread 1 will be affinitized to run on cpus 2,3 and so
     * on..). So reduce the number of threads to take into account odd number of cores present in
     * the system. */
    numthreads = (numthreads >= 2) ? numthreads/2 : 1;

    /* Limit to 32 threads so that we can store the affinity within a single unsigned long */
    if (numthreads > 32)
        numthreads = 32;

    pthread_t* threads = (pthread_t*)malloc(numthreads * sizeof(pthread_t));
    if (!threads) {
         errx(EXIT_FAILURE, "thread allocation failed");
    }

    struct parent_to_child_args* thread_args = malloc(numthreads * sizeof(*thread_args));
    if (!thread_args) {
         errx(EXIT_FAILURE, "thread args allocation failed");
    }

    if (pthread_barrier_init(&barrier, NULL, numthreads + 1)) {
        free(threads);
        errx(EXIT_FAILURE, "pthread barrier init failed");
    }

    /* Validate parent set/get affinity for child */
    cpu_set_t cpus, get_cpus;
    for (long i = 0; i < numthreads; i++) {
        CPU_ZERO(&cpus);
        CPU_ZERO(&get_cpus);

        unsigned long set_affinity;
        if (onlineprocs == 1) {
            CPU_SET(0, &cpus);
            set_affinity = 1UL;
        } else {
            CPU_SET(i * 2, &cpus);
            CPU_SET(i * 2 + 1, &cpus);
            set_affinity = 1UL << (i * 2) | 1UL << (i * 2 + 1);
        }

        thread_args[i].thread_affinity = set_affinity;
        ret = pthread_create(&threads[i], NULL, dowork, (void*)&thread_args[i]);
        if (ret != 0) {
            free(threads);
            free(thread_args);
            errx(EXIT_FAILURE, "pthread_create failed!");
        }

        ret = pthread_setaffinity_np(threads[i], sizeof(cpus), &cpus);
        if (ret != 0) {
            free(threads);
            free(thread_args);
            errx(EXIT_FAILURE, "pthread_setaffinity_np failed for child!");
        }

        ret = pthread_getaffinity_np(threads[i], sizeof(get_cpus), &get_cpus);
        if (ret != 0) {
            free(threads);
            free(thread_args);
            errx(EXIT_FAILURE, "pthread_getaffinity_np failed for child!");
        }

        if (!CPU_EQUAL_S(sizeof(cpus), &cpus, &get_cpus)) {
            free(threads);
            free(thread_args);
            errx(EXIT_FAILURE, "get cpuset is not equal to set cpuset on proc: %ld", i);
        }
    }

    /* unblock the child threads */
    ret = pthread_barrier_wait(&barrier);
    if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
        free(threads);
        free(thread_args);
        errx(EXIT_FAILURE, "Parent did not wait on barrier!");
    }

    for (int i = 0; i < numthreads; i++) {
        ret = pthread_join(threads[i], NULL);
        if (ret != 0) {
            free(threads);
            free(thread_args);
            errx(EXIT_FAILURE, "pthread_join failed!");
        }
    }

    /* Validating parent set/get affinity for children done. Free resources */
    pthread_barrier_destroy(&barrier);
    free(threads);
    free(thread_args);

    /* Validate parent set/get affinity for itself */
    CPU_ZERO(&cpus);
    CPU_SET(0, &cpus);
    ret = pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus);
    if (ret != 0) {
        errx(EXIT_FAILURE, "pthread_setaffinity_np failed for parent!");
    }

    CPU_ZERO(&get_cpus);
    ret = pthread_getaffinity_np(pthread_self(), sizeof(get_cpus), &get_cpus);
    if (ret != 0) {
        errx(EXIT_FAILURE, "pthread_getaffinity_np failed for parent!");
    }

    if (!CPU_EQUAL_S(sizeof(cpus), &cpus, &get_cpus)) {
        errx(EXIT_FAILURE, "get cpuset is not equal to set cpuset on proc 0");
    }

    /* Negative test case with empty cpumask */
    CPU_ZERO(&cpus);
    ret = pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus);
    if (ret != EINVAL) {
        errx(EXIT_FAILURE, "pthread_setaffinity_np with empty cpumask did not return EINVAL!");
    }

    printf("TEST OK\n");
    return 0;
}
