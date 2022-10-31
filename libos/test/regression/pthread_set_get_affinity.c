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
#include <sys/param.h>
#include <sys/syscall.h>
#include <unistd.h>

#define MAIN_THREAD_CNT         1
#define INTERNAL_THREAD_CNT     2
#define MANIFEST_SGX_THREAD_CNT 8 /* corresponds to sgx.max_threads in the manifest template */

/* barrier to synchronize between parent and children */
pthread_barrier_t barrier;

static void* do_work(void* args) {
    int ret = pthread_barrier_wait(&barrier);
    if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
        errx(EXIT_FAILURE, "Child did not wait on barrier!");
    }

    unsigned int cpu, node;
    ret = syscall(SYS_getcpu, &cpu, &node);
    if (ret < 0)
        err(EXIT_FAILURE, "getcpu failed!");

    cpu_set_t* thread_cpuaffinity = (cpu_set_t*)args;
    if (!CPU_ISSET(cpu, thread_cpuaffinity)) {
        errx(EXIT_FAILURE, "cpu = %d is not part of thread %ld affinity mask", cpu,
             syscall(SYS_gettid));
    }

    printf("Thread %ld is running on cpu: %u, node: %u\n", syscall(SYS_gettid), cpu, node);

    return NULL;
}


/* This function tries to set 2 cores as part of thread cpu affinity mask. But if there is only one
 * core online then it is set as the thread's cpu affinity mask. */
static int select_thread_cpu_affinity(cpu_set_t* set_cpumask, cpu_set_t* online_cpumask) {
    long total_cores = sysconf(_SC_NPROCESSORS_CONF);
    if (total_cores < 0)
        return -1;

    size_t cpu_count = 0;
    for (long i = 0; i < total_cores; i++) {
        if (!CPU_ISSET(i, online_cpumask))
            continue;
        cpu_count++;
        CPU_SET(i, set_cpumask);
        CPU_CLR(i, online_cpumask);

        if (cpu_count == 2)
            break;
    }

    return 0;
}

int main(int argc, const char** argv) {
    int ret;
    long online_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (online_cores < 0) {
        err(EXIT_FAILURE, "Failed to retrieve the number of logical processors!");
    }

    /* Get default thread affinity. This should contain all online cores present in the system. */
    cpu_set_t online_cpumask;
    CPU_ZERO(&online_cpumask);
    ret = pthread_getaffinity_np(pthread_self(), sizeof(online_cpumask), &online_cpumask);
    if (ret != 0) {
        errx(EXIT_FAILURE, "pthread_getaffinity_np failed for parent!");
    }

    if (online_cores != CPU_COUNT(&online_cpumask)) {
        errx(EXIT_FAILURE, "Parent should have affinity set to all online cores!");
    }

    /* If you want to run on all cores then increase sgx.max_threads in the manifest.template and
     * also set MANIFEST_SGX_THREAD_CNT to the same value.
     */
    size_t numthreads = MIN(online_cores, (MANIFEST_SGX_THREAD_CNT
                                           - (INTERNAL_THREAD_CNT + MAIN_THREAD_CNT)));

    /* Each thread will be affinitized to run on 2 distinct cores. So reduce the number of threads
     * to half of cores. */
    numthreads = MAX(numthreads / 2, 1);

    pthread_t* threads = (pthread_t*)malloc(numthreads * sizeof(pthread_t));
    if (!threads) {
         errx(EXIT_FAILURE, "thread allocation failed");
    }

    if (pthread_barrier_init(&barrier, NULL, numthreads + 1)) {
        errx(EXIT_FAILURE, "pthread barrier init failed");
    }

    cpu_set_t* set_cpumask = malloc(numthreads * sizeof(*set_cpumask));
    if (!set_cpumask) {
        errx(EXIT_FAILURE, "cpumask allocation failed");
    }

    cpu_set_t get_cpumask;
    for (size_t i = 0; i < numthreads; i++) {
        /* Select cores that will be affinitized to this thread. */
        ret = select_thread_cpu_affinity(&set_cpumask[i], &online_cpumask);
        if (ret < 0) {
            errx(EXIT_FAILURE, "Cannot select cores to affinitize threads");
        }

        ret = pthread_create(&threads[i], NULL, do_work, &set_cpumask[i]);
        if (ret != 0) {
            errx(EXIT_FAILURE, "pthread_create failed!");
        }

        ret = pthread_setaffinity_np(threads[i], sizeof(set_cpumask[i]), &set_cpumask[i]);
        if (ret != 0) {
            errx(EXIT_FAILURE, "pthread_setaffinity_np failed for child!");
        }

        CPU_ZERO(&get_cpumask);
        ret = pthread_getaffinity_np(threads[i], sizeof(get_cpumask), &get_cpumask);
        if (ret != 0) {
            errx(EXIT_FAILURE, "pthread_getaffinity_np failed for child!");
        }

        if (!CPU_EQUAL(&set_cpumask[i], &get_cpumask)) {
            errx(EXIT_FAILURE, "get cpuset is not equal to set cpuset on proc: %ld", i);
        }
    }

    /* unblock the child threads */
    ret = pthread_barrier_wait(&barrier);
    if (ret != 0 && ret != PTHREAD_BARRIER_SERIAL_THREAD) {
        errx(EXIT_FAILURE, "Parent did not wait on barrier!");
    }

    for (size_t i = 0; i < numthreads; i++) {
        ret = pthread_join(threads[i], NULL);
        if (ret != 0) {
            errx(EXIT_FAILURE, "pthread_join failed!");
        }
    }

    /* Validating parent set/get affinity for children done. Free resources */
    pthread_barrier_destroy(&barrier);
    free(threads);
    free(set_cpumask);

    /* Validate parent set/get affinity for itself */
    cpu_set_t cpumask;
    CPU_ZERO(&cpumask);
    CPU_SET(0, &cpumask);
    ret = pthread_setaffinity_np(pthread_self(), sizeof(cpumask), &cpumask);
    if (ret != 0) {
        errx(EXIT_FAILURE, "pthread_setaffinity_np failed for parent!");
    }

    CPU_ZERO(&get_cpumask);
    ret = pthread_getaffinity_np(pthread_self(), sizeof(get_cpumask), &get_cpumask);
    if (ret != 0) {
        errx(EXIT_FAILURE, "pthread_getaffinity_np failed for parent!");
    }

    if (!CPU_EQUAL(&cpumask, &get_cpumask)) {
        errx(EXIT_FAILURE, "get cpuset is not equal to set cpuset on proc 0");
    }

    /* Negative test case with empty cpumask */
    CPU_ZERO(&cpumask);
    ret = pthread_setaffinity_np(pthread_self(), sizeof(cpumask), &cpumask);
    if (ret != EINVAL) {
        errx(EXIT_FAILURE, "pthread_setaffinity_np with empty cpumask did not return EINVAL!");
    }

    printf("TEST OK\n");
    return 0;
}
