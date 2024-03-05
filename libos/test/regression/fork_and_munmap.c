/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 IBM Corporation
 *                    Stefan Berger <stefanb@linux.ibm.com>
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#define NUM_PAGES 1024

int proceed = 0;

static void* thread_func(void* arg) {
    while (__atomic_load_n(&proceed, __ATOMIC_ACQUIRE) == 0)
        usleep(1);
    proceed = 0;

    usleep(1);
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork failed\n");
        exit(1);
    }
    if (pid > 0) {
        while (__atomic_load_n(&proceed, __ATOMIC_ACQUIRE) == 0)
            usleep(1);
        printf("TEST OK\n");
    } else {
        printf("Child started\n");
    }
    exit(0);
}

int main(int argc, char** argv) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size == -1 && errno) {
        err(1, "sysconf");
    }

    void* addr = mmap(NULL, NUM_PAGES * page_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (addr == MAP_FAILED) {
        err(1, "mmap");
    }

    pthread_t forker;
    if (pthread_create(&forker, NULL, thread_func, NULL) != 0) {
        perror("pthread_create failed");
        return 1;
    }

    proceed = 1;
    while (__atomic_load_n(&proceed, __ATOMIC_ACQUIRE) == 1);

    size_t i;
    for (i = 0; i < NUM_PAGES; i++)
        munmap(addr + i * page_size, page_size);

    proceed = 1;
    sleep(1);

    return 0;
}
