/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 IBM Corporation
 *                    Stefan Berger <stefanb@linux.ibm.com>
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

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
    pthread_t forker;
    if (pthread_create(&forker, NULL, thread_func, NULL) != 0) {
        perror("pthread_create failed");
        return 1;
    }

    int i = 0, fd, max_fd = 0;
    char buffer[20];
    while (1) {
        snprintf(buffer, sizeof(buffer), "/tmp/%d", i++);
        unlink(buffer);
        fd = open(buffer, O_RDWR|O_CREAT|O_TRUNC);
        if (fd < 0)
            break;
        max_fd = fd > max_fd ? fd : max_fd;
    }

    proceed = 1;
    while (__atomic_load_n(&proceed, __ATOMIC_ACQUIRE) == 1);

    for (fd = 3; fd <= max_fd; fd++)
        close(fd);

    proceed = 1;
    sleep(1);

    return 0;
}
