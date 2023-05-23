/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Liang Ma <liang3.ma@intel.com>
 */

/*
 * Test for `flock` syscall (`flock(LOCK_EX/LOCK_SH/LOCK_UN`). We assert that the calls succeed (or
 * taking a lock fails), and log all details for debugging purposes.
 *
 * The tests involve multithreaded, dup and file-backed mmap cases. We don't add multi-process cases
 * here because they are already covered by LTP tests `flock03` and `flock04`.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <unistd.h>

#include "common.h"

#define TEST_FILE "tmp/flock_file"
#define FILE_SIZE 1024

struct thread_args {
    int pipes[2][2];
};

static const char* str_type(int type) {
    switch (type) {
        case LOCK_SH: return "LOCK_SH";
        case LOCK_EX: return "LOCK_EX";
        case LOCK_UN: return "LOCK_UN";
        case LOCK_SH | LOCK_NB: return "LOCK_SH | LOCK_NB";
        case LOCK_EX | LOCK_NB: return "LOCK_EX | LOCK_NB";
        default: return "???";
    }
}

static void try_flock(int fd, int operation, int expect_ret) {
    int ret = flock(fd, operation);
    if (ret != expect_ret) {
        errx(1, "flock(%d, %s) error with return value = %d, expected value = %d",
             fd, str_type(operation), ret, expect_ret);
    }
}

static void open_pipes(int pipes[2][2]) {
    for (unsigned int i = 0; i < 2; i++) {
        CHECK(pipe(pipes[i]));
    }
}

static void close_pipes(int pipes[2][2]) {
    for (unsigned int i = 0; i < 2; i++) {
        for (unsigned int j = 0; j < 2; j++) {
            CHECK(close(pipes[i][j]));
        }
    }
}

static void write_pipe(int pipe[2]) {
    char c = 0;
    int ret;
    do {
        ret = write(pipe[1], &c, sizeof(c));
    } while (ret == -1 && errno == EINTR);
    if (ret == -1)
        err(1, "write");
}

static void read_pipe(int pipe[2]) {
    char c;
    int ret;
    do {
        ret = read(pipe[0], &c, sizeof(c));
    } while (ret == -1 && errno == EINTR);
    if (ret == -1)
        err(1, "read");
    if (ret == 0)
        err(1, "pipe closed");
}

static void test_flock_dup_open(void) {
    printf("testing locks with the dup and open...\n");
    int fd = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    try_flock(fd, LOCK_EX, 0);

    int fd2 = CHECK(dup(fd));
    try_flock(fd2, LOCK_EX, 0);
    try_flock(fd, LOCK_UN, 0);
    try_flock(fd2, LOCK_EX, 0);

    int fd3 = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    CHECK(close(fd));
    try_flock(fd3, LOCK_EX | LOCK_NB, -1);
    CHECK(close(fd2));
    try_flock(fd3, LOCK_EX | LOCK_NB, 0);
    CHECK(close(fd3));
}

static void test_mmap_flock_close_unmap(void) {
    printf("testing locks with the mmap and flock...\n");
    int fd1, fd2;
    void* file_data;

    fd1 = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    file_data = mmap(NULL, FILE_SIZE, PROT_READ, MAP_SHARED, fd1, 0);
    if (file_data == MAP_FAILED) {
        err(1, "mmap");
    }
    try_flock(fd1, LOCK_EX, 0);
    CHECK(close(fd1));
    fd2 = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    try_flock(fd2, LOCK_EX | LOCK_NB, -1);
    CHECK(munmap(file_data, FILE_SIZE));
    try_flock(fd2, LOCK_EX, 0);
    CHECK(close(fd2));
}

static void* thread_flock_first(void* arg) {
    struct thread_args* args = (struct thread_args*)arg;

    int fd = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    try_flock(fd, LOCK_EX | LOCK_NB, 0);
    write_pipe(args->pipes[0]);
    read_pipe(args->pipes[1]);
    try_flock(fd, LOCK_UN, 0);
    write_pipe(args->pipes[0]);
    read_pipe(args->pipes[1]);
    try_flock(fd, LOCK_SH | LOCK_NB, 0);
    CHECK(close(fd));

    return arg;
}

static void* thread_flock_second(void* arg) {
    struct thread_args* args = (struct thread_args*)arg;

    int fd = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    read_pipe(args->pipes[0]);
    try_flock(fd, LOCK_EX | LOCK_NB, -1);
    write_pipe(args->pipes[1]);
    read_pipe(args->pipes[0]);
    try_flock(fd, LOCK_SH | LOCK_NB, 0);
    write_pipe(args->pipes[1]);
    CHECK(close(fd));

    return arg;
}

static void test_flock_multithread(void) {
    printf("testing flock with multithread...\n");
    int ret;
    pthread_t threads[2];
    struct thread_args args = {0};
    open_pipes(args.pipes);

    ret = pthread_create(&threads[0], NULL, thread_flock_first, (void*)&args);
    if (ret != 0)
        errx(1, "pthread_create");

    ret = pthread_create(&threads[1], NULL, thread_flock_second, (void*)&args);
    if (ret != 0)
        errx(1, "pthread_create");

    for (int i = 0; i < 2; i++) {
        if ((ret = pthread_join(threads[i], NULL)) != 0) {
            errx(1, "pthread_join");
        } 
    }
    close_pipes(args.pipes);
}

int main(void) {
    setbuf(stdout, NULL);

    test_flock_dup_open();
    test_mmap_flock_close_unmap();
    test_flock_multithread();

    CHECK(unlink(TEST_FILE));
    printf("TEST OK\n");
    return 0;
}
