/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Liang Ma <liang3.ma@intel.com>
 */

/*
 * Test for `flock` syscall (`flock(LOCK_EX/LOCK_SH/LOCK_UN`). We assert that the calls succeed (or
 * taking a lock fails), and log all details for debugging purposes.
 *
 * The tests usually start another process, and coordinate with it using pipes.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/file.h>

#include "common.h"

#define TEST_FILE "lock_file"

static const char* str_type(int type) {
    switch (type) {
        case LOCK_SH: return "LOCK_SH";
        case LOCK_EX: return "LOCK_EX";
        case LOCK_UN: return "LOCK_UN";
        case LOCK_SH | LOCK_NB: return "LOCK_SH | LOCK_NB";
        case LOCK_EX | LOCK_NB: return "LOCK_SH | LOCK_NB";
        default: return "???";
    }
}

static void try_flock(int fd, int operation, int expect_ret) {
    int ret = flock(fd, operation);
    if (ret != expect_ret) {
        errx(1, "flock(%d, %s) error return value = %d\n", fd, str_type(operation), ret);
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
        errx(1, "pipe closed");
}

static void wait_for_child(void) {
    int ret;
    do {
        ret = wait(NULL);
    } while (ret == -1 && errno == EINTR);
    if (ret == -1)
        err(1, "wait");
}

/* Test: lock file with various lock type  */
static void test_locks(void) {
    printf("testing various locks...\n");
    int fd = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    
    try_flock(fd, LOCK_EX, 0);
    try_flock(fd, LOCK_SH, 0);
    try_flock(fd, LOCK_EX | LOCK_NB, 0);
    try_flock(fd, LOCK_SH | LOCK_NB, 0);
    try_flock(fd, LOCK_UN | LOCK_NB, 0);
    try_flock(fd, LOCK_EX | LOCK_SH, -1);
    
    close(fd);
}

static void test_flock_open(void) {
    printf("testing locks with the same file's different fds...\n");
    int fd = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));

    try_flock(fd, LOCK_EX, 0);

    int fd2 = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    
    try_flock(fd2, LOCK_EX | LOCK_NB, -1);
    try_flock(fd2, LOCK_SH | LOCK_NB, -1);
    try_flock(fd, LOCK_UN, 0);
    try_flock(fd2, LOCK_EX | LOCK_NB, 0);
    
    close(fd);
    close(fd2);
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

static void test_flock_fork(void) {
    printf("testing flock with fork...\n");

    int pipes[2][2];
    open_pipes(pipes);

    int fd = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));

    pid_t pid = CHECK(fork());
    
    if (pid == 0) {
        read_pipe(pipes[1]);
        try_flock(fd, LOCK_EX, 0);
        int fd2 = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
        if (fd2 < 0)
            err(1, "open");
        
        try_flock(fd2, LOCK_EX | LOCK_NB, -1);
        try_flock(fd2, LOCK_SH | LOCK_NB, -1);
        CHECK(close(fd2));
        CHECK(close(fd));
        exit(0);
    } 
    write_pipe(pipes[1]);
    try_flock(fd, LOCK_EX, 0);

    CHECK(close(fd));
    wait_for_child();
    close_pipes(pipes);
}

static void test_file_unlock(void) {
    printf("testing flock with fork and unlock...\n");

    int fd = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));

    int pipes[2][2];
    open_pipes(pipes);

    pid_t pid = CHECK(fork());
    
    if (pid == 0) {
        try_flock(fd, LOCK_EX, 0);
        write_pipe(pipes[0]);
        read_pipe(pipes[1]);
        try_flock(fd, LOCK_UN, 0);
        
        write_pipe(pipes[0]);
        CHECK(close(fd));
        exit(0);
    }

    int fd2 = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));

    read_pipe(pipes[0]);
    try_flock(fd2, LOCK_EX | LOCK_NB, -1);
    write_pipe(pipes[1]);
    read_pipe(pipes[0]);
    try_flock(fd2, LOCK_EX | LOCK_NB, 0);

    CHECK(close(fd));
    CHECK(close(fd2));
    wait_for_child();
    close_pipes(pipes);
}

static void test_file_close(void) {
    printf("testing flock with fork and close...\n");

    int fd = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));
    
    int pipes[2][2];
    open_pipes(pipes);

    pid_t pid = CHECK(fork());
    
    if (pid == 0) {
        try_flock(fd, LOCK_EX, 0);
        write_pipe(pipes[0]);
        read_pipe(pipes[1]);

        CHECK(close(fd));

        write_pipe(pipes[0]);
        exit(0);
    }

    int fd2 = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));

    read_pipe(pipes[0]);
    try_flock(fd2, LOCK_EX | LOCK_NB, -1);

    CHECK(close(fd));

    write_pipe(pipes[1]);
    read_pipe(pipes[0]);
    try_flock(fd2, LOCK_EX | LOCK_NB, 0);

    CHECK(close(fd));
    CHECK(close(fd2));
    wait_for_child();
    close_pipes(pipes);
}

int main(void) {
    setbuf(stdout, NULL);

    test_locks();
    test_flock_open();
    test_flock_dup_open();
    test_flock_fork();
    test_file_unlock();
    test_file_close();

    printf("TEST OK\n");
    return 0;
}
