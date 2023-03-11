/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Liang Ma <liang3.ma@intel.com>
 */

/*
 * Test for POSIX locks (`flock(LOCK_EX/LOCK_EX/LOCK_UN`). We assert that the calls succeed (or
 * taking a lock fails), and log all details for debugging purposes.
 *
 * The tests usually start another process, and coordinate with it using pipes.
 */

#define _GNU_SOURCE
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST_DIR "tmp/"
#define TEST_FILE "tmp/lock_file"

static const char* str_type(int type) {
    switch (type) {
        case LOCK_SH: return "LOCK_SH";
        case LOCK_EX: return "LOCK_EX";
        case LOCK_UN: return "LOCK_UN";
        case LOCK_SH|LOCK_NB: return "LOCK_SH|LOCK_NB";
        case LOCK_EX|LOCK_NB: return "LOCK_SH|LOCK_NB";
        default: return "???";
    }
}

static void try_flock(int fd,int operation, int expect_ret) {
    int ret = flock(fd, operation);
    if (ret != expect_ret) {
        fprintf(stderr, "flock(%d, %s) error return value = %d\n", fd, str_type(operation), ret);
    }
    
    fflush(stderr);
}

/* Test: lock file with various lock type  */
static void test_lock(void) {
    printf("testing various locks...\n");
    int fd = open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        err(1, "open");
    
    try_flock(fd, LOCK_EX, 0);
    try_flock(fd, LOCK_SH, 0);
    try_flock(fd, LOCK_EX | LOCK_NB, 0);
    try_flock(fd, LOCK_SH | LOCK_NB, 0);
    try_flock(fd, LOCK_UN | LOCK_NB, 0);
    try_flock(fd, LOCK_EX | LOCK_SH, -1);
    
    close(fd);
}

static void test_flock_open() {
    printf("test locks with the same file's different fd\n");
    int fd = open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        err(1, "open");

    try_flock(fd, LOCK_EX, 0);

    int fd2 = open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd2 < 0)
        err(1, "open");
    
    try_flock(fd2, LOCK_EX|LOCK_NB, -1);
    try_flock(fd2, LOCK_SH|LOCK_NB, -1);
    try_flock(fd, LOCK_UN, 0);
    try_flock(fd2, LOCK_EX|LOCK_NB, 0);
    
    close(fd);
    close(fd2);
}

static void test_flock_dup() {
    printf("test locks with the same fd's different fd\n");
    int fd = open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        err(1, "open");

    try_flock(fd, LOCK_EX, 0);

    int fd2 = dup(fd);
    if (fd2 < 0)
        err(1, "dup");
    
    try_flock(fd2, LOCK_EX, 0);
    try_flock(fd, LOCK_UN, 0);
    try_flock(fd2, LOCK_EX, 0);
    close(fd);
    close(fd2);
}

static void test_flock_dup_open() {
    printf("test locks with the dup and open\n");
    int fd = open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        err(1, "open");

    try_flock(fd, LOCK_EX, 0);

    int fd2 = dup(fd);
    if (fd2 < 0)
        err(1, "dup");
    
    try_flock(fd2, LOCK_EX, 0);
    try_flock(fd, LOCK_UN, 0);
    try_flock(fd2, LOCK_EX, 0);

    int fd3 = open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd3 < 0)
        err(1, "open");
    
    close(fd);
    try_flock(fd3, LOCK_EX|LOCK_NB, -1);
    close(fd2);
    try_flock(fd3, LOCK_EX|LOCK_NB, 0);
    close(fd3);
}

static void child_func(int fd) {
    sleep(1);
    try_flock(fd, LOCK_EX, 0);
    int fd2 = open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd2 < 0)
        err(1, "open");
    
    try_flock(fd2, LOCK_EX|LOCK_NB, -1);
    try_flock(fd2, LOCK_SH|LOCK_NB, -1);
}

static void test_flock_fork() {
    printf("test flock with fork\n");

    int fd = open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        err(1, "open");
    pid_t pid = fork();
    if (pid == 0) {
        child_func(fd);
    } else if (pid > 0) {
        try_flock(fd, LOCK_EX, 0);
        int status;
        wait(&status);
    } else {
        err(1, "fork");
    }
}

int main(void) {
    setbuf(stdout, NULL);

    test_lock();
    test_flock_open();
    test_flock_dup();
    test_flock_dup_open();
    test_flock_fork();
}
