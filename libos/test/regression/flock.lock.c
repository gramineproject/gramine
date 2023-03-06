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

static int g_fd;

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

static const char* str_err(int err) {
    switch (err) {
        case EACCES: return "EACCES";
        case EAGAIN: return "EAGAIN";
        default: return "???";
    }
}

static int try_flock(int operation) {
    int ret = flock(g_fd, operation);
    fprintf(stderr, "%d: flock(fd, %s) = %d", getpid(), str_type(operation), ret);
    if (ret == -1)
        fprintf(stderr, " (%s) ", str_err(errno));
    
    fflush(stderr);

    if (ret != -1 && ret !=0)
        errx(1, "flock returned unexpected value");
    if (ret == -1 && (errno == EACCES || errno == EAGAIN)) 
        err(1, "fcntl");

    return ret;
}

/* Test: lock file with various lock type  */
static void test_lock(void) {
    printf("testing various locks...\n");
    try_flock(LOCK_EX);
    try_flock(LOCK_SH);
    try_flock(LOCK_EX | LOCK_NB);
    try_flock(LOCK_SH | LOCK_NB);
    try_flock(LOCK_UN | LOCK_NB);
    try_flock(LOCK_EX | LOCK_SH);
}

static void test_flock_fork() {
    
}

int main(void) {
    setbuf(stdout, NULL);

    g_fd = open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (g_fd < 0)
        err(1, "open");
    
    test_lock();

}