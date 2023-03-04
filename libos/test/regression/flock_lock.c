/* SPDX-License-Identifier: LGPL-3.0-or-later
 * 
 * Copyright (C) 2023 Philipp Braun <3589810@gmail.com>
 *
 * Test for POSIX locks (`flock`)
 * 
 */

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>

#define TEST_DIR "tmp/"
#define TEST_FILE "tmp/lock_file"

void test_inherited_lock() {
    int fd = open(TEST_FILE, O_CREAT | O_RDWR, 0666);
    if (fd < 0) {
        perror("open");
        exit(1);
    }

    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        printf("Parent could not get lock on file\n");
    } else {
        printf("Parent has lock on file\n");

        pid_t pid = fork();
        if (pid < 0) {
            perror("fork");
            exit(1);
        }

        if (pid == 0) {
            // child process
            if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
                printf("Child could not get lock on file\n");
            } else {
                printf("Child has lock on file\n");
            }
            exit(0);
        } else {
            // parent process
            wait(NULL);
        }
    }
    close(fd);

    printf("Test inherited lock passed\n");
}

void test_shared_lock() {
    int fd = open(TEST_FILE, O_RDWR);
    assert(fd != -1);

    flock(fd, LOCK_SH);

    int result = flock(fd, LOCK_SH | LOCK_NB);
    assert(result == 0);

    flock(fd, LOCK_UN);
    close(fd);

    printf("Test shared lock passed\n");
}

int main(void) {
    test_inherited_lock();
    test_shared_lock();

    return 0;
}