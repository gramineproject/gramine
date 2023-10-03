/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 IBM Corporation
 *                    Stefan Berger <stefanb@linux.ibm.com>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

int main(void) {
    int pipefd[2];
    int pid;
    int n;

    /* A derivative of a syzbot test case that starts the async thread with the
     * ioctl(fd, FIOASYNC). During thread_exit() the file descriptors were
     * detached, which included the freeing of a PAL_HANDLE that the async
     * thread was still using even after it had been freed triggering an assert.
     */

    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork() failed: %s\n", strerror(errno));
        return 1;
    }
    if (pid > 0) {
        /* parent */
        int status = 0;
        while (waitpid(-1, &status, __WALL) != pid) {
        }
        return WEXITSTATUS(status);
    } else {
        n = pipe(pipefd);
        if (n < 0) {
            fprintf(stderr, "pipe() failed: %s\n", strerror(errno));
            return 1;
        }
        n = ioctl(pipefd[1], FIOASYNC, 0);
        if (n < 0) {
            fprintf(stderr, "ioctl(FIOASYNC) failed: %s\n", strerror(errno));
            return 1;
        }
        return 0;
    }
}
