/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 IBM Corporation
 *                    Stefan Berger <stefanb@linux.ibm.com>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/wait.h>

int main(void) {
    int pid;

    /* A derivative of a syzbot test case that causes a failure in a child
     * process calling rt_sigreturn.
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
        int exp_status = SI_KERNEL + SIGSEGV; /* 139 */
        if (status == exp_status) {
            printf("TEST OK\n");
        } else {
            printf("Got status %d but expected %d\n", status, exp_status);
        }
        return WEXITSTATUS(status);
    } else {
        syscall(__NR_rt_sigreturn);
        /* unreachable */
    }
}
