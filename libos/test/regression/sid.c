/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

int main(int argc, const char** argv) {
    /* Parent is already a process group leader so setsid() should fail. */
    errno = 0;
    setsid();
    if (errno != EPERM) {
        errx(1, "unexpected setsid error (expected: %d, actual: %d)", -EPERM, errno);
    }

    pid_t psid = getsid(0);
    pid_t p = CHECK(fork());
    if (p == 0) {
        /* Child created via fork inherits its parent's session ID. */
        pid_t sid = CHECK(getsid(0));
        if (sid != psid) {
            errx(1, "unexpected child's sid (expected: %d, actual: %d)", psid, sid);
        }

        /* On setsid() success, the calling process is the leader of the new session (i.e., its
         * session ID is made the same as its process ID). It also becomes the process group leader
         * of a new process group in the session (i.e., its process group ID is made the same as its
         * process ID).*/
        sid = CHECK(setsid());
        if (sid != getpid() || getpgid(0) != sid) {
            errx(1, "setsid returned wrong value: %d (expected: %d)", sid, getpid());
        }

        exit(0);
    }

    /* NOTE: in a "standard" usage of setsid() for daemonising, the parent should be terminated to
     * ensure the new process is an orphan (adopted by init) and also return control to the calling
     * shell. Here we just wait for child termination for testing purposes. */
    int status = 0;
    CHECK(wait(&status));
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        errx(1, "child wait status: %#x", status);
    }

    puts("TEST OK");
    return 0;
}
