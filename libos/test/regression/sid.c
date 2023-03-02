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
    /* The test is based on the assumption that it's started as the first member of the process
     * group (i.e., the group leader); setsid() should then fail in the first place. */
    errno = 0;
    pid_t psid = setsid();
    if (psid != -1 || errno != EPERM) {
        errx(1, "Unexpected setsid error (expected: %d, actual: %d)", EPERM, errno);
    }

    psid = CHECK(getsid(0));
    pid_t p = CHECK(fork());
    if (p == 0) {
        /* Child created via fork inherits its parent's session ID. */
        pid_t sid = CHECK(getsid(0));
        if (sid != psid) {
            errx(1, "Child: unexpected child's sid (expected: %d, actual: %d)", psid, sid);
        }

        /* On setsid() success, the calling process is the leader of the new session (i.e., its
         * session ID is made the same as its process ID). It also becomes the process group leader
         * of a new process group in the session (i.e., its process group ID is made the same as its
         * process ID). */
        pid_t new_sid = CHECK(setsid());
        if (CHECK(getsid(0)) == sid || CHECK(getsid(0)) != new_sid ||
            new_sid != getpid() || CHECK(getpgid(0)) != new_sid) {
            errx(1, "Child: setsid returned wrong value: %d (expected: %d)", new_sid, getpid());
        }

        p = CHECK(fork());
        if (p == 0) {
            sid = CHECK(getsid(0));

            /* A forked child of the session leader should be able to create a new session. */
            new_sid = CHECK(setsid());
            if (CHECK(getsid(0)) == sid || CHECK(getsid(0)) != new_sid ||
                new_sid != getpid() || CHECK(getpgid(0)) != new_sid) {
                errx(1, "Grandchild: setsid returned wrong value: %d (expected: %d)", new_sid,
                     getpid());
            }
            exit(0);
        }

        int status = 0;
        CHECK(wait(&status));
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            errx(1, "Grandchild: died with status: %#x", status);
        }

        exit(0);
    }

    /* NOTE: in a "standard" usage of setsid() for daemonizing, the parent should be terminated to
     * ensure the new process is an orphan (adopted by init) and also return control to the calling
     * shell. Here we just wait for child termination for testing purposes. */
    int status = 0;
    CHECK(wait(&status));
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errx(1, "Child: died with status: %#x", status);
    }

    puts("TEST OK");
    return 0;
}
