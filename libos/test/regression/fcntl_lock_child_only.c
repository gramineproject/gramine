/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

/*
 * Test for a corner case of POSIX locks (`fcntl(F_SETLK/F_SETLKW/F_GETLK`): the child process
 * acquires the lock on the encrypted file that was not processed yet by the master process. In this
 * case, the child sends an IPC request to the master process (since all POSIX locks' operations are
 * centrally processed in the master process). The master process must lookup the file first, and
 * only if the lookup is successful, grant the POSIX-lock request to the child.
 *
 * There was a bug in Gramine when the above scenario on encrypted files failed, because encrypted
 * files were *not* updated on the hard disk upon creation (the file was created but its metadata
 * wasn't flushed), which confused the master process, and POSIX lock operations failed.
 */

#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

#define TEST_FILE "tmp_enc/lock_file"

int main(void) {
    pid_t pid = CHECK(fork());

    if (pid == 0) {
        int fd = CHECK(open(TEST_FILE, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600));

        struct flock fl = {
            .l_type = F_WRLCK,
            .l_whence = SEEK_SET,
            .l_start = 0,
            .l_len = 0,
        };
        CHECK(fcntl(fd, F_SETLK, &fl));

        fl.l_type = F_UNLCK;
        CHECK(fcntl(fd, F_SETLK, &fl));

        CHECK(close(fd));
        exit(0);
    }

    int status = 0;
    CHECK(wait(&status));
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errx(1, "child died with status: %#x", status);
    }

    CHECK(unlink(TEST_FILE));

    printf("TEST OK\n");
    return 0;
}
