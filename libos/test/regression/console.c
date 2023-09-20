/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

#define FIRST_HELLO_STDOUT    "First hello on stdout!\n"
#define FIRST_HELLO_STDERR    "First hello on stderr!\n"
#define SECOND_HELLO_STDOUT   "Second hello on stdout!\n"
#define SECOND_HELLO_STDERR   "Second hello on stderr!\n"
#define IGNORED_HELLO_STDOUT  "Ignored hello on stdout!\n"
#define IGNORED_HELLO_STDERR  "Ignored hello on stderr!\n"

/* Notes:
 * - stdout and stderr are periodically closed or redirected to /dev/null in this test, so
 *   diagnostic error messages will not appear on the terminal (like errx output). Use strace and
 *   Gramine logs to analyze and debug this test instead.
 * - Under Gramine, app stdout and stderr streams are both redirected to host stdout. The host
 *   stderr only prints Gramine logs. So, don't be surprised that `console > /dev/null` and
 *   `gramine-direct console > /dev/null` show different results.
 */

int main(void) {
    /* initialization -- write some messages and save stdout/stderr (for further restore) */
    ssize_t x = CHECK(write(STDOUT_FILENO, FIRST_HELLO_STDOUT, strlen(FIRST_HELLO_STDOUT)));
    if (x != strlen(FIRST_HELLO_STDOUT))
        CHECK(-1);
    x = CHECK(write(STDERR_FILENO, FIRST_HELLO_STDERR, strlen(FIRST_HELLO_STDERR)));
    if (x != strlen(FIRST_HELLO_STDERR))
        CHECK(-1);

    int saved_stdout = CHECK(dup(STDOUT_FILENO));
    int saved_stderr = CHECK(dup(STDERR_FILENO));

    /* test 1 -- close stdout/stderr, spawn a child, the child should *not* print anything */
    CHECK(close(STDOUT_FILENO));
    CHECK(close(STDERR_FILENO));

    pid_t p = CHECK(fork());
    if (p == 0) {
        x = write(STDOUT_FILENO, IGNORED_HELLO_STDOUT, strlen(IGNORED_HELLO_STDOUT));
        if (x != -1 || errno != EBADF)
            errx(1, "write(stdout) didn't fail with EBADF (returned: %ld, errno: %d)", x, errno);
        x = write(STDERR_FILENO, IGNORED_HELLO_STDERR, strlen(IGNORED_HELLO_STDERR));
        if (x != -1 || errno != EBADF)
            errx(1, "write(stderr) didn't fail with EBADF (returned: %ld, errno: %d)", x, errno);
        return 0;
    }

    int status = 0;
    CHECK(wait(&status));
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        errx(1, "child died with status: %#x", status);

    /* test 2 -- restore stdout/stderr and print one more message */
    CHECK(dup2(saved_stdout, STDOUT_FILENO));
    CHECK(dup2(saved_stderr, STDERR_FILENO));

    x = CHECK(write(STDOUT_FILENO, SECOND_HELLO_STDOUT, strlen(SECOND_HELLO_STDOUT)));
    if (x != strlen(SECOND_HELLO_STDOUT))
        CHECK(-1);
    x = CHECK(write(STDERR_FILENO, SECOND_HELLO_STDERR, strlen(SECOND_HELLO_STDERR)));
    if (x != strlen(SECOND_HELLO_STDERR))
        CHECK(-1);

    /* test 3 -- redirect stdout/stderr to null, the process should *not* print anything */
    int dev_null_fd = open("/dev/null", O_WRONLY, 0666);
    CHECK(close(STDOUT_FILENO));
    CHECK(close(STDERR_FILENO));
    CHECK(dup2(dev_null_fd, STDOUT_FILENO));
    CHECK(dup2(dev_null_fd, STDERR_FILENO));
    CHECK(close(dev_null_fd)); /* not needed anymore */

    x = CHECK(write(STDOUT_FILENO, IGNORED_HELLO_STDOUT, strlen(IGNORED_HELLO_STDOUT)));
    if (x != strlen(IGNORED_HELLO_STDOUT))
        CHECK(-1);
    x = CHECK(write(STDERR_FILENO, IGNORED_HELLO_STDERR, strlen(IGNORED_HELLO_STDERR)));
    if (x != strlen(IGNORED_HELLO_STDERR))
        CHECK(-1);

    /* test 4 -- spawn a child, the child should *not* print anything */
    p = CHECK(fork());
    if (p == 0) {
        x = CHECK(write(STDOUT_FILENO, IGNORED_HELLO_STDOUT, strlen(IGNORED_HELLO_STDOUT)));
        if (x != strlen(IGNORED_HELLO_STDOUT))
            CHECK(-1);
        x = CHECK(write(STDERR_FILENO, IGNORED_HELLO_STDERR, strlen(IGNORED_HELLO_STDERR)));
        if (x != strlen(IGNORED_HELLO_STDERR))
            CHECK(-1);
        return 0;
    }

    status = 0;
    CHECK(wait(&status));
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        errx(1, "child died with status: %#x", status);

    /* finalization -- restore stdout/stderr and write some messages */
    CHECK(close(STDOUT_FILENO));
    CHECK(close(STDERR_FILENO));
    CHECK(dup2(saved_stdout, STDOUT_FILENO));
    CHECK(dup2(saved_stderr, STDERR_FILENO));

    puts("TEST OK");
    return 0;
}
