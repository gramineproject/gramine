/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"
#include "rw_file.h"

#define FILENAME     "fork_and_access_file_testfile"
#define MAX_BUF_SIZE 256

char g_parent_buf[MAX_BUF_SIZE];
char g_child_buf[MAX_BUF_SIZE];

int main(void) {
    int fd = CHECK(open(FILENAME, O_RDONLY));

    ssize_t parent_read_ret = CHECK(posix_fd_read(fd, g_parent_buf, sizeof(g_parent_buf)));
    CHECK(lseek(fd, 0, SEEK_SET));

    pid_t p = CHECK(fork());
    if (p == 0) {
        ssize_t child_read_ret = CHECK(posix_fd_read(fd, g_child_buf, sizeof(g_child_buf)));
        if (child_read_ret != parent_read_ret ||
                memcmp(g_child_buf, g_parent_buf, child_read_ret)) {
            errx(1, "child read data different from what parent read");
        }
        exit(0);
    }

    int status = 0;
    CHECK(wait(&status));
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        errx(1, "child died with status: %#x", status);

    CHECK(close(fd));
    puts("TEST OK");
    return 0;
}
