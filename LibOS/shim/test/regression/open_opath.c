/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */
#define _GNU_SOURCE
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"
#include "rw_file.h"

static char g_expected_buf[] = "XXXXX";

static void check_file_contents(const char* path) {
    char buf[sizeof(g_expected_buf) * 2];
    ssize_t got = CHECK(posix_file_read(path, buf, sizeof(buf)));
    if (got != sizeof(g_expected_buf)) {
        errx(1, "short read from file \"%s\" - got %zd, expected %zu", path, got,
             sizeof(g_expected_buf));
    }
    if (memcmp(buf, g_expected_buf, sizeof(g_expected_buf))) {
        errx(1, "got unexpected data");
    }
}

static void write_expected_to_file(int dir_fd, const char* path) {
    int fd = CHECK(openat(dir_fd, path, O_WRONLY | O_CREAT | O_EXCL, 0777));
    ssize_t got = CHECK(posix_fd_write(fd, g_expected_buf, sizeof(g_expected_buf)));
    if (got != sizeof(g_expected_buf)) {
        errx(1, "short write from file \"%s\" - got %zd, expected %zu", path, got,
             sizeof(g_expected_buf));
    }
    CHECK(close(fd));
}

int main(void) {
    int root_fd = CHECK(open("/", O_PATH));
    int mnt_dir_fd = CHECK(openat(root_fd, "mnt", O_PATH | O_DIRECTORY | O_NOFOLLOW));
    CHECK(close(root_fd));

    /* Test a file on Gramine built-in tmpfs. */
    write_expected_to_file(mnt_dir_fd, "tmpfs/A");
    check_file_contents("/mnt/tmpfs/A");
    /* File inside built-in tmpfs, no need to remove it. */

    /* Test a file on the host fs. */
    write_expected_to_file(mnt_dir_fd, "../tmp/B");
    check_file_contents("/tmp/B");

    CHECK(unlinkat(mnt_dir_fd, "../tmp/B", 0));

    CHECK(close(mnt_dir_fd));

    char path[0x100];
    int fd = CHECK(open("/exec_victim", O_PATH | O_CLOEXEC));
    int ret = snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    if (ret < 0 || (size_t)ret >= sizeof(path)) {
        errx(1, "snprintf failed; %d", ret);
    }

    pid_t p = CHECK(fork());
    if (p == 0) {
        execl(path, "exec_victim", NULL);
        err(1, "execl");
    }

    int status = 0;
    CHECK(wait(&status));
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        errx(1, "child died with status: %#x", status);
    }

    puts("TEST OK");
    return 0;
}
