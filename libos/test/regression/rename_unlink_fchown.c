/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation
 *                    Michael Steiner <michael.steiner@intel.com>
 */

/*
 * Tests for fchown after renaming and deleting files. Mostly focused on cases where a file is still
 * open. These tests are separate from other renaming/deleting tests in `rename_unlink.c` because
 * these tests require a root user to perform fchown with arbitrary user/group.
 */

#define _DEFAULT_SOURCE /* fchmod */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "rw_file.h"

static const char message[] = "first message\n";
static const size_t message_len = sizeof(message) - 1;

static void should_not_exist(const char* path) {
    struct stat statbuf;

    if (stat(path, &statbuf) == 0)
        errx(1, "%s unexpectedly exists", path);
    if (errno != ENOENT)
        err(1, "stat %s", path);
}

static void check_statbuf(const char* desc, struct stat* statbuf, size_t size) {
    assert(!OVERFLOWS(off_t, size));

    if (!S_ISREG(statbuf->st_mode))
        errx(1, "%s: wrong mode (0o%o)", desc, statbuf->st_mode);
    if (statbuf->st_size != (off_t)size)
        errx(1, "%s: wrong size (%lu)", desc, statbuf->st_size);
}

static void should_exist(const char* path, size_t size) {
    struct stat statbuf;

    if (stat(path, &statbuf) != 0)
        err(1, "stat %s", path);

    check_statbuf(path, &statbuf, size);
}

static int create_file(const char* path, const char* str, size_t len) {
    int fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        err(1, "open %s", path);

    ssize_t n = posix_fd_write(fd, str, len);
    if (n < 0)
        errx(1, "posix_fd_write %s", path);
    if ((size_t)n != len)
        errx(1, "written less bytes than expected into %s", path);

    return fd;
}

static void test_rename_fchown_fchmod(const char* path1, const char* path2) {
    printf("%s...\n", __func__);

    int fd = create_file(path1, message, message_len);
    if (fd < 0)
        err(1, "create %s", path1);

    if (fchown(fd, /*owner=*/123, /*group=*/123) != 0) /* dummy owner/group just for testing */
        err(1, "fchown before rename");
    if (fchmod(fd, (mode_t)0660) != 0) /* note: no "other users" mode bits */
        err(1, "fchmod before rename");

    struct stat st;
    if (stat(path1, &st) != 0)
        err(1, "Failed to stat file %s", path1);
    if (st.st_uid != 123 || st.st_gid != 123)
        err(1, "wrong ownership of file %s", path1);
    if ((st.st_mode & ((mode_t)0777)) != (mode_t)0660)
        err(1, "wrong permissions of file %s", path1);

    if (rename(path1, path2) != 0)
        err(1, "rename");

    should_not_exist(path1);
    should_exist(path2, message_len);

    if (fchown(fd, /*owner=*/321, /*group=*/321) != 0) /* different dummy owner/group */
        err(1, "fchown after rename");
    if (fchmod(fd, (mode_t)0666) != 0) /* note: now with "other users" mode bits */
        err(1, "fchmod after rename");

    if (stat(path2, &st) != 0)
        err(1, "Failed to stat (renamed) file %s", path2);
    if (st.st_uid != 321 || st.st_gid != 321)
        err(1, "wrong ownership of (renamed) file %s", path2);
    if ((st.st_mode & ((mode_t)0777)) != (mode_t)0666)
        err(1, "wrong permissions of (renamed) file %s", path2);

    if (close(fd) != 0)
        err(1, "close %s", path2);

    if (unlink(path2) != 0)
        err(1, "unlink %s", path2);
}

static void test_unlink_fchown(const char* path) {
    printf("%s...\n", __func__);

    int fd = create_file(path, /*message=*/NULL, /*len=*/0);

    if (unlink(path) != 0)
        err(1, "unlink");

    should_not_exist(path);

    if (fchown(fd, /*owner=*/123, /*group=*/123) != 0) /* dummy owner/group just for testing */
        err(1, "fchown");

    struct stat st;
    if (fstat(fd, &st) != 0)
        err(1, "Failed to fstat file %s", path);
    if (st.st_uid != 123 || st.st_gid != 123)
        err(1, "wrong ownership of file %s", path);

    if (close(fd) != 0)
        err(1, "close unlinked %s", path);
}

int main(int argc, char* argv[]) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc != 3)
        errx(1, "Usage: %s <path1> <path2>", argv[0]);

    const char* path1 = argv[1];
    const char* path2 = argv[2];

    test_rename_fchown_fchmod(path1, path2);
    test_unlink_fchown(path1);
    printf("TEST OK\n");
    return 0;
}
