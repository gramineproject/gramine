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

static void check_ownership_and_permissions(const char* path, struct stat* statbuf, uid_t uid,
                                            gid_t gid, mode_t permissions) {
    if (statbuf->st_uid != uid || statbuf->st_gid != gid)
        errx(1, "wrong ownership of file %s", path);
    if ((statbuf->st_mode & 0777) != permissions)
        errx(1, "wrong permissions of file %s", path);
}

static void should_exist(const char* path, size_t size) {
    struct stat statbuf;
    CHECK(stat(path, &statbuf));
    check_statbuf(path, &statbuf, size);
}

static int create_file(const char* path, const char* str, size_t len) {
    int fd = CHECK(open(path, O_RDWR | O_CREAT | O_TRUNC, 0600));

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

    if (fchown(fd, /*owner=*/123, /*group=*/123) != 0) /* dummy owner/group just for testing */
        err(1, "fchown before rename");
    if (fchmod(fd, 0660) != 0) /* note: no "other users" mode bits */
        err(1, "fchmod before rename");

    struct stat st;
    CHECK(stat(path1, &st));
    check_ownership_and_permissions(path1, &st, /*uid=*/123, /*gid=*/123, /*permissions=*/0660);

    CHECK(rename(path1, path2));

    should_not_exist(path1);
    should_exist(path2, message_len);

    if (fchown(fd, /*owner=*/321, /*group=*/321) != 0) /* different dummy owner/group */
        err(1, "fchown after rename");
    if (fchmod(fd, 0666) != 0) /* note: now with "other users" mode bits */
        err(1, "fchmod after rename");

    CHECK(stat(path2, &st));
    check_ownership_and_permissions(path2, &st, /*uid=*/321, /*gid=*/321, /*permissions=*/0666);

    CHECK(close(fd));
    CHECK(unlink(path2));
}

static void test_unlink_fchown(const char* path) {
    printf("%s...\n", __func__);

    int fd = create_file(path, /*message=*/NULL, /*len=*/0);

    CHECK(unlink(path));
    should_not_exist(path);

    if (fchown(fd, /*owner=*/123, /*group=*/123) != 0) /* dummy owner/group just for testing */
        err(1, "fchown after file removal");

    /* note that file was created with permissions 0600, see create_file() */
    struct stat st;
    CHECK(fstat(fd, &st));
    check_ownership_and_permissions(path, &st, /*uid=*/123, /*gid=*/123, /*permissions=*/0600);

    CHECK(close(fd));
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
    puts("TEST OK");
    return 0;
}
