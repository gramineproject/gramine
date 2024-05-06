/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Tests for renaming and deleting files. Mostly focus on cases where a file is still open.
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

static const char message1[] = "first message\n";
static const size_t message1_len = sizeof(message1) - 1;

static const char message2[] = "second message\n";
static const size_t message2_len = sizeof(message2) - 1;

static_assert(sizeof(message1) != sizeof(message2), "the messages should have different lengths");

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

static void should_contain(const char* desc, int fd, const char* str, size_t len) {
    char* buffer = malloc(len);
    if (!buffer)
        err(1, "malloc");

    struct stat statbuf;
    if (fstat(fd, &statbuf) != 0)
        err(1, "%s: fstat", desc);
    check_statbuf(desc, &statbuf, len);

    if (lseek(fd, 0, SEEK_SET) != 0)
        err(1, "%s: lseek", desc);

    ssize_t n = posix_fd_read(fd, buffer, len);
    if (n < 0)
        errx(1, "%s: posix_fd_read failed", desc);
    if ((size_t)n != len)
        errx(1, "%s: read less bytes than expected", desc);

    if (memcmp(buffer, str, len) != 0)
        errx(1, "%s: wrong content", desc);

    free(buffer);
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

static void create_file_and_close(const char* path, const char* str, size_t len) {
    int fd = create_file(path, str, len);
    if (close(fd) != 0)
        err(1, "close %s", path);
}

static void test_rename_same_file(const char* path) {
    printf("%s...\n", __func__);

    int fd = create_file(path, message1, message1_len);

    if (rename(path, path) != 0)
        err(1, "rename");

    if (close(fd) != 0)
        err(1, "close %s", path);

    if (unlink(path) != 0)
        err(1, "unlink %s", path);
}

static void test_simple_rename(const char* path1, const char* path2) {
    printf("%s...\n", __func__);

    create_file_and_close(path1, message1, message1_len);

    if (rename(path1, path2) != 0)
        err(1, "rename");

    should_not_exist(path1);
    should_exist(path2, message1_len);

    int fd = open(path2, O_RDONLY, 0);
    if (fd < 0)
        err(1, "open %s", path2);

    should_contain("file opened after it's renamed", fd, message1, message1_len);

    if (close(fd) != 0)
        err(1, "close %s", path2);

    if (unlink(path2) != 0)
        err(1, "unlink %s", path2);
}

static void test_rename_replace(const char* path1, const char* path2) {
    printf("%s...\n", __func__);

    create_file_and_close(path1, message1, message1_len);

    int fd = create_file(path2, message2, message2_len);

    if (fd < 0)
        err(1, "open %s", path2);

    if (rename(path1, path2) != 0)
        err(1, "rename");

    should_not_exist(path1);

    should_exist(path2, message1_len);

    /* We expect `fd` to still point to old data, even though we replaced the file under its path */
    should_contain("file opened before it's replaced", fd, message2, message2_len);

    if (close(fd) != 0)
        err(1, "close %s", path2);

    fd = open(path2, O_RDONLY, 0);
    if (fd < 0)
        err(1, "open %s", path2);

    should_contain("file opened after it's replaced", fd, message1, message1_len);

    if (close(fd) != 0)
        err(1, "close %s", path2);

    if (unlink(path2) != 0)
        err(1, "unlink %s", path2);
}

static void test_rename_follow(const char* path1, const char* path2) {
    printf("%s...\n", __func__);

    int fd = create_file(path1, message1, message1_len);

    if (fd < 0)
        err(1, "open %s", path1);

    if (rename(path1, path2) != 0)
        err(1, "rename");

    should_not_exist(path1);
    should_exist(path2, message1_len);

    if (lseek(fd, 0, SEEK_SET) != 0)
        err(1, "lseek");

    ssize_t n = posix_fd_write(fd, message2, message2_len);
    if (n < 0)
        errx(1, "posix_fd_write failed");
    if ((size_t)n != message2_len)
        errx(1, "wrote less bytes than expected");

    should_contain("file opened before it's renamed", fd, message2, message2_len);

    if (close(fd) != 0)
        err(1, "close %s", path2);

    fd = open(path2, O_RDONLY, 0);
    if (fd < 0)
        err(1, "open %s", path2);

    /* We expect `fd` to point to new data, even though we changed data via old fd after rename */
    should_contain("file opened after it's renamed", fd, message2, message2_len);

    if (close(fd) != 0)
        err(1, "close %s", path2);

    if (unlink(path2) != 0)
        err(1, "unlink %s", path2);
}

// NOTE: below will _not_ run correctly when directly executed unless you run as root.
// But it should run properly in gramine when executed as normal user.
static void test_rename_fchown_fchmod(const char* path1, const char* path2) {
    printf("%s...\n", __func__);

    int fd = create_file(path1, message1, message1_len);

    if (fchown(fd, 1, 1))
        err(1, "fchown before rename");
    if (fchmod(fd, S_IRWXU | S_IRWXG) != 0)  // Note: no other!
        err(1, "fchmod before rename");
    struct stat st;
    if (stat(path1, &st) != 0)
        err(1, "Failed to stat file %s", path1);
    if (st.st_uid != 1 || st.st_gid != 1)
        err(1, "wrong ownership of file %s", path1);
    if (st.st_mode & S_IRWXO)
        err(1, "wrong permissions of file %s", path1);

    if (fd < 0)
        err(1, "open %s", path1);

    if (rename(path1, path2) != 0)
        err(1, "rename");

    should_not_exist(path1);
    should_exist(path2, message1_len);

    if (fchown(fd, 2, 2))
        err(1, "fchown after rename");
    if (fchmod(fd, S_IRWXU | S_IRWXG | S_IRWXO) != 0)  // Note: with other now!
        err(1, "fchmod after rename");
    if (stat(path2, &st) != 0)
        err(1, "Failed to stat (renamed) file %s", path2);
    if (st.st_uid != 2 || st.st_gid != 2)
        err(1, "wrong ownership of (renamed) file %s", path2);
    if (!(st.st_mode & S_IRWXO))
        err(1, "wrong permissions of (renamed) file %s", path2);

    if (close(fd) != 0)
        err(1, "close %s", path2);

    if (unlink(path2) != 0)
        err(1, "unlink %s", path2);
}

static void test_rename_open_file(const char* path1, const char* path2) {
    printf("%s...\n", __func__);

    int fd = create_file(path1, message1, message1_len);

    if (rename(path1, path2) != 0)
        err(1, "rename");

    should_contain("file opened before it's renamed", fd, message1, message1_len);

    if (close(fd) != 0)
        err(1, "close %s", path2);

    if (unlink(path2) != 0)
        err(1, "unlink %s", path2);
}

static void test_unlink_and_recreate(const char* path) {
    printf("%s...\n", __func__);

    int fd1 = create_file(path, message1, message1_len);

    if (unlink(path) != 0)
        err(1, "unlink");

    should_not_exist(path);

    int fd2 = create_file(path, message2, message2_len);

    should_exist(path, message2_len);
    should_contain("file opened before deleting", fd1, message1, message1_len);
    should_contain("file opened after the old one is deleted", fd2, message2, message2_len);

    if (close(fd1) != 0)
        err(1, "close old %s", path);
    if (close(fd2) != 0)
        err(1, "close new %s", path);
    if (unlink(path) != 0)
        err(1, "unlink %s", path);
}

static void test_unlink_and_write(const char* path) {
    printf("%s...\n", __func__);

    int fd = create_file(path, /*message=*/NULL, /*len=*/0);

    if (unlink(path) != 0)
        err(1, "unlink");

    should_not_exist(path);

    ssize_t n = posix_fd_write(fd, message1, message1_len);
    if (n < 0)
        errx(1, "posix_fd_write %s", path);
    if ((size_t)n != message1_len)
        errx(1, "written less bytes than expected into %s", path);

    should_contain("unlinked file", fd, message1, message1_len);
    should_not_exist(path);

    if (close(fd) != 0)
        err(1, "close unlinked %s", path);
}

static void test_unlink_fchmod(const char* path) {
    printf("%s...\n", __func__);

    int fd = create_file(path, /*message=*/NULL, /*len=*/0);

    if (unlink(path) != 0)
        err(1, "unlink");

    should_not_exist(path);

    if (fchmod(fd, (mode_t)0644) != 0)
        err(1, "fchmod");

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

    test_rename_same_file(path1);
    test_simple_rename(path1, path2);
    test_rename_replace(path1, path2);
    test_rename_follow(path1, path2);
    test_rename_fchown_fchmod(path1, path2);
    test_rename_open_file(path1, path2);
    test_unlink_and_recreate(path1);
    test_unlink_and_write(path1);
    test_unlink_fchmod(path1);
    printf("TEST OK\n");
    return 0;
}
