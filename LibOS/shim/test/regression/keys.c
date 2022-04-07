/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/* Test for setting and reading encrypted files keys (/dev/attestation/keys). */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "rw_file.h"

#define KEY_PATH "/dev/attestation/keys/custom"

#define INVALID_KEY "foo"
#define OLD_KEY "00112233445566778899aabbccddeeff"
#define NEW_KEY "8899aabbccddeeff0011223344556677"

#define KEY_LEN 32

static void expect_key(const char* desc, const char* path, const char* expected_key) {
    char key[KEY_LEN + 1];
    ssize_t n = posix_file_read(path, key, KEY_LEN);
    if (n < 0)
        err(1, "%s: error reading %s", desc, path);
    if (n < KEY_LEN)
        errx(1, "%s: file %s is too short: %zd", desc, path, n);
    key[KEY_LEN] = '\0';

    if (strcmp(key, expected_key)) {
        errx(1, "%s: wrong key: expected %s, got %s", desc, key, expected_key);
    }
}

static void write_key(const char* desc, const char* path, const char* key) {
    ssize_t n = posix_file_write(path, key, KEY_LEN);
    if (n < 0)
        err(1, "%s: error writing %s", desc, path);
    if (n < KEY_LEN)
        errx(1, "%s: not enough bytes written to %s: %zd", desc, path, n);
}

int main(void) {
    expect_key("before writing key", KEY_PATH, OLD_KEY);

    ssize_t n = posix_file_write(KEY_PATH, INVALID_KEY, strlen(INVALID_KEY));
    if (n >= 0 || (n < 0 && errno != EACCES))
        err(1, "writing invalid key: expected EACCES");

    write_key("writing key", KEY_PATH, NEW_KEY);
    expect_key("after writing key", KEY_PATH, NEW_KEY);

    /* Check if the child process will see the updated key. */
    pid_t pid = fork();
    if (pid < 0)
        err(1, "fork");
    if (pid == 0) {
        expect_key("in child process", KEY_PATH, NEW_KEY);
    } else {
        int status;
        if (waitpid(pid, &status, 0) == -1)
            err(1, "waitpid");
        if (!WIFEXITED(status))
            errx(1, "child not exited");
        if (WEXITSTATUS(status) != 0)
            errx(1, "unexpected exit status: %d", WEXITSTATUS(status));
        printf("TEST OK\n");
    }

    return 0;
}
