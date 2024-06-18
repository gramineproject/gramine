/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 *                    Michael Steiner <michael.steiner@intel.com>
 */

/*
 * Tests for rollback protection of protected (encrypted) files
 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

/* TODO (MST): this is "borrowed" from common/include/api.h. replace below with `#include "api.h"`
 * once i figured out how to fix the meson.build files .... */
#define __UNUSED(x) \
    do {            \
        (void)(x);  \
    } while (0)

/* function to print out test result to be parsed by driver script in python.
 * Note: OK in tests below should cover the case for protection-mode=strict, so for other modes some
 * tests can be expected to FAIL (documented by a corresponding comment behind the call to
 * test_report()*/
#define test_report(result) printf("%s: %s\n", result, __func__)

const int MAX_FILE_NAME_SIZE = 256;

static const char message[] =
    "short message\n"; /* a message we assume can be written in a single write */
static const size_t message_len = sizeof(message) - 1;

/* dummy functions which are gdb break-point targets */
#pragma GCC push_options
#pragma GCC optimize("O0")
static void adversary_save_file(const char* path) {
    __UNUSED(path); /* neeed in gdb though! */
}
static void adversary_reset_file(const char* path) {
    __UNUSED(path); /* neeed in gdb though! */
}
static void adversary_reset_file_as(const char* path, const char* path2) {
    __UNUSED(path);  /* neeed in gdb though! */
    __UNUSED(path2); /* neeed in gdb though! */
}
static void adversary_delete_file(const char* path) {
    __UNUSED(path); /* neeed in gdb though! */
    /* NOTE: as of 2024-06-14 this attack will never work as the dcache never
     * evicts entries and so libos thinks it still exists yet when it tries to open it (in
     * encrypted_file_internal_open), pal doesn't find it which results in a PalStreamOpen failed:
     * Stream does not exist (PAL_ERROR_STREAMNOTEXIST) in PalStreamOpen.
     *
     * This means that all of the test_delete_rollback will also fail for protection-mode=none.
     * The tests though are still retained just in case dcache flushs would be eventually added. */
}
#pragma GCC pop_options

/*
 * Non-adverserial tests
 * --------------------- */

static void test_open_pre_existing(const char* path1) {
    int fd = open(path1, O_RDWR);
    if (fd < 0) {
        test_report("OK"); /* Note: open only should fail in strict protection mode! */
    } else {
        test_report("FAIL");
    }
}

static void test_reopen_base(const char* path1) {
    int fd = open(path1, O_RDWR | O_EXCL | O_CREAT, 0600);
    if (fd < 0) {
        err(1, "open %s", path1);
    }

    ssize_t n = write(fd, message, message_len);
    if (n < 0)
        err(1, "write %s", path1);
    if ((size_t)n != message_len)
        errx(1, "written less bytes than expected into %s", path1);

    if (close(fd) != 0)
        err(1, "close %s", path1);
}

static void test_reopen_rw(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);

    test_reopen_base(path1);

    int fd = open(path1, O_RDWR);
    if (fd > 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_reopen_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);

    test_reopen_base(path1);

    int fd = open(path1, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd > 0) {
        test_report("FAIL");
    } else {
        test_report("OK");
    }
}

static void test_reopen_non_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);

    test_reopen_base(path1);

    int fd = open(path1, O_RDWR | O_CREAT, 0600);
    if (fd > 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_reopen_renamed_base(const char* path1, const char* path2) {
    int fd = open(path1, O_RDWR | O_EXCL | O_CREAT, 0600);
    if (fd < 0) {
        err(1, "open %s", path1);
    }

    ssize_t n = write(fd, message, message_len);
    if (n < 0)
        err(1, "write %s", path1);
    if ((size_t)n != message_len)
        errx(1, "written less bytes than expected into %s", path1);

    if (close(fd) != 0)
        err(1, "close %s", path1);

    if (rename(path1, path2) != 0)
        err(1, "rename");
}

static void test_reopen_renamed_rw(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);
    char path2[MAX_FILE_NAME_SIZE];
    snprintf(path2, MAX_FILE_NAME_SIZE, "%s/%s.renamed", work_dir, __func__);

    test_reopen_renamed_base(path1, path2);

    int fd = open(path2, O_RDWR);
    if (fd > 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_reopen_renamed_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);
    char path2[MAX_FILE_NAME_SIZE];
    snprintf(path2, MAX_FILE_NAME_SIZE, "%s/%s.renamed", work_dir, __func__);

    test_reopen_renamed_base(path1, path2);

    int fd = open(path2, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd > 0) {
        test_report("FAIL");
    } else {
        test_report("OK");
    }
}

static void test_reopen_renamed_non_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);
    char path2[MAX_FILE_NAME_SIZE];
    snprintf(path2, MAX_FILE_NAME_SIZE, "%s/%s.renamed", work_dir, __func__);

    test_reopen_renamed_base(path1, path2);

    int fd = open(path2, O_RDWR | O_CREAT, 0600);
    if (fd > 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

/*
 * Adverserial tests
 * --------------------- */

static void test_rollback_after_close_base(const char* path1) {
    int fd = open(path1, O_RDWR | O_EXCL | O_CREAT, 0600);
    if (fd < 0) {
        err(1, "open %s", path1);
    }

    ssize_t n = write(fd, message, message_len);
    if (n < 0)
        err(1, "write %s", path1);
    if ((size_t)n != message_len)
        errx(1, "written less bytes than expected into %s", path1);

    if (close(fd) != 0)
        err(1, "close %s", path1);

    adversary_save_file(path1);

    fd = open(path1, O_RDWR);
    if (fd < 0) {
        err(1, "re-open %s", path1);
    }

    n = write(fd, message, message_len);
    if (n < 0)
        err(1, "posix_fd_write %s", path1);
    if ((size_t)n != message_len)
        errx(1, "written less bytes than expected into %s", path1);

    if (close(fd) != 0)
        err(1, "re-close %s", path1);

    adversary_reset_file(path1);
}

static void test_rollback_after_close_rw(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);

    test_rollback_after_close_base(path1);

    int fd = open(path1, O_RDWR);
    if (fd < 0) {
        test_report("OK"); /* Note: open should work in protection mode none! */
    } else {
        test_report("FAIL");
    }
}

static void test_rollback_after_close_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);

    test_rollback_after_close_base(path1);

    int fd = open(path1, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_rollback_after_close_non_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);

    test_rollback_after_close_base(path1);

    int fd = open(path1, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        test_report("OK"); /* Note: open should work in protection mode none! */
    } else {
        test_report("FAIL");
    }
}

static void test_delete_rollback_after_close_base(const char* path1) {
    int fd = open(path1, O_RDWR | O_EXCL | O_CREAT, 0600);
    if (fd < 0) {
        err(1, "open %s", path1);
    }

    ssize_t n = write(fd, message, message_len);
    if (n < 0)
        err(1, "write %s", path1);
    if ((size_t)n != message_len)
        errx(1, "written less bytes than expected into %s", path1);

    if (close(fd) != 0)
        err(1, "close %s", path1);

    adversary_delete_file(path1);
}

static void test_delete_rollback_after_close_rw(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);

    test_delete_rollback_after_close_base(path1);

    int fd = open(path1, O_RDWR);
    if (fd < 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_delete_rollback_after_close_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);

    test_delete_rollback_after_close_base(path1);

    int fd = open(path1, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_delete_rollback_after_close_non_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);

    test_delete_rollback_after_close_base(path1);

    int fd = open(path1, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_rollback_while_open(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);

    int fd = open(path1, O_RDWR | O_EXCL | O_CREAT, 0600);
    if (fd < 0) {
        err(1, "open %s", path1);
    }

    adversary_save_file(path1);

    ssize_t n = write(fd, message, message_len);
    if (n < 0)
        err(1, "write %s", path1);
    if ((size_t)n != message_len)
        errx(1, "written less bytes than expected into %s", path1);

    off_t ret = lseek(fd, 0, SEEK_SET);
    if (ret < 0)
        err(1, "seek %s", path1);
    char buf[message_len];
    n = read(fd, buf, message_len);
    if (n < 0)
        err(1, "read %s", path1);
    if ((size_t)n != message_len)
        errx(1, "read less bytes than expected from %s", path1);
    if (strncmp(buf, message, message_len) != 0)
        errx(1, "read different bytes than expected from %s", path1);

    adversary_reset_file(path1);

    /* TODO (MST): maybe flush state here?! */

    ret = lseek(fd, 0, SEEK_SET);
    if (ret < 0)
        err(1, "seek %s", path1);
    n = read(fd, buf, message_len);
    if (n < 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_rollback_after_rename_base(const char* path1, const char* path2) {
    int fd = open(path1, O_RDWR | O_EXCL | O_CREAT, 0600);
    if (fd < 0) {
        err(1, "open %s", path1);
    }

    ssize_t n = write(fd, message, message_len);
    if (n < 0)
        err(1, "write %s", path1);
    if ((size_t)n != message_len)
        errx(1, "written less bytes than expected into %s", path1);

    if (close(fd) != 0)
        err(1, "close %s", path1);

    adversary_save_file(path1);

    if (rename(path1, path2) != 0)
        err(1, "rename");

    adversary_reset_file(path1);
}

static void test_rollback_after_rename_rw(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);
    char path2[MAX_FILE_NAME_SIZE];
    snprintf(path2, MAX_FILE_NAME_SIZE, "%s/%s.renamed", work_dir, __func__);

    test_rollback_after_rename_base(path1, path2);

    int fd = open(path1, O_RDWR);
    if (fd < 0) {
        test_report("OK"); /* Note: open should work in protection mode none! */
    } else {
        test_report("FAIL");
    }
}

static void test_rollback_after_rename_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);
    char path2[MAX_FILE_NAME_SIZE];
    snprintf(path2, MAX_FILE_NAME_SIZE, "%s/%s.renamed", work_dir, __func__);

    test_rollback_after_rename_base(path1, path2);

    int fd = open(path1, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_rollback_after_rename_non_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);
    char path2[MAX_FILE_NAME_SIZE];
    snprintf(path2, MAX_FILE_NAME_SIZE, "%s/%s.renamed", work_dir, __func__);

    test_rollback_after_rename_base(path1, path2);

    int fd = open(path1, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        test_report("OK"); /* Note: open should work in protection mode none! */
    } else {
        test_report("FAIL");
    }
}

static void test_rename_rollback_after_rename_base(const char* path1, const char* path2) {
    int fd = open(path1, O_RDWR | O_EXCL | O_CREAT, 0600);
    if (fd < 0) {
        err(1, "open %s", path1);
    }

    ssize_t n = write(fd, message, message_len);
    if (n < 0)
        err(1, "write %s", path1);
    if ((size_t)n != message_len)
        errx(1, "written less bytes than expected into %s", path1);

    if (close(fd) != 0)
        err(1, "close %s", path1);

    adversary_save_file(path1);

    if (rename(path1, path2) != 0)
        err(1, "rename");

    adversary_reset_file_as(path1, path2);
}

static void test_rename_rollback_after_rename_rw(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);
    char path2[MAX_FILE_NAME_SIZE];
    snprintf(path2, MAX_FILE_NAME_SIZE, "%s/%s.renamed", work_dir, __func__);

    test_rename_rollback_after_rename_base(path1, path2);

    int fd = open(path2, O_RDWR);
    if (fd < 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_rename_rollback_after_rename_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);
    char path2[MAX_FILE_NAME_SIZE];
    snprintf(path2, MAX_FILE_NAME_SIZE, "%s/%s.renamed", work_dir, __func__);

    test_rename_rollback_after_rename_base(path1, path2);

    int fd = open(path2, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_rename_rollback_after_rename_non_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);
    char path2[MAX_FILE_NAME_SIZE];
    snprintf(path2, MAX_FILE_NAME_SIZE, "%s/%s.renamed", work_dir, __func__);

    test_rename_rollback_after_rename_base(path1, path2);

    int fd = open(path2, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_delete_rollback_after_rename_base(const char* path1, const char* path2) {
    int fd = open(path1, O_RDWR | O_EXCL | O_CREAT, 0600);
    if (fd < 0) {
        err(1, "open %s", path1);
    }

    ssize_t n = write(fd, message, message_len);
    if (n < 0)
        err(1, "write %s", path1);
    if ((size_t)n != message_len)
        errx(1, "written less bytes than expected into %s", path1);

    if (close(fd) != 0)
        err(1, "close %s", path1);

    if (rename(path1, path2) != 0)
        err(1, "rename");

    adversary_delete_file(path2);
}

static void test_delete_rollback_after_rename_rw(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);
    char path2[MAX_FILE_NAME_SIZE];
    snprintf(path2, MAX_FILE_NAME_SIZE, "%s/%s.renamed", work_dir, __func__);

    test_delete_rollback_after_rename_base(path1, path2);

    int fd = open(path2, O_RDWR);
    if (fd < 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_delete_rollback_after_rename_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);
    char path2[MAX_FILE_NAME_SIZE];
    snprintf(path2, MAX_FILE_NAME_SIZE, "%s/%s.renamed", work_dir, __func__);

    test_delete_rollback_after_rename_base(path1, path2);

    int fd = open(path2, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_delete_rollback_after_rename_non_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);
    char path2[MAX_FILE_NAME_SIZE];
    snprintf(path2, MAX_FILE_NAME_SIZE, "%s/%s.renamed", work_dir, __func__);

    test_delete_rollback_after_rename_base(path1, path2);

    int fd = open(path2, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_rollback_after_unlink_base(const char* path1) {
    int fd = open(path1, O_RDWR | O_EXCL | O_CREAT, 0600);
    if (fd < 0) {
        err(1, "open %s", path1);
    }

    ssize_t n = write(fd, message, message_len);
    if (n < 0)
        err(1, "write %s", path1);
    if ((size_t)n != message_len)
        errx(1, "written less bytes than expected into %s", path1);

    if (close(fd) != 0)
        err(1, "close %s", path1);

    adversary_save_file(path1);

    if (unlink(path1) != 0)
        err(1, "unlink");

    adversary_reset_file(path1);
}

static void test_rollback_after_unlink_rw(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);

    test_rollback_after_unlink_base(path1);

    int fd = open(path1, O_RDWR);
    if (fd < 0) {
        test_report("OK");
    } else {
        test_report("FAIL");
    }
}

static void test_rollback_after_unlink_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);

    test_rollback_after_unlink_base(path1);

    int fd = open(path1, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        test_report("OK"); /* Note: open should work in protection mode none! */
    } else {
        test_report("FAIL");
    }
}

static void test_rollback_after_unlink_non_exclusive(const char* work_dir) {
    char path1[MAX_FILE_NAME_SIZE];
    snprintf(path1, MAX_FILE_NAME_SIZE, "%s/%s", work_dir, __func__);

    test_rollback_after_unlink_base(path1);

    int fd = open(path1, O_RDWR | O_CREAT, 0600);
    if (fd < 0) {
        test_report("OK"); /* Note: open should work in protection mode none! */
    } else {
        test_report("FAIL");
    }
}

/*
 * Overall test driver
 * --------------------- */

static void run_tests(const char* work_dir, const char* input_file) {
    /* non-adverserial ones */
    test_open_pre_existing(input_file);
    test_reopen_rw(work_dir);
    test_reopen_exclusive(work_dir);
    test_reopen_non_exclusive(work_dir);
    test_reopen_renamed_rw(work_dir);
    test_reopen_renamed_exclusive(work_dir);
    test_reopen_renamed_non_exclusive(work_dir);

    /* adverserial ones */
    test_rollback_after_close_rw(work_dir);
    test_rollback_after_close_exclusive(work_dir);
    test_rollback_after_close_non_exclusive(work_dir);
    test_delete_rollback_after_close_rw(work_dir);
    test_delete_rollback_after_close_exclusive(work_dir);
    test_delete_rollback_after_close_non_exclusive(work_dir);
    test_rollback_while_open(work_dir);
    test_rollback_after_rename_rw(work_dir);
    test_rollback_after_rename_exclusive(work_dir);
    test_rollback_after_rename_non_exclusive(work_dir);
    test_rename_rollback_after_rename_rw(work_dir);
    test_rename_rollback_after_rename_exclusive(work_dir);
    test_rename_rollback_after_rename_non_exclusive(work_dir);
    test_delete_rollback_after_rename_rw(work_dir);
    test_delete_rollback_after_rename_exclusive(work_dir);
    test_delete_rollback_after_rename_non_exclusive(work_dir);
    test_rollback_after_unlink_rw(work_dir);
    test_rollback_after_unlink_exclusive(work_dir);
    test_rollback_after_unlink_non_exclusive(work_dir);
}

int main(int argc, char* argv[]) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (argc != 3)
        errx(1, "Usage: %s <work_dir> <input_file> (with input_file assumed to be pre-created)",
             argv[0]);

    const char* work_dir   = argv[1];
    const char* input_file = argv[2];

    /* all tests started in process leader */
    run_tests(work_dir, input_file);

    printf("TEST OK\n");
    exit(0);
}
