/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rw_file.h"

#define SECRETSTRING "Secret string\n"

int main(int argc, char** argv) {
    int ret;
    ssize_t bytes;

    if (argc != 2)
        errx(EXIT_FAILURE, "Usage: %s <protected file to create/validate>", argv[0]);

    ret = access(argv[1], F_OK);
    if (ret < 0) {
        if (errno == ENOENT) {
            /* file is not yet created, create with secret string */
            bytes = rw_file_stdio(argv[1], SECRETSTRING, sizeof(SECRETSTRING), /*do_write=*/true);
            if (bytes != sizeof(SECRETSTRING)) {
                /* error is already printed by rw_file_f() */
                return EXIT_FAILURE;
            }
            printf("CREATION OK\n");
            return 0;
        }
        err(EXIT_FAILURE, "access failed");
    }

    char buf[128];
    bytes = rw_file_stdio(argv[1], buf, sizeof(buf), /*do_write=*/false);
    if (bytes <= 0) {
        /* error is already printed by rw_file_f() */
        return EXIT_FAILURE;
    }
    buf[bytes - 1] = '\0';

    if (strncmp(SECRETSTRING, buf, sizeof(SECRETSTRING)))
        errx(EXIT_FAILURE, "Expected '%s' but read '%s'\n", SECRETSTRING, buf);

#ifdef MODIFY_MRENCLAVE
    /* The build system adds MODIFE_MRENCLAVE macro to produce a slightly different executable (due
     * to the below different string), which in turn produces a different MRENCLAVE SGX measurement.
     * This trick is to test `protected_mrsigner_files` functionality. */
    printf("READING FROM MODIFIED ENCLAVE OK\n");
#else
    printf("READING OK\n");
#endif
    return 0;
}
