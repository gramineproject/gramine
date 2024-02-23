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
#define SECRETSTRING_LEN (sizeof(SECRETSTRING) - 1)

int main(int argc, char** argv) {
    int ret;
    ssize_t bytes;

    if (argc != 3)
        errx(EXIT_FAILURE, "Usage: %s <protected file to create/validate> <unlink?>", argv[0]);

    ret = access(argv[1], F_OK);
    if (ret < 0) {
        if (errno == ENOENT) {
            /* file is not yet created, create with secret string */
            bytes = stdio_file_write(argv[1], SECRETSTRING, SECRETSTRING_LEN);
            if (bytes < 0) {
                /* error is already printed by stdio_file_write() */
                return EXIT_FAILURE;
            }

            if (bytes != SECRETSTRING_LEN)
                errx(EXIT_FAILURE, "Wrote %ld instead of expected %ld", bytes, SECRETSTRING_LEN);

            printf("CREATION OK\n");
            return 0;
        }
        if (errno != EACCES || strcmp(argv[2], "unlink") != 0) {
            /* access() can legitimately return EACCES if we're testing the "modified-MRENCLAVE
             * app wants to delete the previous-MRENCLAVE-sealed file" corner case */
            err(EXIT_FAILURE, "access failed");
        }
    }

    /* at this point, the file exists (either created by above or already existed on storage) */

    if (strcmp(argv[2], "unlink") == 0) {
        /* verify that removing the file always works, even with a mismatching MRENCLAVE */
        ret = unlink(argv[1]);
        if (ret < 0)
            err(EXIT_FAILURE, "unlink failed");

        printf("UNLINK OK");
        return 0;
    }

    char buf[SECRETSTRING_LEN];
    bytes = stdio_file_read(argv[1], buf, sizeof(buf));
    if (bytes < 0) {
        /* error is already printed by stdio_file_read() */
        return EXIT_FAILURE;
    }

    if (bytes != SECRETSTRING_LEN)
        errx(EXIT_FAILURE, "Read %ld instead of expected %ld", bytes, SECRETSTRING_LEN);

    if (memcmp(SECRETSTRING, buf, SECRETSTRING_LEN))
        errx(EXIT_FAILURE, "Read wrong content (expected '%s')\n", SECRETSTRING);

#ifdef MODIFY_MRENCLAVE
    /* The build system adds MODIFE_MRENCLAVE macro to produce a slightly different executable (due
     * to the below different string), which in turn produces a different MRENCLAVE SGX measurement.
     * This trick is to test `_sgx_mrsigner` functionality. */
    printf("READING FROM MODIFIED ENCLAVE OK\n");
#else
    printf("READING OK\n");
#endif
    return 0;
}
