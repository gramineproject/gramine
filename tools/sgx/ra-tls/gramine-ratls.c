/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2023 Intel Corp.
 *                    Wojtek Porczyk <woju@invisiblethingslab.com>
 */

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "ra_tls.h"
#include "util.h"


int main(int argc, char* argv[]) {
    uint8_t* key_der = NULL;
    uint8_t* crt_der = NULL;
    size_t key_der_size;
    size_t crt_der_size;
    int ret;

    if (argc < 3) {
        fprintf(stderr, "usage: %s CERTPATH KEYPATH [COMMAND ...]\n", argv[0]);
        return 2;
    }

    ret = ra_tls_create_key_and_crt_der(&key_der, &key_der_size, &crt_der, &crt_der_size);
    if (ret < 0) {
        fprintf(stderr, "ra_tls_create_key_and_crt_der returned %d\n", ret);
        goto err;
    }

    ret = write_file(argv[1], crt_der_size, crt_der);
    if (ret < 0)
        goto err;

    ret = write_file(argv[2], key_der_size, key_der);
    if (ret < 0)
        goto err;

    free(key_der);
    free(crt_der);

    if (argc < 4) {
        return 0;
    }

    execvp(argv[3], argv + 3);
    perror("execvp");
    return 1;

err:
    free(key_der);
    free(crt_der);
    return 1;
 }
