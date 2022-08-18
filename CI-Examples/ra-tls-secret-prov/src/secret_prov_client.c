/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "secret_prov.h"

#define SEND_STRING "MORE"

#define CA_CRT_PATH "ssl/ca.crt"

int main(int argc, char** argv) {
    int ret;

    uint8_t* secret1 = NULL;
    size_t secret1_size = 0;
    uint8_t secret2[3] = {0}; /* we expect second secret to be 2-char string */

    struct ra_tls_ctx* ctx = NULL;
    ret = secret_provision_start("dummyserver:80;localhost:4433;anotherdummy:4433",
                                 CA_CRT_PATH, &ctx);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_start() returned %d\n", ret);
        goto out;
    }

    ret = secret_provision_get(ctx, &secret1, &secret1_size);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_get() returned %d\n", ret);
        goto out;
    }
    if (!secret1_size) {
        fprintf(stderr, "[error] secret_provision_get() returned secret with size 0\n");
        goto out;
    }
    secret1[secret1_size - 1] = '\0';

    /* let's ask for another secret (just to show communication with secret-prov server) */
    ret = secret_provision_write(ctx, (uint8_t*)SEND_STRING, sizeof(SEND_STRING));
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_write() returned %d\n", ret);
        goto out;
    }

    /* the secret we expect in return is a 2-char string */
    ret = secret_provision_read(ctx, secret2, sizeof(secret2));
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_read() returned %d\n", ret);
        goto out;
    }
    secret2[sizeof(secret2) - 1] = '\0';

    printf("--- Received secret1 = '%s', secret2 = '%s' ---\n", secret1, secret2);
    ret = 0;
out:
    free(secret1);
    secret_provision_close(ctx);
    return ret == 0 ? 0 : 1;
}
