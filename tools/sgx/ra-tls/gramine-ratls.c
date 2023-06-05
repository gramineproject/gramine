/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (C) 2023 Intel Corporation
 *                    Wojtek Porczyk <woju@invisiblethingslab.com>
 */

#include <fcntl.h>
#include <getopt.h>
#include <mbedtls/base64.h>
#include <mbedtls/error.h>
#include <mbedtls/pem.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "ra_tls.h"
#include "util.h"

char* progname = NULL;

static void usage(void) {
    fprintf(stderr, "usage: %s [-D|-P] CERTPATH KEYPATH [COMMAND ...]\n", progname);
}

static void help(void) {
    usage();
    fprintf(stderr,
        "\n"
        "options:\n"
        "  -h  show this help and exit\n"
        "  -D  use DER format\n"
        "  -P  use PEM format (default)\n"
    );
}

static int der_to_pem(const char* header, const char* footer, uint8_t* der, size_t der_size,
                      uint8_t** pem, size_t* pem_size) {
    size_t buf_size;
    int ret;

    if (!pem)
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;

    ret = mbedtls_pem_write_buffer(header, footer, der, der_size, /*buf=*/NULL, /*buf_len=*/0,
                                   &buf_size);
    if (!ret) {
        /* shouldn't happen, but let's be sure not to return 0 and leave *pem uninitialized */
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;
    } else if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        return ret;
    }

    *pem = malloc(buf_size);
    if (!*pem)
        return MBEDTLS_ERR_ERROR_GENERIC_ERROR;

    return mbedtls_pem_write_buffer(header, footer, der, der_size, *pem, buf_size, pem_size);
}

int main(int argc, char* argv[]) {
    uint8_t* key_der = NULL;
    uint8_t* crt_der = NULL;
    uint8_t* key_out = NULL;
    uint8_t* crt_out = NULL;
    size_t key_der_size;
    size_t crt_der_size;
    size_t key_out_size;
    size_t crt_out_size;
    bool want_pem = true;
    int ret;

    progname = argv[0];

    while ((ret = getopt(argc, argv, "DPh")) != -1) {
        switch (ret) {
        case 'D':
            want_pem = false;
            break;
        case 'P':
            want_pem = true;
            break;
        case 'h':
            help();
            return 0;
        default:
            usage();
            return 2;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc < 2) {
        usage();
        return 2;
    }

    ret = ra_tls_create_key_and_crt_der(&key_der, &key_der_size, &crt_der, &crt_der_size);
    if (ret < 0) {
        fprintf(stderr, "ra_tls_create_key_and_crt_der returned %d\n", ret);
        goto err;
    }

    if (want_pem) {
        /* keep this in sync with RA-TLS key type */
        ret = der_to_pem("-----BEGIN EC PRIVATE KEY-----\n", "-----END EC PRIVATE KEY-----\n",
                         key_der, key_der_size, &key_out, &key_out_size);
        if (ret < 0)
            goto err;
        /* RA-TLS certificates are always self-signed, so we unconditionally add TRUSTED */
        ret = der_to_pem("-----BEGIN TRUSTED CERTIFICATE-----\n",
                         "-----END TRUSTED CERTIFICATE-----\n", crt_der, crt_der_size, &crt_out,
                         &crt_out_size);
        if (ret < 0)
            goto err;
    } else { /* don't want_pem */
        key_out = key_der;
        key_out_size = key_der_size;
        key_der = NULL;
        crt_out = crt_der;
        crt_out_size = crt_der_size;
        crt_der = NULL;
    }

    ret = write_file(argv[0], crt_out_size, crt_out);
    if (ret < 0)
        goto err;

    ret = write_file(argv[1], key_out_size, key_out);
    if (ret < 0)
        goto err;

    free(key_der);
    free(crt_der);
    free(key_out);
    free(crt_out);

    if (argc < 3) {
        return 0;
    }

    execvp(argv[2], argv + 2);
    perror("execvp");
    return 1;

err:
    free(key_der);
    free(crt_der);
    free(key_out);
    free(crt_out);
    return 1;
 }
