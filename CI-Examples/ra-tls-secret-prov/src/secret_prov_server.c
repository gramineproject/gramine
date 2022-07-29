/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "secret_prov.h"

#define EXPECTED_STRING "MORE"
#define SECRET_STRING "42" /* answer to ultimate question of life, universe, and everything */

#define WRAP_KEY_FILENAME "files/wrap-key"
#define WRAP_KEY_SIZE     16

#define SRV_CRT_PATH "ssl/server.crt"
#define SRV_KEY_PATH "ssl/server.key"

static pthread_mutex_t g_print_lock;
char g_secret_pf_key_hex[WRAP_KEY_SIZE * 2 + 1];

static void hexdump_mem(const void* data, size_t size) {
    uint8_t* ptr = (uint8_t*)data;
    for (size_t i = 0; i < size; i++)
        printf("%02x", ptr[i]);
    printf("\n");
}

static int parse_hex(const char* hex, void* buffer, size_t buffer_size) {
    if (strlen(hex) != buffer_size * 2)
        return -1;

    for (size_t i = 0; i < buffer_size; i++) {
        if (!isxdigit(hex[i * 2]) || !isxdigit(hex[i * 2 + 1]))
            return -1;
        sscanf(hex + i * 2, "%02hhx", &((uint8_t*)buffer)[i]);
    }
    return 0;
}

/* expected SGX measurements in binary form */
static char g_expected_mrenclave[32];
static char g_expected_mrsigner[32];
static char g_expected_isv_prod_id[2];
static char g_expected_isv_svn[2];

static bool g_verify_mrenclave   = false;
static bool g_verify_mrsigner    = false;
static bool g_verify_isv_prod_id = false;
static bool g_verify_isv_svn     = false;

/* our own callback to verify SGX measurements during TLS handshake */
static int verify_measurements_callback(const char* mrenclave, const char* mrsigner,
                                        const char* isv_prod_id, const char* isv_svn) {
    assert(mrenclave && mrsigner && isv_prod_id && isv_svn);

    pthread_mutex_lock(&g_print_lock);
    puts("Received the following measurements from the client:");
    printf("  - MRENCLAVE:   "); hexdump_mem(mrenclave, 32);
    printf("  - MRSIGNER:    "); hexdump_mem(mrsigner, 32);
    printf("  - ISV_PROD_ID: %hu\n", *((uint16_t*)isv_prod_id));
    printf("  - ISV_SVN:     %hu\n", *((uint16_t*)isv_svn));

    if (g_verify_mrenclave &&
            memcmp(mrenclave, g_expected_mrenclave, sizeof(g_expected_mrenclave))){
        puts("Error: MRENCLAVE mismatch");
        goto fail;
    }

    if (g_verify_mrsigner &&
            memcmp(mrsigner, g_expected_mrsigner, sizeof(g_expected_mrsigner))){
        puts("Error: MRSIGNER mismatch");
        goto fail;
    }

    if (g_verify_isv_prod_id &&
            memcmp(isv_prod_id, g_expected_isv_prod_id, sizeof(g_expected_isv_prod_id))){
        puts("Error: ISV_PROD_ID mismatch");
        goto fail;
    }

    if (g_verify_isv_svn &&
            memcmp(isv_svn, g_expected_isv_svn, sizeof(g_expected_isv_svn))){
        puts("Error: ISV_SVN mismatch");
        goto fail;
    }

    pthread_mutex_unlock(&g_print_lock);
    return 0;

fail:
    pthread_mutex_unlock(&g_print_lock);
    return -1;
}

/* this callback is called in a new thread associated with a client; be careful to make this code
 * thread-local and/or thread-safe */
static int communicate_with_client_callback(struct ra_tls_ctx* ctx) {
    int ret;

    /* if we reached this callback, the first secret was sent successfully */
    printf("--- Sent secret1 = '%s' ---\n", g_secret_pf_key_hex);

    /* let's send another secret (just to show communication with secret-awaiting client) */
    int bytes;
    uint8_t buf[128] = {0};

    bytes = secret_provision_read(ctx, buf, sizeof(EXPECTED_STRING));
    if (bytes < 0) {
        if (bytes == -ECONNRESET) {
            /* client doesn't want another secret, shutdown communication gracefully */
            ret = 0;
            goto out;
        }

        fprintf(stderr, "[error] secret_provision_read() returned %d\n", bytes);
        ret = -EINVAL;
        goto out;
    }

    assert(bytes == sizeof(EXPECTED_STRING));
    if (memcmp(buf, EXPECTED_STRING, bytes)) {
        fprintf(stderr, "[error] client sent '%s' but expected '%s'\n", buf, EXPECTED_STRING);
        ret = -EINVAL;
        goto out;
    }

    bytes = secret_provision_write(ctx, (uint8_t*)SECRET_STRING, sizeof(SECRET_STRING));
    if (bytes < 0) {
        fprintf(stderr, "[error] secret_provision_write() returned %d\n", bytes);
        ret = -EINVAL;
        goto out;
    }

    printf("--- Sent secret2 = '%s' ---\n", SECRET_STRING);
    ret = 0;
out:
    secret_provision_close(ctx);
    return ret;
}

int main(int argc, char** argv) {
    int ret;

    if (argc > 1) {
        if (argc != 5) {
            printf("USAGE: %s <expected mrenclave> <expected mrsigner>"
                   " <expected isv_prod_id> <expected isv_svn>\n"
                   "       (first two in hex, last two as decimal; set to 0 to ignore)\n",
                   argv[0]);
            return 1;
        }

        printf("[ using our own SGX-measurement verification callback"
               " (via command line options) ]\n");

        g_verify_mrenclave   = true;
        g_verify_mrsigner    = true;
        g_verify_isv_prod_id = true;
        g_verify_isv_svn     = true;

        if (!strcmp(argv[1], "0")) {
            printf("  - ignoring MRENCLAVE\n");
            g_verify_mrenclave = false;
        } else if (parse_hex(argv[1], g_expected_mrenclave, sizeof(g_expected_mrenclave)) < 0) {
            printf("Cannot parse MRENCLAVE!\n");
            return 1;
        }

        if (!strcmp(argv[2], "0")) {
            printf("  - ignoring MRSIGNER\n");
            g_verify_mrsigner = false;
        } else if (parse_hex(argv[2], g_expected_mrsigner, sizeof(g_expected_mrsigner)) < 0) {
            printf("Cannot parse MRSIGNER!\n");
            return 1;
        }

        if (!strcmp(argv[3], "0")) {
            printf("  - ignoring ISV_PROD_ID\n");
            g_verify_isv_prod_id = false;
        } else {
            errno = 0;
            uint16_t isv_prod_id = (uint16_t)strtoul(argv[3], NULL, 10);
            if (errno) {
                printf("Cannot parse ISV_PROD_ID!\n");
                return 1;
            }
            memcpy(g_expected_isv_prod_id, &isv_prod_id, sizeof(isv_prod_id));
        }

        if (!strcmp(argv[4], "0")) {
            printf("  - ignoring ISV_SVN\n");
            g_verify_isv_svn = false;
        } else {
            errno = 0;
            uint16_t isv_svn = (uint16_t)strtoul(argv[4], NULL, 10);
            if (errno) {
                printf("Cannot parse ISV_SVN\n");
                return 1;
            }
            memcpy(g_expected_isv_svn, &isv_svn, sizeof(isv_svn));
        }
    } else {
        printf("[ using default SGX-measurement verification callback"
               " (via RA_TLS_* environment variables) ]\n");
    }

    ret = pthread_mutex_init(&g_print_lock, NULL);
    if (ret < 0)
        return ret;

    puts("--- Reading the master key for protected files from '" WRAP_KEY_FILENAME "' ---");
    int fd = open(WRAP_KEY_FILENAME, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[error] cannot open '" WRAP_KEY_FILENAME "'\n");
        return 1;
    }

    char buf[WRAP_KEY_SIZE + 1] = {0}; /* +1 is to detect if file is not bigger than expected */
    ssize_t bytes_read = 0;
    while (1) {
        ssize_t ret = read(fd, buf + bytes_read, sizeof(buf) - bytes_read);
        if (ret > 0) {
            bytes_read += ret;
        } else if (ret == 0) {
            /* end of file */
            break;
        } else if (errno == EAGAIN || errno == EINTR) {
            continue;
        } else {
            fprintf(stderr, "[error] cannot read '" WRAP_KEY_FILENAME "'\n");
            close(fd);
            return 1;
        }
    }

    ret = close(fd);
    if (ret < 0) {
        fprintf(stderr, "[error] cannot close '" WRAP_KEY_FILENAME "'\n");
        return 1;
    }

    if (bytes_read != WRAP_KEY_SIZE) {
        fprintf(stderr, "[error] encryption key from '" WRAP_KEY_FILENAME "' is not 16B in size\n");
        return 1;
    }

    uint8_t* ptr = (uint8_t*)buf;
    for (size_t i = 0; i < bytes_read; i++)
        sprintf(&g_secret_pf_key_hex[i * 2], "%02x", ptr[i]);

    puts("--- Starting the Secret Provisioning server on port 4433 ---");
    ret = secret_provision_start_server((uint8_t*)g_secret_pf_key_hex, sizeof(g_secret_pf_key_hex),
                                        "4433", SRV_CRT_PATH, SRV_KEY_PATH,
                                        argc > 1 ? verify_measurements_callback : NULL,
                                        communicate_with_client_callback);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_start_server() returned %d\n", ret);
        return 1;
    }

    pthread_mutex_destroy(&g_print_lock);
    return 0;
}
