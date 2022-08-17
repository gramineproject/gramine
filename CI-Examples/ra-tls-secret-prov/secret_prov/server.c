/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "secret_prov.h"

#define PORT "4433"
#define EXPECTED_STRING "MORE"
#define FIRST_SECRET "FIRST_SECRET"
#define SECOND_SECRET "42" /* answer to ultimate question of life, universe, and everything */

#define SRV_CRT_PATH "../ssl/server.crt"
#define SRV_KEY_PATH "../ssl/server.key"

static pthread_mutex_t g_print_lock;

static void hexdump_mem(const void* data, size_t size) {
    uint8_t* ptr = (uint8_t*)data;
    for (size_t i = 0; i < size; i++)
        printf("%02x", ptr[i]);
    printf("\n");
}

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
    puts("[ WARNING: In reality, you would want to compare against expected values! ]");
    pthread_mutex_unlock(&g_print_lock);

    return 0;
}

/* this callback is called in a new thread associated with a client; be careful to make this code
 * thread-local and/or thread-safe */
static int communicate_with_client_callback(struct ra_tls_ctx* ctx) {
    int ret;

    /* if we reached this callback, the first secret was sent successfully */
    printf("--- Sent secret1 ---\n");

    /* let's send another secret (just to show communication with secret-awaiting client) */
    uint8_t buf[sizeof(EXPECTED_STRING)] = {0};

    ret = secret_provision_read(ctx, buf, sizeof(buf));
    if (ret < 0) {
        if (ret == -ECONNRESET) {
            /* client doesn't want another secret, shutdown communication gracefully */
            return 0;
        }

        fprintf(stderr, "[error] secret_provision_read() returned %d\n", ret);
        return -EINVAL;
    }

    if (memcmp(buf, EXPECTED_STRING, sizeof(EXPECTED_STRING))) {
        fprintf(stderr, "[error] client sent '%s' but expected '%s'\n", buf, EXPECTED_STRING);
        return -EINVAL;
    }

    ret = secret_provision_write(ctx, (uint8_t*)SECOND_SECRET, sizeof(SECOND_SECRET));
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_write() returned %d\n", ret);
        return -EINVAL;
    }

    printf("--- Sent secret2 = '%s' ---\n", SECOND_SECRET);
    return 0;
}

int main(void) {
    int ret = pthread_mutex_init(&g_print_lock, NULL);
    if (ret < 0)
        return ret;

    puts("--- Starting the Secret Provisioning server on port " PORT " ---");
    ret = secret_provision_start_server((uint8_t*)FIRST_SECRET, sizeof(FIRST_SECRET),
                                        PORT, SRV_CRT_PATH, SRV_KEY_PATH,
                                        verify_measurements_callback,
                                        communicate_with_client_callback);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_start_server() returned %d\n", ret);
        return 1;
    }

    pthread_mutex_destroy(&g_print_lock);
    return 0;
}
