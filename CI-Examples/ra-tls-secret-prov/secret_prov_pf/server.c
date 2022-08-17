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

int main(int argc, char** argv) {
    int ret;
    #define SECRET_KEY_SIZE 16
    uint8_t secret_key[SECRET_KEY_SIZE + 1] = {0}; /* +1 is to detect if file is not bigger than
                                                    * expected */
    ssize_t bytes_read = 0;

    ret = pthread_mutex_init(&g_print_lock, NULL);
    if (ret < 0)
        return ret;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s key_path\n", argv[0]);
        return 1;
    } else {
        printf("--- Reading the master key for encrypted files from '%s' ---\n", argv[1]);
        int fd = open(argv[1], O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "[error] cannot open %s\n", argv[1]);
            return 1;
        }
        while (1) {
            ssize_t ret = read(fd, secret_key + bytes_read, sizeof(secret_key) - bytes_read);
            if (ret > 0) {
                bytes_read += ret;
            } else if (ret == 0) {
                /* end of file */
                break;
            } else if (errno == EAGAIN || errno == EINTR) {
                continue;
            } else {
                fprintf(stderr, "[error] cannot read %s\n", argv[1]);
                close(fd);
                return 1;
            }
        }

        ret = close(fd);
        if (ret < 0) {
            fprintf(stderr, "[error] cannot close %s\n", argv[1]);
            return 1;
        }

        if (bytes_read != SECRET_KEY_SIZE) {
            fprintf(stderr, "[error] encryption key from %s is not %dB in size\n", argv[1],
                    SECRET_KEY_SIZE);
            return 1;
        }
    }

    puts("--- Starting the Secret Provisioning server on port 4433 ---");
    ret = secret_provision_start_server(secret_key, SECRET_KEY_SIZE,
                                        "4433", SRV_CRT_PATH, SRV_KEY_PATH,
                                        verify_measurements_callback,
                                        NULL);
    if (ret < 0) {
        fprintf(stderr, "[error] secret_provision_start_server() returned %d\n", ret);
        return 1;
    }

    pthread_mutex_destroy(&g_print_lock);
    return 0;
}
