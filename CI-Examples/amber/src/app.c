/*
 *  Copyright (C) 2022, Intel, All Rights Reserved
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include "mbedtls/build_info.h"
#include "mbedtls/base64.h"


int read_to_buffer(const char* fn, char buf[], size_t bufsz);
int write_from_buffer(const char* fn, char buf[], size_t bufsz);

#define AMBER_TOKEN_DEVFILE "/dev/amber/token"
#define AMBER_SECRET_DEVFILE "/dev/amber/secret"
#define AMBER_USERDATA_DEVFILE "/dev/amber/userdata"
#define AMBER_STATUS_DEVFILE "/dev/amber/status"
#define BUF_SZ 8096

int read_to_buffer(const char* fn, char buf[], size_t bufsz) {
    int ret;
    ssize_t cnt;
    int fd = open(fn, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[error] cannot open '%s'\n"
                        "Please make sure this app is running with Gramine-SGX\n", fn);
        return -1;
    }

    ssize_t bytes_read = 0;
    while (1) {
        cnt = read(fd, buf + bytes_read, bufsz - bytes_read);
        if (cnt > 0) {
            bytes_read += cnt;
        } else if (cnt == 0) {
            /* end of file */
            buf[bytes_read] = '\0';
            break;
        } else if (errno == EAGAIN || errno == EINTR) {
            continue;
        } else {
            fprintf(stderr, "[error] cannot read '%s'\n", fn);
            close(fd);
            return -1;
        }
    }

    ret = close(fd);
    if (ret < 0) {
        fprintf(stderr, "[error] cannot close '%s'\n", fn);
        return -1;
    }

    return ret;
}

int write_from_buffer(const char* fn, char buf[], size_t bufsz) {
    int ret;
    ssize_t cnt;
    int fd = open(fn, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "[error] cannot open '%s'\n"
                        "Please make sure this app is running with Gramine-SGX\n", fn);
        return -1;
    }
    off_t offset = 0;
    while (bufsz > 0) {
        cnt = write(fd, buf + offset, bufsz);
        if (cnt < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            fprintf(stderr, "[error] cannot write '%s'\n", fn);
            close(fd);
            return -1;
        }
        bufsz -= cnt;
        offset += cnt;
    }

    ret = close(fd);
    if (ret < 0) {
        fprintf(stderr, "[error] cannot close '%s'\n", fn);
        return -1;
    }

    return ret;
}

int (*ra_tls_create_key_and_crt_der_f)(uint8_t** der_key, size_t* der_key_size, uint8_t** der_crt,
                                       size_t* der_crt_size);

int main(int argc, char** argv) {
    int ret;
    char buf[BUF_SZ] = {0};

    void* ra_tls_attest_lib = dlopen("libra_tls_attest.so", RTLD_LAZY);;
    if (!ra_tls_attest_lib) {
        printf("User requested RA-TLS attestation but cannot find lib\n");
        return -1;
    }

    char* error;
    ra_tls_create_key_and_crt_der_f = dlsym(ra_tls_attest_lib, "ra_tls_create_key_and_crt_der");
    if ((error = dlerror()) != NULL) {
        printf("%s\n", error);
        return -1;
    }

    uint8_t* der_key = NULL;
    uint8_t* der_crt = NULL;
    size_t der_key_size;
    size_t der_crt_size;
    // An ephemeral keypair generated here, and it can be manually configured as well.
    ret = (*ra_tls_create_key_and_crt_der_f)(&der_key, &der_key_size, &der_crt, &der_crt_size);
    if (ret != 0) {
        printf(" failed\n  !  ra_tls_create_key_and_crt_der returned %d\n\n", ret);
        return -1;
    }
    printf("A keypair generated: %ld, %ld \n", der_key_size, der_crt_size);

    size_t b64_size = 0;
    // encode the raw pubkey material
    ret = mbedtls_base64_encode(buf, BUF_SZ - 1, &b64_size, der_crt, der_crt_size);
    if (ret < 0) {
        printf("Failed to base64 encode the generated cert.\n");
        return -1;
    }

    // supply the user data with encoded pubkey
    // ret = write_from_buffer(AMBER_USERDATA_DEVFILE, buf, b64_size);
    // if (ret == 0) {
    //     printf("Write to %s: \n%s\nb64 size: %ld\n", AMBER_USERDATA_DEVFILE, buf, b64_size);
    // } else {
    //     printf("Failed to write to %s: %d\n", AMBER_USERDATA_DEVFILE, ret);
    // }

    // read the amber token
    ret = read_to_buffer(AMBER_TOKEN_DEVFILE, buf, BUF_SZ);
    if (ret == 0) {
        printf("Read from %s: \n%s\n", AMBER_TOKEN_DEVFILE, buf);
    } else {
        printf("Failed to read from %s: %d\n", AMBER_TOKEN_DEVFILE, ret);
    }

    // read the status
    ret = read_to_buffer(AMBER_STATUS_DEVFILE, buf, BUF_SZ);
    if (ret == 0) {
        printf("Read from %s: \n%s\n", AMBER_STATUS_DEVFILE, buf);
    } else {
        printf("Failed to read from %s: %d\n", AMBER_STATUS_DEVFILE, ret);
    }

    // This part does only work with KBS
    // ret = read_to_buffer(AMBER_SECRET_DEVFILE, buf, BUF_SZ);
    // if (ret == 0) {
    //     printf("Read from %s: \n%s\n", AMBER_SECRET_DEVFILE, buf);
    // } else {
    //     printf("Failed to read from %s: %d\n", AMBER_SECRET_DEVFILE, ret);
    // }

    // ret = read_to_buffer(AMBER_STATUS_DEVFILE, buf, BUF_SZ);
    // if (ret == 0) {
    //     printf("Read from %s: \n%s\n", AMBER_STATUS_DEVFILE, buf);
    // } else {
    //     printf("Failed to read from %s: %d\n", AMBER_STATUS_DEVFILE, ret);
    // }

    return ret;
}
