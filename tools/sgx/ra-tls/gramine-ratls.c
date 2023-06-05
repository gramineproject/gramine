/* SPDX-License-Identifier: LGPL-3.0-or-later
 * Copyright (c) 2023 Intel Corp.
 *                    Wojtek Porczyk <woju@invisiblethingslab.com>
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>

const size_t buf_size = 4096;

/* ratls does not install its headers */
int ra_tls_create_key_and_crt_der(
    uint8_t** der_key,
    size_t* der_key_size,
    uint8_t** der_crt,
    size_t* der_crt_size);

int write_buf(const char *pathname, uint8_t *buf, size_t buf_size);
int write_buf(const char *pathname, uint8_t *buf, size_t buf_size) {
    int fd = open(pathname, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
    if (fd < 0) {
        perror("open");
        return -1;
    }

    ssize_t ret = write(fd, buf, buf_size);
    if (ret < 0) {
        perror("write");
        close(fd);
        return -1;
    } else if ((size_t)ret != buf_size) {
        close(fd);
        return -2;
    }

    close(fd);
    return 0;
}

int main(int argc, char* argv[]) {
    uint8_t* key_der = NULL;
    uint8_t* crt_der = NULL;
    size_t key_der_size;
    size_t crt_der_size;
    int ret = 0;

    if (argc < 3) {
        fprintf(stderr, "usage: %s CERTPATH KEYPATH [COMMAND ...]\n", argv[0]);
        return 2;
    }

    ret = ra_tls_create_key_and_crt_der(
        &key_der, &key_der_size, &crt_der, &crt_der_size);
    if (ret != 0) {
        fprintf(stderr, "ra_tls_create_key_and_crt_der returned %d\n", ret);
        goto err;
    }

    ret = write_buf(argv[1], crt_der, crt_der_size);
    if (ret < 0)
        goto err;

    ret = write_buf(argv[2], key_der, key_der_size);
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
