/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

/*!
 * \file
 *
 * This file contains common utilities for secret provisioning library.
 */

#define _XOPEN_SOURCE 700
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>

#include "secret_prov.h"
#include "secret_prov_common.h"
#include "util.h"

int secret_provision_common_write(mbedtls_ssl_context* ssl, const uint8_t* buf, size_t size) {
    int ret;

    if (!ssl || size > INT_MAX)
        return -EINVAL;

    size_t written = 0;
    while (written < size) {
        ret = mbedtls_ssl_write(ssl, buf + written, size - written);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (ret < 0) {
            /* use well-known error code for a typical case when remote party closes connection */
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
                return -ECONNRESET;
            ERROR("Secret Provisioning failed during write with mbedTLS error %d\n", ret);
            return -EPERM;
        }
        written += (size_t)ret;
    }
    assert(written == size);
    return 0;
}

int secret_provision_common_read(mbedtls_ssl_context* ssl, uint8_t* buf, size_t size) {
    int ret;

    if (!ssl || size > INT_MAX)
        return -EINVAL;

    size_t read = 0;
    while (read < size) {
        ret = mbedtls_ssl_read(ssl, buf + read, size - read);
        if (!ret)
            return -ECONNRESET;
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;
        if (ret < 0) {
            /* use well-known error code for a typical case when remote party closes connection */
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
                return -ECONNRESET;
            ERROR("Secret Provisioning failed during read with mbedTLS error %d\n", ret);
            return -EPERM;
        }
        read += (size_t)ret;
    }
    assert(read == size);
    return 0;
}

int secret_provision_common_close(mbedtls_ssl_context* ssl) {
    if (!ssl)
        return 0;

    int ret;
    do {
        ret = mbedtls_ssl_close_notify(ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    if (ret < 0) {
        /* use well-known error code for a typical case when remote party closes connection */
        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
            return -ECONNRESET;
        ERROR("Secret Provisioning failed during connection close with mbedTLS error %d\n", ret);
        return -EPERM;
    }
    return 0;
}
