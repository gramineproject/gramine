/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

/*!
 * \file
 *
 * This file contains the implementation of secret provisioning library based on RA-TLS for
 * verifier/secret provisioning server. It contains functions to receive a self-signed RA-TLS
 * certificate with an SGX quote embedded in it from the enclavized application, verify it
 * using ra_tls_verify_callback(), and send (provision) the secret to the enclavized application.
 *
 * This file is part of the secret-provisioning verifier-side library which is typically linked
 * into the secret provisioning server. This library is *not* thread-safe.
 */

#define _XOPEN_SOURCE 700
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/build_info.h"

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#include "ra_tls.h"
#include "ra_tls_common.h"
#include "secret_prov.h"
#include "secret_prov_common.h"
#include "util.h"

struct ra_tls_ctx {
    mbedtls_ssl_context* ssl;
};

struct thread_info {
    mbedtls_net_context client_fd;
    mbedtls_ssl_config* conf;
    uint8_t* secret;
    size_t secret_size;
    secret_provision_cb_t f_cb;
};

/* SSL/TLS + RA-TLS handshake is not thread-safe, use coarse-grained lock */
static pthread_mutex_t g_handshake_lock;

int secret_provision_write(struct ra_tls_ctx* ctx, const uint8_t* buf, size_t size) {
    if (!ctx || (size && !buf))
        return -EINVAL;
    return secret_provision_common_write(ctx->ssl, buf, size);
}

int secret_provision_read(struct ra_tls_ctx* ctx, uint8_t* buf, size_t size) {
    if (!ctx || (size && !buf))
        return -EINVAL;
    return secret_provision_common_read(ctx->ssl, buf, size);
}

int secret_provision_close(struct ra_tls_ctx* ctx) {
    if (!ctx)
        return -EINVAL;
    /* no need to free the ctx resources, this will be done in client_connection() */
    return secret_provision_common_close(ctx->ssl);
}

static void* client_connection(void* data) {
    int ret;
    struct thread_info* ti = (struct thread_info*)data;

    mbedtls_ssl_context ssl;
    mbedtls_ssl_init(&ssl);

    ret = mbedtls_ssl_setup(&ssl, ti->conf);
    if (ret < 0) {
        ERROR("Secret Provisioning failed during mbedtls_ssl_setup with error %d\n", ret);
        goto out;
    }

    mbedtls_ssl_set_bio(&ssl, &ti->client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    do {
        /* FIXME: this coarse-grained locking is less than optimal; need to switch to thread-safe
         *        mbedTLS configuration and thread-safe RA-TLS in the future */
        pthread_mutex_lock(&g_handshake_lock);
        ret = mbedtls_ssl_handshake(&ssl);
        pthread_mutex_unlock(&g_handshake_lock);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    if (ret < 0) {
        ERROR("Secret Provisioning failed during mbedtls_ssl_handshake with error %d\n", ret);
        goto out;
    }

    uint32_t flags = mbedtls_ssl_get_verify_result(&ssl);
    if (flags != 0) {
        ERROR("Secret Provisioning failed during mbedtls_ssl_get_verify_result (flags = %u)\n",
              flags);
        goto out;
    }

    uint8_t buf[128] = {0};
    static_assert(sizeof(buf) >= sizeof(SECRET_PROVISION_REQUEST),
                  "buffer must be sufficiently large to hold SECRET_PROVISION_REQUEST");

    ret = secret_provision_common_read(&ssl, buf, sizeof(SECRET_PROVISION_REQUEST));
    if (ret < 0) {
        goto out;
    }

    if (memcmp(buf, SECRET_PROVISION_REQUEST, sizeof(SECRET_PROVISION_REQUEST))) {
        ERROR("Secret Provisioning read a request that doesn't match the expected "
              SECRET_PROVISION_REQUEST "\n");
        goto out;
    }

    /* remote attester receives 32-bit integer over network; we need to hton it */
    if (ti->secret_size > INT_MAX) {
        goto out;
    }

    uint32_t send_secret_size = htonl((uint32_t)ti->secret_size);
    static_assert(sizeof(buf) >= sizeof(SECRET_PROVISION_RESPONSE) + sizeof(send_secret_size),
                  "buffer must be sufficiently large to hold SECRET_PROVISION_RESPONSE + int32");

    memset(buf, 0, sizeof(buf));
    memcpy(buf, SECRET_PROVISION_RESPONSE, sizeof(SECRET_PROVISION_RESPONSE));
    memcpy(buf + sizeof(SECRET_PROVISION_RESPONSE), &send_secret_size, sizeof(send_secret_size));

    ret = secret_provision_common_write(&ssl, buf, sizeof(SECRET_PROVISION_RESPONSE)
                                                   + sizeof(send_secret_size));
    if (ret < 0) {
        goto out;
    }

    ret = secret_provision_common_write(&ssl, ti->secret, ti->secret_size);
    if (ret < 0) {
        goto out;
    }

    if (ti->f_cb) {
        struct ra_tls_ctx ctx = { .ssl = &ssl };
        ti->f_cb(&ctx);
    }
    secret_provision_common_close(&ssl);

out:
    mbedtls_ssl_free(&ssl);
    mbedtls_net_free(&ti->client_fd);
    free(ti);
    return NULL;
}

int secret_provision_start_server(uint8_t* secret, size_t secret_size, const char* port,
                                  const char* cert_path, const char* key_path,
                                  verify_measurements_cb_t m_cb, secret_provision_cb_t f_cb) {
    int ret;

    if (!secret || !secret_size || !cert_path || !key_path)
        return -EINVAL;

    ret = pthread_mutex_init(&g_handshake_lock, NULL);
    if (ret < 0)
        return ret;

    mbedtls_ssl_config conf;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_pk_context srvkey;
    mbedtls_x509_crt srvcert;
    mbedtls_net_context client_fd;
    mbedtls_net_context listen_fd;

    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_pk_init(&srvkey);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_net_init(&client_fd);
    mbedtls_net_init(&listen_fd);

    const char* pers = "secret-provisioning-server";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const uint8_t*)pers, strlen(pers));
    if (ret < 0) {
        ERROR("Secret Provisioning failed during mbedtls_ctr_drbg_seed with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    ret = mbedtls_x509_crt_parse_file(&srvcert, cert_path);
    if (ret != 0) {
        ERROR("Secret Provisioning failed during mbedtls_x509_crt_parse_file with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    char crt_issuer[256];
    ret = mbedtls_x509_dn_gets(crt_issuer, sizeof(crt_issuer), &srvcert.issuer);
    if (ret < 0) {
        ERROR("Secret Provisioning failed during mbedtls_x509_dn_gets with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    ret = mbedtls_pk_parse_keyfile(&srvkey, key_path, /*password=*/NULL, mbedtls_ctr_drbg_random,
                                   &ctr_drbg);
    if (ret < 0) {
        ERROR("Secret Provisioning failed during mbedtls_pk_parse_keyfile with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    ret = mbedtls_net_bind(&listen_fd, NULL, port ?: "4433", MBEDTLS_NET_PROTO_TCP);
    if (ret < 0) {
        ERROR("Secret Provisioning failed during mbedtls_net_bind with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret < 0) {
        ERROR("Secret Provisioning failed during mbedtls_ssl_config_defaults with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

    /* the below CA chain is a dummy (RA-TLS verify callback ignores it) but required by mbedTLS */
    mbedtls_ssl_conf_ca_chain(&conf, &srvcert, NULL);

    ra_tls_set_measurement_callback(m_cb);
    mbedtls_ssl_conf_verify(&conf, ra_tls_verify_callback, NULL);

    ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &srvkey);
    if (ret < 0) {
        ERROR("Secret Provisioning failed during mbedtls_ssl_conf_own_cert with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    /* wait for new clients */
    while (true) {
        ret = mbedtls_net_accept(&listen_fd, &client_fd, NULL, 0, NULL);
        if (ret < 0) {
            mbedtls_net_free(&client_fd);
            continue;
        }

        struct thread_info* ti = calloc(1, sizeof(*ti));
        if (!ti) {
            mbedtls_net_free(&client_fd);
            continue;
        }

        /* client_fd is reused for multiple threads, so pass ownership of its copy to new thread */
        memcpy(&ti->client_fd, &client_fd, sizeof(client_fd));
        ti->conf        = &conf;
        ti->secret      = secret;
        ti->secret_size = secret_size;
        ti->f_cb        = f_cb;

        pthread_attr_t tattr;
        ret = pthread_attr_init(&tattr);
        if (ret < 0) {
            free(ti);
            mbedtls_net_free(&client_fd);
            continue;
        }

        ret = pthread_attr_setdetachstate(&tattr, PTHREAD_CREATE_DETACHED);
        if (ret < 0) {
            free(ti);
            pthread_attr_destroy(&tattr);
            mbedtls_net_free(&client_fd);
            continue;
        }

        pthread_t tid;
        ret = pthread_create(&tid, &tattr, client_connection, ti);
        if (ret < 0) {
            free(ti);
            mbedtls_net_free(&client_fd);
        }

        pthread_attr_destroy(&tattr);
    }

    ret = 0;
out:
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&srvkey);
    mbedtls_net_free(&listen_fd);
    mbedtls_net_free(&client_fd);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    pthread_mutex_destroy(&g_handshake_lock);
    return ret;
}
