/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

/*!
 * \file
 *
 * This file contains the implementation of secret provisioning library based on RA-TLS for
 * enclavized application. It contains functions to create a self-signed RA-TLS certificate
 * with an SGX quote embedded in it (using ra_tls_create_key_and_crt()), send it to one of
 * the verifier/secret provisioning servers, and receive secrets in response.
 *
 * This file is part of the secret-provisioning client-side library which is typically linked
 * into the SGX application that needs to receive secrets. This library is *not* thread-safe.
 */

#define STDC_WANT_LIB_EXT1 1
#define _XOPEN_SOURCE 700
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#include "ra_tls.h"
#include "secret_prov.h"
#include "util.h"

typedef struct _secret_prov_resources_t {
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt verifier_ca_chain;
    mbedtls_net_context verifier_fd;
    mbedtls_ssl_context ssl;
    mbedtls_pk_context my_ratls_key;
    mbedtls_x509_crt my_ratls_cert;
} secret_prov_resources_t;

static uint8_t* provisioned_secret = NULL;
static size_t provisioned_secret_size = 0;

int free_secret_prov_resources(secret_prov_resources_t* _res);

int secret_provision_get(uint8_t** out_secret, size_t* out_secret_size) {
    if (!out_secret || !out_secret_size)
        return -EINVAL;

    *out_secret      = provisioned_secret;
    *out_secret_size = provisioned_secret_size;
    return 0;
}

int free_secret_prov_resources(secret_prov_resources_t* _res) {
    if (!_res)
        return -EINVAL;

    secret_prov_resources_t* res = (secret_prov_resources_t*) _res;

    mbedtls_x509_crt_free(&res->my_ratls_cert);
    mbedtls_pk_free(&res->my_ratls_key);
    mbedtls_net_free(&res->verifier_fd);
    mbedtls_ssl_free(&res->ssl);
    mbedtls_ssl_config_free(&res->conf);
    mbedtls_x509_crt_free(&res->verifier_ca_chain);
    mbedtls_ctr_drbg_free(&res->ctr_drbg);
    mbedtls_entropy_free(&res->entropy);

    return 0;
}

void secret_provision_destroy(struct ra_tls_ctx* ctx) {
    /* free provisioned_secret */
    if (provisioned_secret) {
#ifdef __STDC_LIB_EXT1__
        memset_s(provisioned_secret, 0, provisioned_secret_size);
#else
        memset(provisioned_secret, 0, provisioned_secret_size);
#endif
        free(provisioned_secret);
        provisioned_secret = NULL;
    }

    provisioned_secret_size = 0;

    if (ctx) {
        if (ctx->attest_resources) {
            free_secret_prov_resources(ctx->attest_resources);

            free(ctx->attest_resources);
            ctx->attest_resources = 0;
        }
    }
}

int secret_provision_start(const char* in_servers, const char* in_ca_chain_path,
                           struct ra_tls_ctx* out_ctx) {
    int ret;

    char* servers       = NULL;
    char* ca_chain_path = NULL;

    char* connected_addr = NULL;
    char* connected_port = NULL;

    secret_prov_resources_t* res =
        (secret_prov_resources_t*)malloc(sizeof(secret_prov_resources_t));
    if (!res) {
        ret = -ENOMEM;
        goto out;
    }

    mbedtls_ctr_drbg_init(&res->ctr_drbg);
    mbedtls_entropy_init(&res->entropy);
    mbedtls_x509_crt_init(&res->verifier_ca_chain);

    mbedtls_pk_init(&res->my_ratls_key);
    mbedtls_x509_crt_init(&res->my_ratls_cert);

    mbedtls_net_init(&res->verifier_fd);
    mbedtls_ssl_config_init(&res->conf);
    mbedtls_ssl_init(&res->ssl);

    const char* pers = "secret-provisioning";
    ret = mbedtls_ctr_drbg_seed(&res->ctr_drbg, mbedtls_entropy_func, &res->entropy,
                                (const uint8_t*)pers, strlen(pers));
    if (ret < 0) {
        goto out;
    }

    if (!in_ca_chain_path) {
        in_ca_chain_path = getenv(SECRET_PROVISION_CA_CHAIN_PATH);
        if (!in_ca_chain_path)
            return -EINVAL;
    }

    ca_chain_path = strdup(in_ca_chain_path);
    if (!ca_chain_path) {
        ret = -ENOMEM;
        goto out;
    }

    if (!in_servers) {
        in_servers = getenv(SECRET_PROVISION_SERVERS);
        if (!in_servers)
            in_servers = DEFAULT_SERVERS;
    }

    servers = strdup(in_servers);
    if (!servers) {
        ret = -ENOMEM;
        goto out;
    }

    char* saveptr1;
    char* saveptr2;
    char* str1;
    for (str1 = servers; /*no condition*/; str1 = NULL) {
        ret = -ECONNREFUSED;
        char* token = strtok_r(str1, ",; ", &saveptr1);
        if (!token)
            break;

        connected_addr = strtok_r(token, ":", &saveptr2);
        if (!connected_addr)
            continue;

        connected_port = strtok_r(NULL, ":", &saveptr2);
        if (!connected_port)
            continue;

        ret = mbedtls_net_connect(&res->verifier_fd, connected_addr, connected_port,
                                  MBEDTLS_NET_PROTO_TCP);
        if (!ret)
            break;
    }

    if (ret < 0) {
        goto out;
    }

    ret = mbedtls_ssl_config_defaults(&res->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret < 0) {
        goto out;
    }

    ret = mbedtls_x509_crt_parse_file(&res->verifier_ca_chain, ca_chain_path);
    if (ret != 0) {
        goto out;
    }

    char crt_issuer[256];
    ret = mbedtls_x509_dn_gets(crt_issuer, sizeof(crt_issuer), &res->verifier_ca_chain.issuer);
    if (ret < 0) {
        goto out;
    }

    mbedtls_ssl_conf_authmode(&res->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&res->conf, &res->verifier_ca_chain, NULL);

    ret = ra_tls_create_key_and_crt(&res->my_ratls_key, &res->my_ratls_cert);
    if (ret < 0) {
        goto out;
    }

    mbedtls_ssl_conf_rng(&res->conf, mbedtls_ctr_drbg_random, &res->ctr_drbg);

    ret = mbedtls_ssl_conf_own_cert(&res->conf, &res->my_ratls_cert, &res->my_ratls_key);
    if (ret < 0) {
        goto out;
    }

    ret = mbedtls_ssl_setup(&res->ssl, &res->conf);
    if (ret < 0) {
        goto out;
    }

    ret = mbedtls_ssl_set_hostname(&res->ssl, connected_addr);
    if (ret < 0) {
        goto out;
    }

    mbedtls_ssl_set_bio(&res->ssl, &res->verifier_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    ret = -1;
    while (ret < 0) {
        ret = mbedtls_ssl_handshake(&res->ssl);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }
        if (ret < 0) {
            goto out;
        }
    }

    uint32_t flags = mbedtls_ssl_get_verify_result(&res->ssl);
    if (flags != 0) {
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        goto out;
    }

    struct ra_tls_ctx ctx = {.ssl = &res->ssl};
    uint8_t buf[128] = {0};
    size_t size;

    static_assert(sizeof(buf) >= sizeof(SECRET_PROVISION_REQUEST),
                  "buffer must be sufficiently large to hold SECRET_PROVISION_REQUEST");
    size = sprintf((char*)buf, SECRET_PROVISION_REQUEST);
    size += 1; /* include null byte */

    ret = secret_provision_write(&ctx, buf, size);
    if (ret < 0) {
        goto out;
    }

    /* remote verifier sends 32-bit integer over network; we need to ntoh it */
    uint32_t received_secret_size;
    static_assert(sizeof(buf) >= sizeof(SECRET_PROVISION_RESPONSE) + sizeof(received_secret_size),
                  "buffer must be sufficiently large to hold SECRET_PROVISION_RESPONSE + int32");

    memset(buf, 0, sizeof(buf));
    ret = secret_provision_read(&ctx, buf,
                                sizeof(SECRET_PROVISION_RESPONSE) + sizeof(received_secret_size));
    if (ret < 0) {
        goto out;
    }

    if (memcmp(buf, SECRET_PROVISION_RESPONSE, sizeof(SECRET_PROVISION_RESPONSE))) {
        ret = -EINVAL;
        goto out;
    }

    memcpy(&received_secret_size, buf + sizeof(SECRET_PROVISION_RESPONSE),
           sizeof(received_secret_size));

    received_secret_size = ntohl(received_secret_size);
    if (received_secret_size > INT_MAX) {
        ret = -EINVAL;
        goto out;
    }

    /* free previously one */
    if (provisioned_secret) {
        free(provisioned_secret);
        provisioned_secret = 0;
    }
    /* size may changed, allocate new memory */
    provisioned_secret = malloc(received_secret_size);
    if (!provisioned_secret) {
        ret = -ENOMEM;
        goto out;
    }
    /* set size after successfully allocated memory */
    provisioned_secret_size = received_secret_size;

    ret = secret_provision_read(&ctx, provisioned_secret, provisioned_secret_size);
    if (ret < 0) {
        goto out;
    }

    if (out_ctx) {
        out_ctx->ssl = ctx.ssl;
        out_ctx->attest_resources = res;
    } else {
        secret_provision_close(&ctx);
    }

    ret = 0;
out:
    if (ret < 0) {
        secret_provision_destroy(0);
    }

    if (ret < 0 || !out_ctx) {
        free_secret_prov_resources(res);
        free(res);
        res = 0;
    }

    free(servers);
    free(ca_chain_path);

    return ret;
}

static bool truthy(const char* s) {
    return !strcmp(s, "1") || !strcmp(s, "true") || !strcmp(s, "TRUE");
}

__attribute__((constructor)) static void secret_provision_constructor(void) {
    const char* constructor = getenv(SECRET_PROVISION_CONSTRUCTOR);
    if (constructor && truthy(constructor)) {
        /* user wants to provision secret before application runs */
        uint8_t* secret = NULL;
        size_t secret_size = 0;

        /* immediately unset envvar so that execve'd child processes do not land here (otherwise
         * secret provisioning would happen for each new child, but each child already got all the
         * secrets from the parent process during checkpoint-and-restore) */
        unsetenv(SECRET_PROVISION_CONSTRUCTOR);

        unsetenv(SECRET_PROVISION_SECRET_STRING);

        int ret = secret_provision_start(/*in_servers=*/NULL, /*in_ca_chain_path=*/NULL,
                                         /*out_ctx=*/NULL);
        if (ret < 0)
            return;

        ret = secret_provision_get(&secret, &secret_size);
        if (ret < 0 || !secret || !secret_size || secret_size > PATH_MAX ||
                secret[secret_size - 1] != '\0') {
            /* secret is not a null-terminated string, cannot do anything about such secret */
            return;
        }

        /* successfully retrieved the secret: is it a key for encrypted files? */
        const char* key_name = getenv(SECRET_PROVISION_SET_KEY);
        if (!key_name) {
            /* no key name specified - check old PF env var for compatibility */
            const char* pf_key = getenv(SECRET_PROVISION_SET_PF_KEY);
            if (pf_key && truthy(pf_key)) {
                INFO(SECRET_PROVISION_SET_PF_KEY " is deprecated, consider setting "
                     SECRET_PROVISION_SET_KEY "=default instead.\n");
                key_name = "default";
            }
        }

        if (key_name) {
            sgx_key_128bit_t keydata;
            if (parse_hex((char*)secret, keydata, sizeof(keydata), "provisioned secret") < 0)
                return;

            char path_buf[256];
            if (snprintf(path_buf, 256, "/dev/attestation/keys/%s", key_name) >= 256) {
                ERROR("Key name '%s' too long\n", key_name);
                return;
            }

            int fd = open(path_buf, O_WRONLY);
            if (fd < 0)
                return;

            size_t total_written = 0;
            while (total_written < sizeof(keydata)) {
                ssize_t written = write(fd, keydata + total_written, sizeof(keydata) - total_written);
                if (written > 0) {
                    total_written += written;
                } else if (written == 0) {
                    /* end of file */
                    break;
                } else if (errno == EAGAIN || errno == EINTR) {
                    continue;
                } else {
                    close(fd);
                    return;
                }
            }

            close(fd);  /* applies retrieved encryption key */
        }

        /* put the secret into an environment variable */
        setenv(SECRET_PROVISION_SECRET_STRING, (const char*)secret, /*overwrite=*/1);

        secret_provision_destroy(0);
    }
}
