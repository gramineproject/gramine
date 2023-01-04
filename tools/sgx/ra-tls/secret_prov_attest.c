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
#include <assert.h>
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
#include "ra_tls_common.h"
#include "secret_prov.h"
#include "secret_prov_common.h"
#include "util.h"

struct ra_tls_ctx {
    mbedtls_ssl_context* ssl;
    mbedtls_net_context* net;
    mbedtls_ssl_config* conf;
    uint8_t* secret;
    size_t   secret_size;
};

static void erase_secret(uint8_t* secret, size_t secret_size) {
#ifdef __STDC_LIB_EXT1__
        memset_s(secret, 0, secret_size);
#else
        memset(secret, 0, secret_size);
#endif
}

int secret_provision_get(struct ra_tls_ctx* ctx, uint8_t** out_secret, size_t* out_secret_size) {
    if (!ctx || !out_secret || !out_secret_size)
        return -EINVAL;

    uint8_t* secret_copy = malloc(ctx->secret_size);
    if (!secret_copy)
        return -ENOMEM;

    memcpy(secret_copy, ctx->secret, ctx->secret_size);
    *out_secret      = secret_copy;
    *out_secret_size = ctx->secret_size;
    return 0;
}

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

    if (ctx->secret && ctx->secret_size) {
        erase_secret(ctx->secret, ctx->secret_size);
    }

    int ret = secret_provision_common_close(ctx->ssl);

    mbedtls_ssl_free(ctx->ssl);
    mbedtls_ssl_config_free(ctx->conf);
    mbedtls_net_free(ctx->net);
    free(ctx->ssl);
    free(ctx->conf);
    free(ctx->net);

    free(ctx->secret);
    free(ctx);
    return ret;
}

int secret_provision_start(const char* in_servers, const char* in_ca_chain_path,
                           struct ra_tls_ctx** out_ctx) {
    int ret;

    char* servers       = NULL;
    char* ca_chain_path = NULL;

    char* connected_addr = NULL;
    char* connected_port = NULL;

    uint8_t* secret = NULL;

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_x509_crt verifier_ca_chain;
    mbedtls_pk_context my_ratls_key;
    mbedtls_x509_crt my_ratls_cert;

    if (!out_ctx)
        return -EINVAL;

    mbedtls_net_context* net  = malloc(sizeof(*net));
    mbedtls_ssl_config*  conf = malloc(sizeof(*conf));
    mbedtls_ssl_context* ssl  = malloc(sizeof(*ssl));
    struct ra_tls_ctx*   ctx  = malloc(sizeof(*ctx));

    if (!net || !conf || !ssl || !ctx) {
        free(net);
        free(conf);
        free(ssl);
        free(ctx);
        return -ENOMEM;
    }

    ctx->ssl         = ssl;
    ctx->conf        = conf;
    ctx->net         = net;
    ctx->secret      = NULL;
    ctx->secret_size = 0;

    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509_crt_init(&verifier_ca_chain);
    mbedtls_pk_init(&my_ratls_key);
    mbedtls_x509_crt_init(&my_ratls_cert);

    mbedtls_net_init(net);
    mbedtls_ssl_config_init(conf);
    mbedtls_ssl_init(ssl);

    const char* pers = "secret-provisioning";
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                (const uint8_t*)pers, strlen(pers));
    if (ret < 0) {
        ERROR("Secret Provisioning failed during mbedtls_ctr_drbg_seed with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    if (!in_ca_chain_path) {
        in_ca_chain_path = getenv(SECRET_PROVISION_CA_CHAIN_PATH);
        if (!in_ca_chain_path) {
            ERROR("Secret Provisioning could not find envvar " SECRET_PROVISION_CA_CHAIN_PATH "\n");
            ret = -EINVAL;
            goto out;
        }
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

    char* saveptr1 = NULL;
    char* saveptr2 = NULL;
    char* str1;
    for (str1 = servers; /*no condition*/; str1 = NULL) {
        ret = MBEDTLS_ERR_NET_CONNECT_FAILED;
        char* token = strtok_r(str1, ",; ", &saveptr1);
        if (!token)
            break;

        connected_addr = strtok_r(token, ":", &saveptr2);
        if (!connected_addr)
            continue;

        connected_port = strtok_r(NULL, ":", &saveptr2);
        if (!connected_port)
            continue;

        ret = mbedtls_net_connect(net, connected_addr, connected_port, MBEDTLS_NET_PROTO_TCP);
        if (!ret)
            break;
    }

    if (ret < 0) {
        ERROR("Secret Provisioning could not connect to any of the servers specified in "
              SECRET_PROVISION_SERVERS "; last mbedTLS error was %d\n", ret);
        goto out;
    }

    ret = mbedtls_ssl_config_defaults(conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret < 0) {
        ERROR("Secret Provisioning failed during mbedtls_ssl_config_defaults with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    ret = mbedtls_x509_crt_parse_file(&verifier_ca_chain, ca_chain_path);
    if (ret != 0) {
        ERROR("Secret Provisioning failed during mbedtls_x509_crt_parse_file with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    char crt_issuer[256];
    ret = mbedtls_x509_dn_gets(crt_issuer, sizeof(crt_issuer), &verifier_ca_chain.issuer);
    if (ret < 0) {
        ERROR("Secret Provisioning failed during mbedtls_x509_dn_gets with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(conf, &verifier_ca_chain, NULL);

    ret = ra_tls_create_key_and_crt(&my_ratls_key, &my_ratls_cert);
    if (ret < 0) {
        ERROR("Secret Provisioning failed during ra_tls_create_key_and_crt with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    ret = mbedtls_ssl_conf_own_cert(conf, &my_ratls_cert, &my_ratls_key);
    if (ret < 0) {
        ERROR("Secret Provisioning failed during mbedtls_ssl_conf_own_cert with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    ret = mbedtls_ssl_setup(ssl, conf);
    if (ret < 0) {
        ERROR("Secret Provisioning failed during mbedtls_ssl_setup with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    ret = mbedtls_ssl_set_hostname(ssl, connected_addr);
    if (ret < 0) {
        ERROR("Secret Provisioning failed during mbedtls_ssl_set_hostname with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    mbedtls_ssl_set_bio(ssl, net, mbedtls_net_send, mbedtls_net_recv, NULL);

    do {
        ret = mbedtls_ssl_handshake(ssl);
    } while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
    if (ret < 0) {
        ERROR("Secret Provisioning failed during mbedtls_ssl_handshake with error %d\n", ret);
        ret = -EPERM;
        goto out;
    }

    uint32_t flags = mbedtls_ssl_get_verify_result(ssl);
    if (flags != 0) {
        ERROR("Secret Provisioning failed during mbedtls_ssl_get_verify_result (flags = %u)\n",
              flags);
        ret = -EPERM;
        goto out;
    }

    uint8_t buf[128] = {0};
    size_t size;

    static_assert(sizeof(buf) >= sizeof(SECRET_PROVISION_REQUEST),
                  "buffer must be sufficiently large to hold SECRET_PROVISION_REQUEST");
    size = sprintf((char*)buf, SECRET_PROVISION_REQUEST);
    size += 1; /* include null byte */

    ret = secret_provision_common_write(ssl, buf, size);
    if (ret < 0) {
        goto out;
    }

    /* remote verifier sends 32-bit integer over network; we need to ntoh it */
    uint32_t secret_size;
    static_assert(sizeof(buf) >= sizeof(SECRET_PROVISION_RESPONSE) + sizeof(secret_size),
                  "buffer must be sufficiently large to hold SECRET_PROVISION_RESPONSE + int32");

    memset(buf, 0, sizeof(buf));
    ret = secret_provision_common_read(ssl, buf,
                                       sizeof(SECRET_PROVISION_RESPONSE) + sizeof(secret_size));
    if (ret < 0) {
        goto out;
    }

    if (memcmp(buf, SECRET_PROVISION_RESPONSE, sizeof(SECRET_PROVISION_RESPONSE))) {
        ERROR("Secret Provisioning read a response that doesn't match the expected "
              SECRET_PROVISION_RESPONSE "\n");
        ret = -EINVAL;
        goto out;
    }

    memcpy(&secret_size, buf + sizeof(SECRET_PROVISION_RESPONSE), sizeof(secret_size));

    secret_size = ntohl(secret_size);
    if (secret_size > INT_MAX) {
        ret = -EINVAL;
        goto out;
    }

    secret = malloc(secret_size);
    if (!secret) {
        ret = -ENOMEM;
        goto out;
    }

    ret = secret_provision_common_read(ssl, secret, secret_size);
    if (ret < 0) {
        goto out;
    }

    ctx->secret      = secret;
    ctx->secret_size = secret_size;
    *out_ctx = ctx;
    ret = 0;
out:
    if (ret < 0) {
        free(secret);
        int close_ret = secret_provision_close(ctx);
        if (close_ret < 0)
            INFO("WARNING: Closing the secret-prov context failed with error %d.\n", close_ret);
    }

    mbedtls_x509_crt_free(&my_ratls_cert);
    mbedtls_pk_free(&my_ratls_key);
    mbedtls_x509_crt_free(&verifier_ca_chain);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);

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

        struct ra_tls_ctx* ctx;
        int ret = secret_provision_start(/*in_servers=*/NULL, /*in_ca_chain_path=*/NULL,
                                         &ctx);
        if (ret < 0) {
            ERROR("Secret provisioning failed, terminating the whole process\n");
            exit(1);
        }

        ret = secret_provision_get(ctx, &secret, &secret_size);
        if (ret < 0 || !secret || !secret_size) {
            ERROR("Secret provisioning failed - no secret/empty secret received\n");
            exit(1);
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
            if (secret_size != 16) {
                ERROR("Provisioned secret is not 16 bytes long, cannot use it as encrypted files "
                      "key.\n");
                exit(1);
            }

            char path_buf[256];
            ret = snprintf(path_buf, sizeof(path_buf), "/dev/attestation/keys/%s", key_name);
            if (ret < 0 || (size_t)ret >= sizeof(path_buf)) {
                ERROR("Provisioned key name '%s' is too long\n", key_name);
                exit(1);
            }

            int fd = open(path_buf, O_WRONLY);
            if (fd < 0) {
                ERROR("Secret provisioning cannot open '%s'\n", path_buf);
                exit(1);
            }

            size_t total_written = 0;
            while (total_written < secret_size) {
                ssize_t written = write(fd, secret + total_written, secret_size - total_written);
                if (written > 0) {
                    total_written += written;
                } else if (written == 0) {
                    /* end of file */
                    break;
                } else if (errno == EAGAIN || errno == EINTR) {
                    continue;
                } else {
                    close(fd);
                    ERROR("Secret provisioning cannot write to '%s'\n", path_buf);
                    exit(1);
                }
            }

            close(fd);  /* applies retrieved encryption key */
        } else {
            if (secret[secret_size - 1] != '\0' || secret_size > PATH_MAX) {
                ERROR("Secret is not a null-terminated string or is too long, cannot do anything "
                      "about such secret\n");
                exit(1);
            }
            /* put the secret into an environment variable */
            setenv(SECRET_PROVISION_SECRET_STRING, (const char*)secret, /*overwrite=*/1);
        }

        secret_provision_close(ctx);
        erase_secret(secret, secret_size);
        free(secret);
    }
}
