/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

/*!
 * \file
 *
 * This file contains the implementation of server-side attestation for TLS libraries. It contains
 * functions to create a self-signed RA-TLS certificate with an SGX quote embedded in it. It is
 * agnostic to the format of the SGX quote, formerly worked with both
 * EPID-based (quote v2) and ECDSA-based (quote v3 or DCAP) SGX quotes.
 *
 * This file is part of the RA-TLS attestation library which is typically linked into server
 * applications. This library is *not* thread-safe.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cbor.h>

#include <mbedtls/build_info.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#define JSMN_STATIC
#include "third_party/jsmn/jsmn.h"

#include "ra_tls.h"
#include "ra_tls_common.h"

/* Algorithm configuration structure */
typedef struct {
    const char* name;
    mbedtls_pk_type_t pk_type;
    union {
        mbedtls_ecp_group_id ecp_group_id;
        unsigned int rsa_key_size;
        int ed25519_marker;  /* For ED25519, just a marker */
    } params;
} algorithm_config_t;

/* Supported algorithms list */
static const algorithm_config_t g_supported_algorithms[] = {
    /* EC curves */
    { "secp256r1", MBEDTLS_PK_ECKEY, { .ecp_group_id = MBEDTLS_ECP_DP_SECP256R1 } },
    { "secp384r1", MBEDTLS_PK_ECKEY, { .ecp_group_id = MBEDTLS_ECP_DP_SECP384R1 } },
    { "secp521r1", MBEDTLS_PK_ECKEY, { .ecp_group_id = MBEDTLS_ECP_DP_SECP521R1 } },
    { "secp256k1", MBEDTLS_PK_ECKEY, { .ecp_group_id = MBEDTLS_ECP_DP_SECP256K1 } },
    { "secp192r1", MBEDTLS_PK_ECKEY, { .ecp_group_id = MBEDTLS_ECP_DP_SECP192R1 } },
    { "secp192k1", MBEDTLS_PK_ECKEY, { .ecp_group_id = MBEDTLS_ECP_DP_SECP192K1 } },
    { "bp256r1",   MBEDTLS_PK_ECKEY, { .ecp_group_id = MBEDTLS_ECP_DP_BP256R1 } },
    { "bp384r1",   MBEDTLS_PK_ECKEY, { .ecp_group_id = MBEDTLS_ECP_DP_BP384R1 } },
    { "bp512r1",   MBEDTLS_PK_ECKEY, { .ecp_group_id = MBEDTLS_ECP_DP_BP512R1 } },
    /* RSA algorithms */
    { "rsa2048", MBEDTLS_PK_RSA, { .rsa_key_size = 2048 } },
    { "rsa3072", MBEDTLS_PK_RSA, { .rsa_key_size = 3072 } },
    { "rsa4096", MBEDTLS_PK_RSA, { .rsa_key_size = 4096 } },
    /* ED25519 (Edwards curve) */
    { "ed25519", MBEDTLS_PK_OPAQUE, { .ed25519_marker = 1 } },
};

#define DEFAULT_ALGORITHM_NAME "secp384r1"
#define NUM_SUPPORTED_ALGORITHMS (sizeof(g_supported_algorithms) / sizeof(g_supported_algorithms[0]))

#define CERT_SUBJECT_NAME_VALUES  "CN=RATLS,O=GramineDevelopers,C=US"
#define CERT_TIMESTAMP_NOT_BEFORE_DEFAULT "20010101000000"
#define CERT_TIMESTAMP_NOT_AFTER_DEFAULT  "20301231235959"

static ssize_t rw_file(const char* path, uint8_t* buf, size_t len, bool do_write) {
    ssize_t bytes = 0;
    ssize_t ret = 0;

    int fd = do_write ? open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644) : open(path, O_RDONLY);
    if (fd < 0)
        return fd;

    while ((ssize_t)len > bytes) {
        if (do_write)
            ret = write(fd, buf + bytes, len - bytes);
        else
            ret = read(fd, buf + bytes, len - bytes);

        if (ret > 0) {
            bytes += ret;
        } else if (ret == 0) {
            /* end of file */
            break;
        } else {
            if (ret < 0 && (errno == EAGAIN || errno == EINTR))
                continue;
            break;
        }
    }

    close(fd);
    return ret < 0 ? ret : bytes;
}

static ssize_t read_file(const char* path, uint8_t* buf, size_t len) {
    return rw_file(path, buf, len, /*do_write=*/false);
}

static ssize_t write_file(const char* path, uint8_t* buf, size_t len) {
    return rw_file(path, buf, len, /*do_write=*/true);
}

/* Helper function to log mbedtls errors with human-readable strings */
static void log_mbedtls_error(const char* context, int ret) {
    char error_buf[256];
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    printf("RA-TLS: %s failed: ret=%d (%s)\n", context, ret, error_buf);
}

/* Helper function to get MD algorithm name */
static const char* get_md_name(mbedtls_md_type_t md_type) {
    switch (md_type) {
        case MBEDTLS_MD_SHA224: return "SHA224";
        case MBEDTLS_MD_SHA256: return "SHA256";
        case MBEDTLS_MD_SHA384: return "SHA384";
        case MBEDTLS_MD_SHA512: return "SHA512";
        default: return "UNKNOWN";
    }
}

/* Helper function to write certificate in PEM format */
static int write_cert_pem(const char* path, const uint8_t* der_data, size_t der_len) {
    int ret;
    size_t pem_len = 0;
    
    /* Calculate required PEM buffer size */
    ret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n",
                                   "-----END CERTIFICATE-----\n",
                                   der_data, der_len, NULL, 0, &pem_len);
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        printf("RA-TLS: Failed to calculate PEM buffer size: %d\n", ret);
        return ret;
    }
    
    /* Allocate PEM buffer */
    uint8_t* pem_buf = malloc(pem_len);
    if (!pem_buf) {
        printf("RA-TLS: Failed to allocate PEM buffer\n");
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }
    
    /* Convert DER to PEM */
    ret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n",
                                   "-----END CERTIFICATE-----\n",
                                   der_data, der_len, pem_buf, pem_len, &pem_len);
    if (ret < 0) {
        printf("RA-TLS: Failed to convert certificate to PEM: %d\n", ret);
        free(pem_buf);
        return ret;
    }
    
    /* Write PEM to file */
    ssize_t written = write_file(path, pem_buf, pem_len - 1);  /* -1 to exclude null terminator */
    free(pem_buf);
    
    if (written < 0) {
        printf("RA-TLS: Failed to write PEM file: %s (errno=%d: %s)\n", path, errno, strerror(errno));
        return -1;
    }
    
    return 0;
}

/* Helper function to write private key in PEM format */
static int write_key_pem(const char* path, mbedtls_pk_context* key) {
    int ret;
    size_t output_buf_size = 16384;  /* Large enough for any private key */
    uint8_t* output_buf = malloc(output_buf_size);
    if (!output_buf) {
        printf("RA-TLS: Failed to allocate buffer for key PEM conversion\n");
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }
    
    /* Write key to PEM format */
    ret = mbedtls_pk_write_key_pem(key, output_buf, output_buf_size);
    if (ret < 0) {
        printf("RA-TLS: Failed to convert key to PEM: %d\n", ret);
        free(output_buf);
        return ret;
    }
    
    /* Write PEM to file */
    size_t pem_len = strlen((char*)output_buf);
    ssize_t written = write_file(path, output_buf, pem_len);
    free(output_buf);
    
    if (written < 0) {
        printf("RA-TLS: Failed to write key PEM file: %s (errno=%d: %s)\n", path, errno, strerror(errno));
        return -1;
    }
    
    return 0;
}

/* Helper function to extract directory from file path */
static char* get_directory_from_path(const char* file_path) {
    if (!file_path) {
        return NULL;
    }
    
    const char* last_slash = strrchr(file_path, '/');
    if (!last_slash) {
        /* No directory separator, return current directory */
        return strdup(".");
    }
    
    if (last_slash == file_path) {
        /* Root directory */
        return strdup("/");
    }
    
    /* Extract directory part */
    size_t dir_len = last_slash - file_path;
    char* dir = malloc(dir_len + 1);
    if (!dir) {
        return NULL;
    }
    
    memcpy(dir, file_path, dir_len);
    dir[dir_len] = '\0';
    return dir;
}

/* Helper function to extract basename from file path */
static const char* get_basename_from_path(const char* file_path) {
    if (!file_path) {
        return NULL;
    }
    
    const char* last_slash = strrchr(file_path, '/');
    if (!last_slash) {
        /* No directory separator, return the whole path */
        return file_path;
    }
    
    /* Return pointer to character after last slash */
    return last_slash + 1;
}

/* Helper function to get PK type name */
static const char* get_pk_type_name(mbedtls_pk_type_t pk_type) {
    switch (pk_type) {
        case MBEDTLS_PK_ECKEY: return "EC";
        case MBEDTLS_PK_RSA: return "RSA";
        case MBEDTLS_PK_OPAQUE: return "OPAQUE";
        default: return "UNKNOWN";
    }
}

int ra_tls_get_supported_algorithms(const char*** algorithms, size_t* algorithms_count) {
    if (!algorithms || !algorithms_count) {
        return -EINVAL;
    }

    static const char* algorithm_names[NUM_SUPPORTED_ALGORITHMS];
    for (size_t i = 0; i < NUM_SUPPORTED_ALGORITHMS; i++) {
        algorithm_names[i] = g_supported_algorithms[i].name;
    }

    *algorithms = algorithm_names;
    *algorithms_count = NUM_SUPPORTED_ALGORITHMS;
    return 0;
}

/* Certificate configuration from JSON */
typedef struct {
    char* key_file;
    char* key_format;  /* "pem" or "der" */
    char* algorithm;
    char* subject;
    char* not_before;
    char* not_after;
    char* signature_md;
    bool is_ca;  /* whether to mark the generated certificate as a CA certificate */
    /* CA certificate fields (for using existing CA to sign) */
    char* ca_key_file;
    char* ca_key_format;  /* "pem" or "der" */
    char* ca_algorithm;  /* algorithm for CA key/cert generation */
    char* ca_cert_file;  /* path to existing CA certificate file */
    char* ca_cert_format;  /* "pem" or "der" */
    char* ca_subject;
    char* ca_not_before;
    char* ca_not_after;
} cert_config_t;

/* Helper function to find JSON string value by key */
static int json_get_string(const char* json, jsmntok_t* tokens, int num_tokens,
                           const char* key, char** out_value) {
    for (int i = 0; i < num_tokens - 1; i++) {
        if (tokens[i].type == JSMN_STRING) {
            int key_len = tokens[i].end - tokens[i].start;
            if (strncmp(json + tokens[i].start, key, key_len) == 0 &&
                strlen(key) == (size_t)key_len) {
                /* Found the key, next token is the value */
                i++;
                if (tokens[i].type == JSMN_STRING) {
                    int val_len = tokens[i].end - tokens[i].start;
                    *out_value = strndup(json + tokens[i].start, val_len);
                    return *out_value ? 0 : -ENOMEM;
                }
            }
        }
    }
    return -ENOENT;
}

/* Helper function to find JSON boolean value by key */
static int json_get_bool(const char* json, jsmntok_t* tokens, int num_tokens,
                         const char* key, bool* out_value) {
    for (int i = 0; i < num_tokens - 1; i++) {
        if (tokens[i].type == JSMN_STRING) {
            int key_len = tokens[i].end - tokens[i].start;
            if (strncmp(json + tokens[i].start, key, key_len) == 0 &&
                strlen(key) == (size_t)key_len) {
                /* Found the key, next token is the value */
                i++;
                if (tokens[i].type == JSMN_PRIMITIVE) {
                    int val_len = tokens[i].end - tokens[i].start;
                    if (val_len == 4 && strncmp(json + tokens[i].start, "true", 4) == 0) {
                        *out_value = true;
                        return 0;
                    } else if (val_len == 5 && strncmp(json + tokens[i].start, "false", 5) == 0) {
                        *out_value = false;
                        return 0;
                    }
                }
            }
        }
    }
    return -ENOENT;
}

/* Parse base64-encoded JSON configuration */
static int parse_json_config(const char* b64_json, cert_config_t* config) {
    int ret;
    unsigned char* json_buf = NULL;
    size_t json_len = 0;
    jsmn_parser parser;
    jsmntok_t tokens[128];
    int num_tokens;

    memset(config, 0, sizeof(*config));

    /* Decode base64 */
    ret = mbedtls_base64_decode(NULL, 0, &json_len, (const unsigned char*)b64_json,
                                strlen(b64_json));
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
        return -EINVAL;
    }

    json_buf = malloc(json_len + 1);
    if (!json_buf) {
        return -ENOMEM;
    }

    ret = mbedtls_base64_decode(json_buf, json_len, &json_len, (const unsigned char*)b64_json,
                                strlen(b64_json));
    if (ret < 0) {
        free(json_buf);
        return -EINVAL;
    }
    json_buf[json_len] = '\0';

    /* Parse JSON */
    jsmn_init(&parser);
    num_tokens = jsmn_parse(&parser, (const char*)json_buf, json_len, tokens,
                           sizeof(tokens) / sizeof(tokens[0]));
    if (num_tokens < 0) {
        free(json_buf);
        return -EINVAL;
    }

    /* Extract fields (all optional) */
    json_get_string((const char*)json_buf, tokens, num_tokens, "key_file", &config->key_file);
    json_get_string((const char*)json_buf, tokens, num_tokens, "key_format", &config->key_format);
    json_get_string((const char*)json_buf, tokens, num_tokens, "algorithm", &config->algorithm);
    json_get_string((const char*)json_buf, tokens, num_tokens, "subject", &config->subject);
    json_get_string((const char*)json_buf, tokens, num_tokens, "not_before", &config->not_before);
    json_get_string((const char*)json_buf, tokens, num_tokens, "not_after", &config->not_after);
    json_get_string((const char*)json_buf, tokens, num_tokens, "signature_md", &config->signature_md);
    json_get_bool((const char*)json_buf, tokens, num_tokens, "is_ca", &config->is_ca);
    /* CA fields (for using existing CA to sign) */
    json_get_string((const char*)json_buf, tokens, num_tokens, "ca_key_file", &config->ca_key_file);
    json_get_string((const char*)json_buf, tokens, num_tokens, "ca_key_format", &config->ca_key_format);
    json_get_string((const char*)json_buf, tokens, num_tokens, "ca_algorithm", &config->ca_algorithm);
    json_get_string((const char*)json_buf, tokens, num_tokens, "ca_cert_file", &config->ca_cert_file);
    json_get_string((const char*)json_buf, tokens, num_tokens, "ca_cert_format", &config->ca_cert_format);
    json_get_string((const char*)json_buf, tokens, num_tokens, "ca_subject", &config->ca_subject);
    json_get_string((const char*)json_buf, tokens, num_tokens, "ca_not_before", &config->ca_not_before);
    json_get_string((const char*)json_buf, tokens, num_tokens, "ca_not_after", &config->ca_not_after);

    free(json_buf);
    return 0;
}

/* Free cert_config_t structure */
static void free_cert_config(cert_config_t* config) {
    free(config->key_file);
    free(config->key_format);
    free(config->algorithm);
    free(config->subject);
    free(config->not_before);
    free(config->not_after);
    free(config->signature_md);
    free(config->ca_key_file);
    free(config->ca_key_format);
    free(config->ca_algorithm);
    free(config->ca_cert_file);
    free(config->ca_cert_format);
    free(config->ca_subject);
    free(config->ca_not_before);
    free(config->ca_not_after);
}

/* Helper function to parse signature MD algorithm from string */
static mbedtls_md_type_t parse_signature_md(const char* md_str) {
    if (!md_str) {
        return MBEDTLS_MD_SHA256;  /* default */
    }
    
    if (strcasecmp(md_str, "sha256") == 0) {
        return MBEDTLS_MD_SHA256;
    } else if (strcasecmp(md_str, "sha384") == 0) {
        return MBEDTLS_MD_SHA384;
    } else if (strcasecmp(md_str, "sha512") == 0) {
        return MBEDTLS_MD_SHA512;
    } else if (strcasecmp(md_str, "sha224") == 0) {
        return MBEDTLS_MD_SHA224;
    }
    
    /* Default to SHA256 for unknown values */
    return MBEDTLS_MD_SHA256;
}

/* Auto-detect appropriate hash algorithm based on key type and curve */
static mbedtls_md_type_t get_recommended_md_for_key(mbedtls_pk_context* key) {
    if (!key) {
        return MBEDTLS_MD_SHA256;  /* default */
    }
    
    mbedtls_pk_type_t pk_type = mbedtls_pk_get_type(key);
    
    if (pk_type == MBEDTLS_PK_OPAQUE) {
        /* For ED25519 (opaque PSA key), use NONE as it uses PureEdDSA (no separate hash) */
        return MBEDTLS_MD_NONE;
    } else if (pk_type == MBEDTLS_PK_ECKEY || pk_type == MBEDTLS_PK_ECDSA) {
        /* For EC keys, match hash size to curve size */
        mbedtls_ecp_keypair* ec = mbedtls_pk_ec(*key);
        if (ec) {
            mbedtls_ecp_group_id grp_id = mbedtls_ecp_keypair_get_group_id(ec);
            switch (grp_id) {
                case MBEDTLS_ECP_DP_SECP521R1:
                    return MBEDTLS_MD_SHA512;  /* P-521 -> SHA-512 */
                case MBEDTLS_ECP_DP_SECP384R1:
                case MBEDTLS_ECP_DP_BP384R1:
                    return MBEDTLS_MD_SHA384;  /* P-384 -> SHA-384 */
                case MBEDTLS_ECP_DP_SECP256R1:
                case MBEDTLS_ECP_DP_SECP256K1:
                case MBEDTLS_ECP_DP_BP256R1:
                default:
                    return MBEDTLS_MD_SHA256;  /* P-256 and others -> SHA-256 */
            }
        }
    } else if (pk_type == MBEDTLS_PK_RSA) {
        /* For RSA keys, use SHA-256 as default (can handle any RSA key size) */
        return MBEDTLS_MD_SHA256;
    }
    
    /* Default fallback */
    return MBEDTLS_MD_SHA256;
}

/*! given public key \p pk, generate an RA-TLS certificate \p writecrt with \p quote (legacy format)
 *  and \p evidence (new standard format) embedded */
static int generate_x509(mbedtls_pk_context* pk, const uint8_t* quote, size_t quote_size,
                         const uint8_t* evidence, size_t evidence_size,
                         mbedtls_x509write_cert* writecrt,
                         mbedtls_pk_context* ca_key, const char* ca_subject_name,
                         const char* subject_name, const char* not_before, const char* not_after,
                         mbedtls_md_type_t md_type, bool is_ca) {
    int ret;
    char* cert_timestamp_not_before = NULL;
    char* cert_timestamp_not_after  = NULL;

    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);

    mbedtls_x509write_crt_init(writecrt);

    /* Set subject key (always the RA-TLS key) */
    mbedtls_x509write_crt_set_subject_key(writecrt, pk);
    
    /* Set issuer key: CA key if provided, otherwise self-signed */
    if (ca_key) {
        mbedtls_x509write_crt_set_issuer_key(writecrt, ca_key);
    } else {
        mbedtls_x509write_crt_set_issuer_key(writecrt, pk);
    }
    
    /* Set signature MD algorithm AFTER setting issuer key */
    mbedtls_x509write_crt_set_md_alg(writecrt, md_type);
    
    /* Debug logging for certificate configuration */
    printf("RA-TLS: ========== Certificate Configuration (generate_x509) ==========\n");
    printf("RA-TLS:   Certificate type: %s\n", ca_key ? "CA-signed" : "self-signed");
    printf("RA-TLS:   Subject key type: %s\n", get_pk_type_name(mbedtls_pk_get_type(pk)));
    if (mbedtls_pk_get_type(pk) == MBEDTLS_PK_ECKEY || mbedtls_pk_get_type(pk) == MBEDTLS_PK_ECDSA) {
        mbedtls_ecp_keypair* ec = mbedtls_pk_ec(*pk);
        if (ec) {
            mbedtls_ecp_group_id grp_id = mbedtls_ecp_keypair_get_group_id(ec);
            const char* curve_name = "unknown";
            if (grp_id == MBEDTLS_ECP_DP_SECP256R1) curve_name = "P-256";
            else if (grp_id == MBEDTLS_ECP_DP_SECP384R1) curve_name = "P-384";
            else if (grp_id == MBEDTLS_ECP_DP_SECP521R1) curve_name = "P-521";
            else if (grp_id == MBEDTLS_ECP_DP_SECP256K1) curve_name = "secp256k1";
            else if (grp_id == MBEDTLS_ECP_DP_SECP192R1) curve_name = "P-192";
            else if (grp_id == MBEDTLS_ECP_DP_SECP192K1) curve_name = "secp192k1";
            else if (grp_id == MBEDTLS_ECP_DP_BP256R1)   curve_name = "brainpoolP256r1";
            else if (grp_id == MBEDTLS_ECP_DP_BP384R1)   curve_name = "brainpoolP384r1";
            else if (grp_id == MBEDTLS_ECP_DP_BP512R1)   curve_name = "brainpoolP512r1";
            printf("RA-TLS:   Subject key curve: %s\n", curve_name);
        }
    }
    if (ca_key) {
        printf("RA-TLS:   Issuer key type: %s\n", get_pk_type_name(mbedtls_pk_get_type(ca_key)));
        if (mbedtls_pk_get_type(ca_key) == MBEDTLS_PK_ECKEY || mbedtls_pk_get_type(ca_key) == MBEDTLS_PK_ECDSA) {
            mbedtls_ecp_keypair* ec = mbedtls_pk_ec(*ca_key);
            if (ec) {
                mbedtls_ecp_group_id grp_id = mbedtls_ecp_keypair_get_group_id(ec);
                const char* curve_name = "unknown";
                if (grp_id == MBEDTLS_ECP_DP_SECP256R1) curve_name = "P-256";
                else if (grp_id == MBEDTLS_ECP_DP_SECP384R1) curve_name = "P-384";
                else if (grp_id == MBEDTLS_ECP_DP_SECP521R1) curve_name = "P-521";
                printf("RA-TLS:   Issuer key curve: %s\n", curve_name);
            }
        }
    } else {
        printf("RA-TLS:   Issuer key: same as subject (self-signed)\n");
    }
    printf("RA-TLS:   Signature MD: %s (type=%d)\n", get_md_name(md_type), md_type);
    printf("RA-TLS:   is_ca flag: %s\n", is_ca ? "true" : "false");
    printf("RA-TLS: ================================================================\n");

    /* Set subject name */
    const char* subject = subject_name ? subject_name : CERT_SUBJECT_NAME_VALUES;
    ret = mbedtls_x509write_crt_set_subject_name(writecrt, subject);
    if (ret < 0)
        goto out;

    /* Set issuer name: CA subject if provided, otherwise same as subject (self-signed) */
    const char* issuer = ca_subject_name ? ca_subject_name : subject;
    ret = mbedtls_x509write_crt_set_issuer_name(writecrt, issuer);
    if (ret < 0)
        goto out;

    /* set a serial number (dummy "1") for the generated certificate */
    ret = mbedtls_mpi_read_string(&serial, 10, "1");
    if (ret < 0)
        goto out;

    ret = mbedtls_x509write_crt_set_serial(writecrt, &serial);
    if (ret < 0)
        goto out;

    /* Set validity period */
    if (not_before) {
        cert_timestamp_not_before = strdup(not_before);
    } else {
        cert_timestamp_not_before = strdup(getenv(RA_TLS_CERT_TIMESTAMP_NOT_BEFORE) ? :
                                           CERT_TIMESTAMP_NOT_BEFORE_DEFAULT);
    }
    if (!cert_timestamp_not_before) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    if (not_after) {
        cert_timestamp_not_after = strdup(not_after);
    } else {
        cert_timestamp_not_after = strdup(getenv(RA_TLS_CERT_TIMESTAMP_NOT_AFTER) ? :
                                          CERT_TIMESTAMP_NOT_AFTER_DEFAULT);
    }
    if (!cert_timestamp_not_after) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    ret = mbedtls_x509write_crt_set_validity(writecrt, cert_timestamp_not_before,
                                             cert_timestamp_not_after);
    if (ret < 0)
        goto out;

    ret = mbedtls_x509write_crt_set_basic_constraints(writecrt, is_ca ? 1 : 0, /*max_pathlen=*/-1);
    if (ret < 0)
        goto out;

    ret = mbedtls_x509write_crt_set_subject_key_identifier(writecrt);
    if (ret < 0)
        goto out;

    ret = mbedtls_x509write_crt_set_authority_key_identifier(writecrt);
    if (ret < 0)
        goto out;

    /*
     * embed the SGX quote into the generated certificate (as X.509 extension) in two formats:
     *   - legacy non-standard "SGX quote" OID (used since Gramine v1.0)
     *   - new standard TCG DICE "tagged evidence" OID 2.23.133.5.4.9 (used since Gramine v1.8)
     */
    ret = mbedtls_x509write_crt_set_extension(writecrt, (const char*)g_ratls_quote_oid,
                                              sizeof(g_ratls_quote_oid), /*critical=*/0, quote,
                                              quote_size);
    if (ret < 0)
        goto out;

    ret = mbedtls_x509write_crt_set_extension(writecrt, (const char*)g_ratls_evidence_oid,
                                              sizeof(g_ratls_evidence_oid), /*critical=*/0,
                                              evidence, evidence_size);
    if (ret < 0)
        goto out;

    ret = 0;
out:
    free(cert_timestamp_not_before);
    free(cert_timestamp_not_after);
    mbedtls_mpi_free(&serial);
    return ret;
}

/*! calculate sha256 over public key \p pk and copy it into \p sha */
static int sha256_over_pk(mbedtls_pk_context* pk, uint8_t* sha) {
    uint8_t pk_der[PUB_KEY_SIZE_MAX] = {0};

    /* below function writes data at the end of the buffer */
    int pk_der_size_byte = mbedtls_pk_write_pubkey_der(pk, pk_der, sizeof(pk_der));
    if (pk_der_size_byte < 0)
        return pk_der_size_byte;

    /* move the data to the beginning of the buffer, to avoid pointer arithmetic later */
    memmove(pk_der, pk_der + PUB_KEY_SIZE_MAX - pk_der_size_byte, pk_der_size_byte);

    return mbedtls_sha256(pk_der, pk_der_size_byte, sha, /*is224=*/0);
}

/*! generate SGX quote with user_report_data equal to SHA256 hash over \p pk (legacy format) */
static int generate_quote_with_pk_hash(mbedtls_pk_context* pk, uint8_t** out_quote,
                                       size_t* out_quote_size) {
    sgx_report_data_t user_report_data = {0};
    int ret = sha256_over_pk(pk, user_report_data.d);
    if (ret < 0)
        return ret;

    ssize_t written = write_file("/dev/attestation/user_report_data", user_report_data.d,
                                 sizeof(user_report_data.d));
    if (written != sizeof(user_report_data))
        return MBEDTLS_ERR_X509_FILE_IO_ERROR;

    uint8_t* quote = malloc(SGX_QUOTE_MAX_SIZE);
    if (!quote)
        return MBEDTLS_ERR_X509_ALLOC_FAILED;

    ssize_t quote_size = read_file("/dev/attestation/quote", quote, SGX_QUOTE_MAX_SIZE);
    if (quote_size < 0) {
        free(quote);
        return MBEDTLS_ERR_X509_FILE_IO_ERROR;
    }

    *out_quote = quote;
    *out_quote_size = (size_t)quote_size;
    return 0;
}

/*! create CBOR bstr from SHA256 hash of public key \p pk and copy it into \p out_cbor_bstr */
static int cbor_bstr_from_pk_sha256(mbedtls_pk_context* pk, cbor_item_t** out_cbor_bstr) {
    uint8_t sha256[SHA256_DIGEST_SIZE] = {0};
    int ret = sha256_over_pk(pk, sha256);
    if (ret < 0)
        return ret;

    cbor_item_t* cbor_bstr = cbor_build_bytestring(sha256, sizeof(sha256));
    if (!cbor_bstr)
        return MBEDTLS_ERR_X509_ALLOC_FAILED;

    *out_cbor_bstr = cbor_bstr;
    return 0;
}

/*! generate hash-entry -- CBOR array with [ hash-alg-id, hash-value -- hash of pubkey ] */
static int generate_serialized_pk_hash_entry(mbedtls_pk_context* pk, uint8_t** out_hash_entry_buf,
                                             size_t* out_hash_entry_buf_size) {
    /* the hash-entry array as defined in Concise Software Identification Tags (CoSWID) */
    cbor_item_t* cbor_hash_entry = cbor_new_definite_array(2);
    if (!cbor_hash_entry)
        return MBEDTLS_ERR_X509_ALLOC_FAILED;

    /* RA-TLS always uses SHA256 hash */
    cbor_item_t* cbor_hash_alg_id = cbor_build_uint8(IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA256);
    if (!cbor_hash_alg_id) {
        cbor_decref(&cbor_hash_entry);
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    cbor_item_t* cbor_hash_value;
    int ret = cbor_bstr_from_pk_sha256(pk, &cbor_hash_value);
    if (ret < 0) {
        cbor_decref(&cbor_hash_alg_id);
        cbor_decref(&cbor_hash_entry);
        return ret;
    }

    int bool_ret = cbor_array_push(cbor_hash_entry, cbor_hash_alg_id);
    if (!bool_ret) {
        cbor_decref(&cbor_hash_value);
        cbor_decref(&cbor_hash_alg_id);
        cbor_decref(&cbor_hash_entry);
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    bool_ret = cbor_array_push(cbor_hash_entry, cbor_hash_value);
    if (!bool_ret) {
        cbor_decref(&cbor_hash_value);
        cbor_decref(&cbor_hash_alg_id);
        cbor_decref(&cbor_hash_entry);
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    /* cbor_hash_entry took ownership of hash_alg_id and hash_value cbor items */
    cbor_decref(&cbor_hash_alg_id);
    cbor_decref(&cbor_hash_value);

    uint8_t* hash_entry_buf;
    size_t hash_entry_buf_size;
    cbor_serialize_alloc(cbor_hash_entry, &hash_entry_buf, &hash_entry_buf_size);

    cbor_decref(&cbor_hash_entry);

    if (!hash_entry_buf)
        return MBEDTLS_ERR_X509_ALLOC_FAILED;

    *out_hash_entry_buf = hash_entry_buf;
    *out_hash_entry_buf_size = hash_entry_buf_size;
    return 0;
}

/*! generate claims -- CBOR map with { "pubkey-hash" = <serialized CBOR array hash-entry> } */
static int generate_serialized_claims(mbedtls_pk_context* pk, uint8_t** out_claims_buf,
                                      size_t* out_claims_buf_size) {
    /* TODO: currently, only claim "pubkey-hash" is implemented, but in the future there may be more
     *       (e.g. "nonce") */
    cbor_item_t* cbor_claims = cbor_new_definite_map(1);
    if (!cbor_claims)
        return MBEDTLS_ERR_X509_ALLOC_FAILED;

    cbor_item_t* cbor_pubkey_hash_key = cbor_build_string("pubkey-hash");
    if (!cbor_pubkey_hash_key) {
        cbor_decref(&cbor_claims);
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    uint8_t* hash_entry_buf;
    size_t hash_entry_buf_size;
    int ret = generate_serialized_pk_hash_entry(pk, &hash_entry_buf, &hash_entry_buf_size);
    if (ret < 0) {
        cbor_decref(&cbor_pubkey_hash_key);
        cbor_decref(&cbor_claims);
        return ret;
    }

    cbor_item_t* cbor_pubkey_hash_val = cbor_build_bytestring(hash_entry_buf, hash_entry_buf_size);

    free(hash_entry_buf);

    if (!cbor_pubkey_hash_val) {
        cbor_decref(&cbor_pubkey_hash_key);
        cbor_decref(&cbor_claims);
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    struct cbor_pair cbor_pubkey_hash_pair = { .key = cbor_pubkey_hash_key,
                                               .value = cbor_pubkey_hash_val };
    bool bool_ret = cbor_map_add(cbor_claims, cbor_pubkey_hash_pair);
    if (!bool_ret) {
        cbor_decref(&cbor_pubkey_hash_val);
        cbor_decref(&cbor_pubkey_hash_key);
        cbor_decref(&cbor_claims);
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    /* cbor_claims took ownership of hash_key and hash_val cbor items */
    cbor_decref(&cbor_pubkey_hash_val);
    cbor_decref(&cbor_pubkey_hash_key);

    uint8_t* claims_buf;
    size_t claims_buf_size;
    cbor_serialize_alloc(cbor_claims, &claims_buf, &claims_buf_size);

    cbor_decref(&cbor_claims);

    if (!claims_buf)
        return MBEDTLS_ERR_X509_ALLOC_FAILED;

    *out_claims_buf = claims_buf;
    *out_claims_buf_size = claims_buf_size;
    return 0;
}

/*! generate SGX quote with user_report_data = hash(serialized-cbor-map of claims) */
static int generate_quote_with_claims_hash(uint8_t* claims, size_t claims_size,
                                           uint8_t** out_quote_buf, size_t* out_quote_buf_size) {
    int ret;
    uint8_t* quote = NULL;

    sgx_report_data_t user_report_data = {0};
    ret = mbedtls_sha256(claims, claims_size, user_report_data.d, /*is224=*/0);
    if (ret < 0)
        goto fail;

    ssize_t written = write_file("/dev/attestation/user_report_data", user_report_data.d,
                                 sizeof(user_report_data.d));
    if (written != sizeof(user_report_data)) {
        ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
        goto fail;
    }

    quote = malloc(SGX_QUOTE_MAX_SIZE);
    if (!quote) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto fail;
    }

    ssize_t quote_size = read_file("/dev/attestation/quote", quote, SGX_QUOTE_MAX_SIZE);
    if (quote_size < 0) {
        ret = MBEDTLS_ERR_X509_FILE_IO_ERROR;
        goto fail;
    }

    *out_quote_buf = quote;
    *out_quote_buf_size = quote_size;
    return 0;
fail:
    free(quote);
    return ret;
}

/*! combine quote and claims in a CBOR tag with CBOR array of CBOR bstrs: [ quote, claims ] */
static int combine_quote_and_claims_in_evidence(uint8_t* quote, size_t quote_size,
                                                uint8_t* claims, size_t claims_size,
                                                uint8_t** out_evidence_buf,
                                                size_t* out_evidence_buf_size) {
    /* step 1: wrap quote and claims as two CBOR-bstr items in a CBOR array */
    cbor_item_t* cbor_evidence = cbor_new_definite_array(2);
    if (!cbor_evidence)
        return MBEDTLS_ERR_X509_ALLOC_FAILED;

    cbor_item_t* cbor_quote = cbor_build_bytestring(quote, quote_size);
    if (!cbor_quote) {
        cbor_decref(&cbor_evidence);
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    cbor_item_t* cbor_claims = cbor_build_bytestring(claims, claims_size);
    if (!cbor_claims) {
        cbor_decref(&cbor_quote);
        cbor_decref(&cbor_evidence);
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    int bool_ret = cbor_array_push(cbor_evidence, cbor_quote);
    if (!bool_ret) {
        cbor_decref(&cbor_claims);
        cbor_decref(&cbor_quote);
        cbor_decref(&cbor_evidence);
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    bool_ret = cbor_array_push(cbor_evidence, cbor_claims);
    if (!bool_ret) {
        cbor_decref(&cbor_claims);
        cbor_decref(&cbor_quote);
        cbor_decref(&cbor_evidence);
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    /* cbor_evidence took ownership of quote and claims cbor bstrs */
    cbor_decref(&cbor_claims);
    cbor_decref(&cbor_quote);

    /* step 2: wrap the resulting CBOR array in a tagged CBOR object */
    cbor_item_t* cbor_tagged_evidence = cbor_new_tag(TCG_DICE_TAGGED_EVIDENCE_TEE_QUOTE_CBOR_TAG);
    if (!cbor_tagged_evidence) {
        cbor_decref(&cbor_evidence);
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    }

    cbor_tag_set_item(cbor_tagged_evidence, cbor_evidence);

    /* step 3: serialize the resulting tagged CBOR object, to be embedded as an OID in X.509 cert */
    uint8_t* evidence_buf;
    size_t evidence_buf_size;
    cbor_serialize_alloc(cbor_tagged_evidence, &evidence_buf, &evidence_buf_size);

    cbor_decref(&cbor_evidence);
    cbor_decref(&cbor_tagged_evidence);

    if (!evidence_buf)
        return MBEDTLS_ERR_X509_ALLOC_FAILED;

    *out_evidence_buf = evidence_buf;
    *out_evidence_buf_size = evidence_buf_size;
    return 0;
}

/*! generate TCG DICE tagged evidence object (a set of claims) with the SGX quote as the main
 * evidence and \p pk as one of the embedded claims */
static int generate_tcg_dice_tagged_evidence(mbedtls_pk_context* pk, uint8_t** out_evidence,
                                             size_t* out_evidence_size) {
    /*
     * TCG DICE tagged evidence has the following serialized-CBOR format:
     *
     * CBOR object (major type 6, new CBOR tag for "ECDSA SGX Quotes") ->
     *   CBOR array ->
     *      [
     *        0: CBOR bstr (SGX quote with user_report_data = hash(serialized-cbor-map of claims)),
     *        1: CBOR bstr (serialized-cbor-map of claims)
     *      ]
     *
     * where "serialized-cbor-map of claims" is a serialized representation of the following:
     *
     *   CBOR map ->
     *      {
     *        "pubkey-hash" (req) : CBOR bstr (serialized-cbor-array hash-entry),
     *        "nonce"       (opt) : CBOR bstr (arbitrary-sized nonce for per-session freshness)
     *      }
     *
     * where "serialized-cbor-array hash-entry" is a serialized representation of the following:
     *
     *   CBOR array ->
     *      [
     *        0: CBOR uint (hash-alg-id),
     *        1: CBOR bstr (hash of DER-formatted "SubjectPublicKeyInfo" field as CBOR bstr)
     *      ]
     *
     * For hash-alg-id values, see
     * https://www.iana.org/assignments/named-information/named-information.xhtml
     */
    int ret;
    uint8_t* claims   = NULL;
    uint8_t* quote    = NULL;
    uint8_t* evidence = NULL;

    size_t claims_size;
    ret = generate_serialized_claims(pk, &claims, &claims_size);
    if (ret < 0)
        goto out;

    size_t quote_size;
    ret = generate_quote_with_claims_hash(claims, claims_size, &quote, &quote_size);
    if (ret < 0)
        goto out;

    size_t evidence_size;
    ret = combine_quote_and_claims_in_evidence(quote, quote_size, claims, claims_size, &evidence,
                                               &evidence_size);
    if (ret < 0)
        goto out;

    *out_evidence = evidence;
    *out_evidence_size = (size_t)evidence_size;
    ret = 0;
out:
    free(quote);
    free(claims);
    return ret;
}

/*! Generate a CA certificate using the provided key and configuration */
static int generate_ca_certificate(mbedtls_pk_context* ca_key, mbedtls_x509_crt* ca_crt,
                                   const char* ca_subject, const char* ca_not_before,
                                   const char* ca_not_after, mbedtls_md_type_t md_type,
                                   mbedtls_ctr_drbg_context* ctr_drbg) {
    int ret;
    mbedtls_x509write_cert ca_writecrt;
    mbedtls_mpi serial;
    uint8_t* quote = NULL;
    uint8_t* evidence = NULL;
    
    printf("RA-TLS: generate_ca_certificate() called\n");
    printf("RA-TLS:   CA subject: %s\n", ca_subject ? ca_subject : "(null)");
    printf("RA-TLS:   CA not_before: %s\n", ca_not_before ? ca_not_before : "(using default)");
    printf("RA-TLS:   CA not_after: %s\n", ca_not_after ? ca_not_after : "(using default)");
    printf("RA-TLS:   CA signature MD: %s\n", get_md_name(md_type));
    printf("RA-TLS:   CA key type: %s\n", get_pk_type_name(mbedtls_pk_get_type(ca_key)));
    
    mbedtls_x509write_crt_init(&ca_writecrt);
    mbedtls_mpi_init(&serial);
    
    /* Generate SGX quote with CA key hash (same as user certificate) */
    /* Check if running in SGX environment - if not, skip quote generation */
    size_t quote_size = 0;
    size_t evidence_size = 0;
    
    /* Simple check: try to generate quote, if it fails assume not in SGX */
    printf("RA-TLS: Checking SGX environment for CA certificate quote generation...\n");
    ret = generate_quote_with_pk_hash(ca_key, &quote, &quote_size);
    if (ret < 0) {
        printf("RA-TLS: Not in SGX environment or quote generation failed, skipping SGX quote for CA certificate\n");
        /* Not in SGX environment - continue without quote */
        ret = 0;  /* Reset error, continue without quote */
    } else {
        printf("RA-TLS: SGX quote generated for CA certificate\n");
        ret = generate_tcg_dice_tagged_evidence(ca_key, &evidence, &evidence_size);
        if (ret < 0) {
            printf("RA-TLS: Failed to generate TCG DICE evidence for CA certificate\n");
            free(quote);
            quote = NULL;
            quote_size = 0;
            ret = 0;  /* Continue without evidence */
        } else {
            printf("RA-TLS:   Quote size: %zu bytes, Evidence size: %zu bytes\n", quote_size, evidence_size);
        }
    }
    
    /* Set MD algorithm */
    mbedtls_x509write_crt_set_md_alg(&ca_writecrt, md_type);
    
    /* Set subject and issuer keys (self-signed) */
    mbedtls_x509write_crt_set_subject_key(&ca_writecrt, ca_key);
    mbedtls_x509write_crt_set_issuer_key(&ca_writecrt, ca_key);
    
    /* Set subject and issuer names (same for self-signed) */
    const char* subject = ca_subject ? ca_subject : CERT_SUBJECT_NAME_VALUES;
    ret = mbedtls_x509write_crt_set_subject_name(&ca_writecrt, subject);
    if (ret < 0)
        goto out;
    
    ret = mbedtls_x509write_crt_set_issuer_name(&ca_writecrt, subject);
    if (ret < 0)
        goto out;
    
    /* Set serial number */
    ret = mbedtls_mpi_read_string(&serial, 10, "1");
    if (ret < 0)
        goto out;
    
    ret = mbedtls_x509write_crt_set_serial(&ca_writecrt, &serial);
    if (ret < 0)
        goto out;
    
    /* Set validity period */
    const char* not_before_str = ca_not_before ? ca_not_before : CERT_TIMESTAMP_NOT_BEFORE_DEFAULT;
    const char* not_after_str = ca_not_after ? ca_not_after : CERT_TIMESTAMP_NOT_AFTER_DEFAULT;
    
    ret = mbedtls_x509write_crt_set_validity(&ca_writecrt, not_before_str, not_after_str);
    if (ret < 0)
        goto out;
    
    /* Set basic constraints: CA=TRUE */
    printf("RA-TLS:   Setting CA basic constraints: CA=TRUE\n");
    ret = mbedtls_x509write_crt_set_basic_constraints(&ca_writecrt, /*is_ca=*/1, /*max_pathlen=*/-1);
    if (ret < 0)
        goto out;
    
    /* Set key usage: KEY_CERT_SIGN | CRL_SIGN */
    ret = mbedtls_x509write_crt_set_key_usage(&ca_writecrt, 
                                              MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN);
    if (ret < 0)
        goto out;
    
    /* Set subject and authority key identifiers */
    ret = mbedtls_x509write_crt_set_subject_key_identifier(&ca_writecrt);
    if (ret < 0)
        goto out;
    
    ret = mbedtls_x509write_crt_set_authority_key_identifier(&ca_writecrt);
    if (ret < 0)
        goto out;
    
    /* Add SGX quote extensions if quote was generated */
    if (quote && quote_size > 0) {
        printf("RA-TLS: Adding SGX quote extensions to CA certificate\n");
        ret = mbedtls_x509write_crt_set_extension(&ca_writecrt, (const char*)g_ratls_quote_oid,
                                                  sizeof(g_ratls_quote_oid), /*critical=*/0,
                                                  quote, quote_size);
        if (ret < 0) {
            log_mbedtls_error("CA certificate: set SGX quote extension", ret);
            goto out;
        }
        
        if (evidence && evidence_size > 0) {
            ret = mbedtls_x509write_crt_set_extension(&ca_writecrt, (const char*)g_ratls_evidence_oid,
                                                      sizeof(g_ratls_evidence_oid), /*critical=*/0,
                                                      evidence, evidence_size);
            if (ret < 0) {
                log_mbedtls_error("CA certificate: set TCG DICE evidence extension", ret);
                goto out;
            }
        }
    } else {
        printf("RA-TLS: Skipping SGX quote extensions for CA certificate (not in SGX environment)\n");
    }
    
    /* Dynamic buffer allocation with retry loop for CA certificate DER encoding */
    uint8_t* ca_cert_buf = NULL;
    size_t ca_cert_buf_size = 16384;  /* Start with 16KB */
    const size_t max_buf_size = 131072;  /* Cap at 128KB */
    int ca_cert_size = 0;
    
    while (ca_cert_buf_size <= max_buf_size) {
        ca_cert_buf = malloc(ca_cert_buf_size);
        if (!ca_cert_buf) {
            printf("RA-TLS: Failed to allocate %zu bytes for CA certificate buffer\n", ca_cert_buf_size);
            ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
            goto out;
        }
        
        printf("RA-TLS:   Attempting DER write with buffer size: %zu bytes\n", ca_cert_buf_size);
        ca_cert_size = mbedtls_x509write_crt_der(&ca_writecrt, ca_cert_buf, ca_cert_buf_size,
                                                  mbedtls_ctr_drbg_random, ctr_drbg);
        
        if (ca_cert_size >= 0) {
            /* Success */
            printf("RA-TLS:   CA certificate DER size: %d bytes (buffer: %zu bytes)\n", 
                   ca_cert_size, ca_cert_buf_size);
            break;
        } else if (ca_cert_size == MBEDTLS_ERR_ASN1_BUF_TOO_SMALL) {
            /* Buffer too small, retry with larger buffer */
            printf("RA-TLS:   Buffer too small (%zu bytes), retrying with larger buffer\n", ca_cert_buf_size);
            free(ca_cert_buf);
            ca_cert_buf = NULL;
            ca_cert_buf_size *= 2;  /* Double the buffer size */
        } else {
            /* Other error */
            ret = ca_cert_size;
            log_mbedtls_error("CA certificate DER write", ret);
            free(ca_cert_buf);
            ca_cert_buf = NULL;
            goto out;
        }
    }
    
    if (ca_cert_size < 0) {
        printf("RA-TLS: Failed to write CA certificate even with max buffer size (%zu bytes)\n", max_buf_size);
        ret = ca_cert_size;
        goto out;
    }
    
    /* Parse the generated certificate - note mbedtls writes from end of buffer */
    ret = mbedtls_x509_crt_parse_der(ca_crt, ca_cert_buf + ca_cert_buf_size - ca_cert_size, 
                                     ca_cert_size);
    if (ret < 0) {
        log_mbedtls_error("CA certificate parse", ret);
        free(ca_cert_buf);
        ca_cert_buf = NULL;
        goto out;
    }
    
    free(ca_cert_buf);
    ca_cert_buf = NULL;
    
    printf("RA-TLS: CA certificate generated successfully (with SGX quote)\n");
    
out:
    free(quote);
    free(evidence);
    mbedtls_x509write_crt_free(&ca_writecrt);
    mbedtls_mpi_free(&serial);
    return ret;
}

/*! Load and verify a CA certificate from file */
static int load_and_verify_ca_certificate(const char* ca_cert_file, const char* ca_cert_format,
                                          mbedtls_pk_context* ca_key, mbedtls_x509_crt* ca_crt,
                                          mbedtls_ctr_drbg_context* ctr_drbg) {
    int ret;
    
    printf("RA-TLS: load_and_verify_ca_certificate() called\n");
    printf("RA-TLS:   CA cert file: %s\n", ca_cert_file);
    printf("RA-TLS:   CA cert format: %s\n", ca_cert_format ? ca_cert_format : "pem (default)");
    
    /* Determine format */
    bool is_pem = !ca_cert_format || strcasecmp(ca_cert_format, "pem") == 0;
    
    if (is_pem) {
        /* Load PEM certificate */
        ret = mbedtls_x509_crt_parse_file(ca_crt, ca_cert_file);
    } else {
        /* Load DER certificate */
        uint8_t ca_cert_buf[8192];
        ssize_t ca_cert_len = read_file(ca_cert_file, ca_cert_buf, sizeof(ca_cert_buf));
        if (ca_cert_len < 0) {
            printf("RA-TLS: Failed to read CA certificate file: %s (errno=%d)\n", ca_cert_file, errno);
            return MBEDTLS_ERR_X509_FILE_IO_ERROR;
        }
        ret = mbedtls_x509_crt_parse_der(ca_crt, ca_cert_buf, ca_cert_len);
    }
    
    if (ret < 0) {
        log_mbedtls_error("CA certificate parse", ret);
        return ret;
    }
    
    printf("RA-TLS: CA certificate loaded successfully\n");
    
    /* Extract and log CA subject */
    char subject_buf[256];
    ret = mbedtls_x509_dn_gets(subject_buf, sizeof(subject_buf), &ca_crt->subject);
    if (ret > 0) {
        printf("RA-TLS:   CA certificate subject: %s\n", subject_buf);
    }
    
    /* Verify that the CA certificate's public key matches the provided private key */
    printf("RA-TLS: Verifying CA certificate public key matches private key...\n");
    ret = mbedtls_pk_check_pair(&ca_crt->pk, ca_key, mbedtls_ctr_drbg_random, ctr_drbg);
    if (ret != 0) {
        log_mbedtls_error("CA key/cert mismatch", ret);
        return MBEDTLS_ERR_X509_INVALID_ALG;  /* Key mismatch */
    }
    printf("RA-TLS:   CA key/cert pair verified successfully\n");
    
    /* Verify that the certificate is a CA certificate using accessor function */
    int ca_istrue = mbedtls_x509_crt_get_ca_istrue(ca_crt);
    printf("RA-TLS:   CA certificate CA flag: %s\n", ca_istrue ? "TRUE" : "FALSE");
    if (ca_istrue == 0) {
        printf("RA-TLS: ERROR: Certificate is not marked as a CA certificate\n");
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;  /* Not a CA certificate */
    }
    
    /* Verify that the certificate has KEY_CERT_SIGN in key usage */
    ret = mbedtls_x509_crt_check_key_usage(ca_crt, MBEDTLS_X509_KU_KEY_CERT_SIGN);
    if (ret != 0) {
        printf("RA-TLS: ERROR: CA certificate missing KEY_CERT_SIGN usage\n");
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;  /* Missing KEY_CERT_SIGN */
    }
    printf("RA-TLS:   CA certificate has KEY_CERT_SIGN usage\n");
    
    printf("RA-TLS: CA certificate verification completed successfully\n");
    return 0;
}

/*! given public key \p pk, generate an RA-TLS certificate \p writecrt */
static int create_x509(mbedtls_pk_context* pk, mbedtls_x509write_cert* writecrt,
                       mbedtls_pk_context* ca_key, const char* ca_subject,
                       const char* subject, const char* not_before, const char* not_after,
                       mbedtls_md_type_t md_type, bool is_ca) {
    int ret;

    /*
     * We put both "legacy Gramine" OID with plain SGX quote as well as standardized TCG DICE "tagged
     * evidence" OID with CBOR-formatted SGX quote into the RA-TLS X.509 cert. This is for keeping
     * backward compatibility at the price of a larger size of the resulting cert.
     */
    uint8_t* quote = NULL;
    uint8_t* evidence = NULL;

    /* Check if running in SGX environment - if not, skip quote generation */
    size_t quote_size = 0;
    size_t evidence_size = 0;

    /* TODO: this legacy OID with plain SGX quote should be removed at some point */
    ret = generate_quote_with_pk_hash(pk, &quote, &quote_size);
    if (ret < 0) {
        /* Not in SGX environment - continue without quote */
        ret = 0;
    } else {
        ret = generate_tcg_dice_tagged_evidence(pk, &evidence, &evidence_size);
        if (ret < 0) {
            free(quote);
            quote = NULL;
            quote_size = 0;
            ret = 0;  /* Continue without evidence */
        }
    }

    /* TODO: currently, the Endorsement extension is not implemented (contains TCB info, CRL, etc.);
     *       should be added in the future */

    ret = generate_x509(pk, quote, quote_size, evidence, evidence_size, writecrt,
                       ca_key, ca_subject, subject, not_before, not_after, md_type, is_ca);
    free(quote);
    free(evidence);
    return ret;
}

static int create_key_and_crt(mbedtls_pk_context* key, mbedtls_x509_crt* crt, uint8_t** crt_der,
                              size_t* crt_der_size) {
    int ret;

    if (!key || (!crt && !(crt_der && crt_der_size))) {
        /* mbedTLS API (ra_tls_create_key_and_crt) and generic API (ra_tls_create_key_and_crt_der)
         * both use `key`, but the former uses `crt` and the latter uses `crt_der` */
        return MBEDTLS_ERR_X509_FATAL_ERROR;
    }

    /* Initialize PSA Crypto for MBEDTLS_USE_PSA_CRYPTO support (required for all signing operations) */
    static bool psa_initialized = false;
    if (!psa_initialized) {
        psa_status_t psa_status = psa_crypto_init();
        if (psa_status != PSA_SUCCESS) {
            printf("RA-TLS: ERROR: PSA crypto initialization failed: %d\n", psa_status);
            return MBEDTLS_ERR_X509_FATAL_ERROR;
        }
        psa_initialized = true;
        printf("RA-TLS: PSA Crypto initialized successfully\n");
    }

    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_entropy_context entropy;
    mbedtls_entropy_init(&entropy);

    mbedtls_x509write_cert writecrt;
    mbedtls_x509write_crt_init(&writecrt);

    uint8_t* crt_der_buf = NULL;
    uint8_t* output_buf = NULL;
    size_t output_buf_size = 16 * 1024; /* enough for any X.509 certificate */

    output_buf = malloc(output_buf_size);
    if (!output_buf) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, /*custom=*/NULL,
                                /*customlen=*/0);
    if (ret < 0)
        goto out;

    /* Configuration precedence: RA_TLS_CERT_ALGORITHM > RA_TLS_CERT_CONFIG_B64 > defaults */
    const char* algo_env = getenv(RA_TLS_CERT_ALGORITHM);
    const char* config_b64 = getenv(RA_TLS_CERT_CONFIG_B64);
    cert_config_t json_config = {0};
    bool use_json = false;

    printf("RA-TLS: ========== Certificate Generation Configuration ==========\n");
    printf("RA-TLS: RA_TLS_CERT_ALGORITHM=%s\n", algo_env ? algo_env : "(not set)");
    printf("RA-TLS: RA_TLS_CERT_CONFIG_B64=%s\n", config_b64 ? "present" : "(not set)");
    
    if (algo_env) {
        printf("RA-TLS: NOTE: RA_TLS_CERT_ALGORITHM is set, JSON config will be IGNORED\n");
    }

    if (!algo_env && config_b64) {
        /* Parse JSON configuration if algorithm not specified */
        printf("RA-TLS: Parsing JSON configuration from RA_TLS_CERT_CONFIG_B64...\n");
        ret = parse_json_config(config_b64, &json_config);
        if (ret == 0) {
            use_json = true;
            printf("RA-TLS: JSON configuration parsed successfully\n");
            printf("RA-TLS: JSON config - key_file: %s\n", json_config.key_file ? json_config.key_file : "(not set)");
            printf("RA-TLS: JSON config - key_format: %s\n", json_config.key_format ? json_config.key_format : "(not set)");
            printf("RA-TLS: JSON config - algorithm: %s\n", json_config.algorithm ? json_config.algorithm : "(not set)");
            printf("RA-TLS: JSON config - subject: %s\n", json_config.subject ? json_config.subject : "(not set)");
            printf("RA-TLS: JSON config - not_before: %s\n", json_config.not_before ? json_config.not_before : "(not set)");
            printf("RA-TLS: JSON config - not_after: %s\n", json_config.not_after ? json_config.not_after : "(not set)");
            printf("RA-TLS: JSON config - signature_md: %s\n", json_config.signature_md ? json_config.signature_md : "(not set)");
            printf("RA-TLS: JSON config - is_ca: %s\n", json_config.is_ca ? "true" : "false");
            printf("RA-TLS: JSON config - ca_key_file: %s\n", json_config.ca_key_file ? json_config.ca_key_file : "(not set)");
            printf("RA-TLS: JSON config - ca_key_format: %s\n", json_config.ca_key_format ? json_config.ca_key_format : "(not set)");
            printf("RA-TLS: JSON config - ca_algorithm: %s\n", json_config.ca_algorithm ? json_config.ca_algorithm : "(not set)");
            printf("RA-TLS: JSON config - ca_cert_file: %s\n", json_config.ca_cert_file ? json_config.ca_cert_file : "(not set)");
            printf("RA-TLS: JSON config - ca_cert_format: %s\n", json_config.ca_cert_format ? json_config.ca_cert_format : "(not set)");
            printf("RA-TLS: JSON config - ca_subject: %s\n", json_config.ca_subject ? json_config.ca_subject : "(not set)");
            printf("RA-TLS: JSON config - ca_not_before: %s\n", json_config.ca_not_before ? json_config.ca_not_before : "(not set)");
            printf("RA-TLS: JSON config - ca_not_after: %s\n", json_config.ca_not_after ? json_config.ca_not_after : "(not set)");
        } else {
            printf("RA-TLS: Failed to parse JSON configuration, ret=%d\n", ret);
        }
    }
    printf("RA-TLS: ==========================================================\n");

    /* Load or generate key */
    if (use_json && json_config.key_file) {
        /* Load private key from file specified in JSON */
        bool is_pem = !json_config.key_format || strcasecmp(json_config.key_format, "pem") == 0;
        
        printf("RA-TLS: Loading leaf key from file: %s (format=%s)\n", 
               json_config.key_file, is_pem ? "pem" : "der");
        
        if (is_pem) {
            ret = mbedtls_pk_parse_keyfile(key, json_config.key_file, /*password=*/NULL,
                                           mbedtls_ctr_drbg_random, &ctr_drbg);
        } else {
            /* DER format - read file and parse */
            uint8_t key_buf[8192];
            ssize_t key_len = read_file(json_config.key_file, key_buf, sizeof(key_buf));
            if (key_len < 0) {
                printf("RA-TLS: Failed to read key file: %s (errno=%d)\n", json_config.key_file, errno);
                ret = MBEDTLS_ERR_PK_FILE_IO_ERROR;
                goto out_json;
            }
            ret = mbedtls_pk_parse_key(key, key_buf, key_len, /*password=*/NULL, 0,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
        }
        if (ret < 0) {
            log_mbedtls_error("Load leaf key from file", ret);
            goto out_json;
        }
        printf("RA-TLS: Leaf key loaded successfully, type=%s\n", get_pk_type_name(mbedtls_pk_get_type(key)));
    } else {
        /* Generate new key based on algorithm */
        const char* algo_name = algo_env;
        if (!algo_name && use_json && json_config.algorithm) {
            algo_name = json_config.algorithm;
        }
        if (!algo_name) {
            algo_name = DEFAULT_ALGORITHM_NAME;
        }

        printf("RA-TLS: Generating new leaf key with algorithm: %s\n", algo_name);

        /* Find algorithm configuration */
        const algorithm_config_t* algo_config = NULL;
        for (size_t i = 0; i < NUM_SUPPORTED_ALGORITHMS; i++) {
            if (strcasecmp(g_supported_algorithms[i].name, algo_name) == 0) {
                algo_config = &g_supported_algorithms[i];
                break;
            }
        }
        if (!algo_config) {
            /* Algorithm not found, use default */
            printf("RA-TLS: Algorithm '%s' not found, using default: %s\n", 
                   algo_name, g_supported_algorithms[0].name);
            algo_config = &g_supported_algorithms[0];
        }

        printf("RA-TLS:   Key type: %s\n", get_pk_type_name(algo_config->pk_type));

        ret = mbedtls_pk_setup(key, mbedtls_pk_info_from_type(algo_config->pk_type));
        if (ret < 0) {
            log_mbedtls_error("PK setup", ret);
            goto out_json;
        }

        /* Generate key based on algorithm type */
        if (algo_config->pk_type == MBEDTLS_PK_ECKEY) {
            printf("RA-TLS:   Generating EC key...\n");
            ret = mbedtls_ecp_gen_key(algo_config->params.ecp_group_id, mbedtls_pk_ec(*key),
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
            if (ret < 0) {
                log_mbedtls_error("EC key generation", ret);
                goto out_json;
            }
        } else if (algo_config->pk_type == MBEDTLS_PK_RSA) {
            printf("RA-TLS:   Generating RSA key (%u bits)...\n", algo_config->params.rsa_key_size);
            ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key), mbedtls_ctr_drbg_random, &ctr_drbg,
                                      algo_config->params.rsa_key_size, 65537);
            if (ret < 0) {
                log_mbedtls_error("RSA key generation", ret);
                goto out_json;
            }
        } else if (algo_config->pk_type == MBEDTLS_PK_OPAQUE) {
            printf("RA-TLS:   Generating ED25519 key using PSA Crypto API...\n");
            
            /* Initialize PSA Crypto */
            psa_status_t psa_status = psa_crypto_init();
            if (psa_status != PSA_SUCCESS) {
                printf("RA-TLS: ERROR: PSA crypto init failed: %d\n", psa_status);
                ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
                goto out_json;
            }
            
            /* Set up key attributes for ED25519 */
            psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
            psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
            psa_set_key_bits(&attributes, 255);  /* ED25519 uses 255-bit keys */
            psa_set_key_algorithm(&attributes, PSA_ALG_PURE_EDDSA);
            psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_EXPORT);
            
            /* Generate the key */
            mbedtls_svc_key_id_t key_id;
            psa_status = psa_generate_key(&attributes, &key_id);
            psa_reset_key_attributes(&attributes);
            
            if (psa_status != PSA_SUCCESS) {
                printf("RA-TLS: ERROR: PSA key generation failed: %d\n", psa_status);
                ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
                goto out_json;
            }
            
            /* Setup the PK context to use the PSA key */
            ret = mbedtls_pk_setup_opaque(key, key_id);
            if (ret < 0) {
                log_mbedtls_error("PK setup opaque for ED25519", ret);
                psa_destroy_key(key_id);
                goto out_json;
            }
            
            printf("RA-TLS:   ED25519 key generated successfully (PSA key ID: %lu)\n", (unsigned long)key_id);
        } else {
            printf("RA-TLS: ERROR: Unsupported key type\n");
            ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
            goto out_json;
        }
        printf("RA-TLS: Leaf key generated successfully\n");
    }

    /* Parse signature MD algorithm (needed before CA cert generation) */
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;  /* default */
    if (use_json && json_config.signature_md) {
        md_type = parse_signature_md(json_config.signature_md);
        printf("RA-TLS: User-specified signature MD algorithm: %s\n", get_md_name(md_type));
    }
    
    /* Handle CA certificate and key if JSON config has ca_key_file or ca_cert_file or ca_subject */
    printf("RA-TLS: ========== CA Certificate Handling ==========\n");
    mbedtls_pk_context ca_key_ctx;
    mbedtls_pk_context* ca_key_ptr = NULL;
    mbedtls_x509_crt* ca_crt_heap = NULL;  /* Heap-allocated to attach to chain */
    mbedtls_x509_crt* ca_crt_ptr = NULL;
    char* ca_subject_from_cert = NULL;
    const char* ca_subject_ptr = NULL;
    bool ca_was_generated = false;  /* Track if CA was generated (not loaded) */
    char* ca_key_file_path = NULL;  /* Path where CA key was written */
    char* ca_cert_file_path = NULL;  /* Path where CA cert was written */
    
    /* Check if CA key file exists */
    bool ca_key_file_exists = false;
    bool ca_cert_file_exists = false;
    
    if (use_json && json_config.ca_key_file) {
        /* Check if CA key file exists */
        int fd = open(json_config.ca_key_file, O_RDONLY);
        if (fd >= 0) {
            ca_key_file_exists = true;
            close(fd);
            printf("RA-TLS: CA key file exists: %s\n", json_config.ca_key_file);
        } else {
            printf("RA-TLS: CA key file does not exist (will be treated as path specification): %s\n", 
                   json_config.ca_key_file);
        }
    }
    
    if (use_json && json_config.ca_cert_file) {
        /* Check if CA cert file exists */
        int fd = open(json_config.ca_cert_file, O_RDONLY);
        if (fd >= 0) {
            ca_cert_file_exists = true;
            close(fd);
            printf("RA-TLS: CA cert file exists: %s\n", json_config.ca_cert_file);
        } else {
            printf("RA-TLS: CA cert file does not exist (will be treated as path specification): %s\n", 
                   json_config.ca_cert_file);
        }
    }
    
    /* Determine if we should use CA logic:
     * - If ca_key_file is set (regardless of whether file exists)
     * - OR if ca_cert_file is set (regardless of whether file exists)
     * - OR if ca_subject is set */
    bool use_ca_logic = (use_json && (json_config.ca_key_file || json_config.ca_cert_file || json_config.ca_subject));
    
    if (use_ca_logic) {
        /* Initialize CA key context and allocate CA cert on heap */
        mbedtls_pk_init(&ca_key_ctx);
        ca_crt_heap = malloc(sizeof(mbedtls_x509_crt));
        if (!ca_crt_heap) {
            ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
            log_mbedtls_error("CA cert allocation", ret);
            goto out_json;
        }
        mbedtls_x509_crt_init(ca_crt_heap);
        
        /* ONLY scenario where we don't regenerate CA cert: both CA key and CA cert files exist */
        bool load_existing_ca = ca_key_file_exists && ca_cert_file_exists;
        
        if (load_existing_ca) {
            printf("RA-TLS: Both CA key and CA cert files exist - loading existing CA\n");
            
            /* Load CA key from file */
            printf("RA-TLS: Loading CA key from file: %s\n", json_config.ca_key_file);
            bool is_pem = !json_config.ca_key_format || strcasecmp(json_config.ca_key_format, "pem") == 0;
            if (is_pem) {
                ret = mbedtls_pk_parse_keyfile(&ca_key_ctx, json_config.ca_key_file, /*password=*/NULL,
                                               mbedtls_ctr_drbg_random, &ctr_drbg);
            } else {
                /* DER format - read file and parse */
                uint8_t ca_key_buf[8192];
                ssize_t ca_key_len = read_file(json_config.ca_key_file, ca_key_buf, sizeof(ca_key_buf));
                if (ca_key_len < 0) {
                    printf("RA-TLS: Failed to read CA key file: %s (errno=%d)\n", json_config.ca_key_file, errno);
                    ret = MBEDTLS_ERR_PK_FILE_IO_ERROR;
                    mbedtls_pk_free(&ca_key_ctx);
                    mbedtls_x509_crt_free(ca_crt_heap);
                    free(ca_crt_heap);
                    ca_crt_heap = NULL;
                    goto out_json;
                }
                ret = mbedtls_pk_parse_key(&ca_key_ctx, ca_key_buf, ca_key_len, /*password=*/NULL, 0,
                                           mbedtls_ctr_drbg_random, &ctr_drbg);
            }
            if (ret < 0) {
                log_mbedtls_error("Load CA key from file", ret);
                mbedtls_pk_free(&ca_key_ctx);
                mbedtls_x509_crt_free(ca_crt_heap);
                free(ca_crt_heap);
                ca_crt_heap = NULL;
                goto out_json;
            }
            
            printf("RA-TLS: CA key loaded successfully, type=%s\n", get_pk_type_name(mbedtls_pk_get_type(&ca_key_ctx)));
            ca_key_ptr = &ca_key_ctx;
            
            /* Load existing CA certificate */
            printf("RA-TLS: Loading existing CA certificate from file: %s\n", json_config.ca_cert_file);
            ret = load_and_verify_ca_certificate(json_config.ca_cert_file, json_config.ca_cert_format,
                                                &ca_key_ctx, ca_crt_heap, &ctr_drbg);
            if (ret < 0) {
                printf("RA-TLS: ERROR: Failed to load/verify CA certificate\n");
                mbedtls_pk_free(&ca_key_ctx);
                mbedtls_x509_crt_free(ca_crt_heap);
                free(ca_crt_heap);
                ca_crt_heap = NULL;
                goto out_json;
            }
            
            ca_crt_ptr = ca_crt_heap;
            ca_was_generated = false;
            
            /* Extract subject from CA certificate */
            char subject_buf[256];
            ret = mbedtls_x509_dn_gets(subject_buf, sizeof(subject_buf), &ca_crt_heap->subject);
            if (ret > 0) {
                ca_subject_from_cert = strdup(subject_buf);
                ca_subject_ptr = ca_subject_from_cert;
                printf("RA-TLS: Using CA subject from certificate: %s\n", ca_subject_ptr);
            } else {
                /* Fallback to JSON ca_subject or default */
                ca_subject_ptr = json_config.ca_subject ? json_config.ca_subject : CERT_SUBJECT_NAME_VALUES;
                printf("RA-TLS: Failed to extract CA subject, using fallback: %s\n", ca_subject_ptr);
            }
        } else {
            /* Need to generate CA certificate - all other cases */
            printf("RA-TLS: Need to generate CA certificate\n");
            
            /* Determine CA subject, not_before, not_after */
            const char* ca_subject_to_use = NULL;
            const char* ca_not_before_to_use = NULL;
            const char* ca_not_after_to_use = NULL;
            
            /* If CA cert file exists (but CA key doesn't), read its info before overwriting */
            if (ca_cert_file_exists && !ca_key_file_exists) {
                printf("RA-TLS: CA cert exists but CA key doesn't - reading existing CA cert info\n");
                mbedtls_x509_crt temp_ca_crt;
                mbedtls_x509_crt_init(&temp_ca_crt);
                
                bool is_pem = !json_config.ca_cert_format || strcasecmp(json_config.ca_cert_format, "pem") == 0;
                int temp_ret;
                if (is_pem) {
                    temp_ret = mbedtls_x509_crt_parse_file(&temp_ca_crt, json_config.ca_cert_file);
                } else {
                    uint8_t temp_cert_buf[8192];
                    ssize_t temp_cert_len = read_file(json_config.ca_cert_file, temp_cert_buf, sizeof(temp_cert_buf));
                    if (temp_cert_len > 0) {
                        temp_ret = mbedtls_x509_crt_parse_der(&temp_ca_crt, temp_cert_buf, temp_cert_len);
                    } else {
                        temp_ret = -1;
                    }
                }
                
                if (temp_ret == 0) {
                    /* Successfully loaded old CA cert - extract info */
                    char subject_buf[256];
                    temp_ret = mbedtls_x509_dn_gets(subject_buf, sizeof(subject_buf), &temp_ca_crt.subject);
                    if (temp_ret > 0) {
                        ca_subject_from_cert = strdup(subject_buf);
                        ca_subject_to_use = ca_subject_from_cert;
                        printf("RA-TLS: Extracted CA subject from existing cert: %s\n", ca_subject_to_use);
                    }
                    
                    /* Extract validity period */
                    char not_before_buf[32];
                    char not_after_buf[32];
                    snprintf(not_before_buf, sizeof(not_before_buf), "%04d%02d%02d%02d%02d%02d",
                            temp_ca_crt.valid_from.year, temp_ca_crt.valid_from.mon, temp_ca_crt.valid_from.day,
                            temp_ca_crt.valid_from.hour, temp_ca_crt.valid_from.min, temp_ca_crt.valid_from.sec);
                    snprintf(not_after_buf, sizeof(not_after_buf), "%04d%02d%02d%02d%02d%02d",
                            temp_ca_crt.valid_to.year, temp_ca_crt.valid_to.mon, temp_ca_crt.valid_to.day,
                            temp_ca_crt.valid_to.hour, temp_ca_crt.valid_to.min, temp_ca_crt.valid_to.sec);
                    
                    /* Allocate and copy validity strings */
                    char* not_before_copy = strdup(not_before_buf);
                    char* not_after_copy = strdup(not_after_buf);
                    if (not_before_copy && not_after_copy) {
                        ca_not_before_to_use = not_before_copy;
                        ca_not_after_to_use = not_after_copy;
                        printf("RA-TLS: Extracted CA validity: %s to %s\n", ca_not_before_to_use, ca_not_after_to_use);
                    }
                } else {
                    printf("RA-TLS: Failed to read existing CA cert, will use defaults\n");
                }
                
                mbedtls_x509_crt_free(&temp_ca_crt);
            }
            
            /* Apply fallbacks for CA subject and validity */
            if (!ca_subject_to_use) {
                ca_subject_to_use = json_config.ca_subject ? json_config.ca_subject : CERT_SUBJECT_NAME_VALUES;
                printf("RA-TLS: Using CA subject: %s\n", ca_subject_to_use);
            }
            if (!ca_not_before_to_use) {
                ca_not_before_to_use = json_config.ca_not_before;
            }
            if (!ca_not_after_to_use) {
                ca_not_after_to_use = json_config.ca_not_after;
            }
            
            ca_subject_ptr = ca_subject_to_use;
            
            /* Determine if we need to load or generate CA key */
            if (ca_key_file_exists) {
                /* Load existing CA key */
                printf("RA-TLS: Loading existing CA key from file: %s\n", json_config.ca_key_file);
                bool is_pem = !json_config.ca_key_format || strcasecmp(json_config.ca_key_format, "pem") == 0;
                if (is_pem) {
                    ret = mbedtls_pk_parse_keyfile(&ca_key_ctx, json_config.ca_key_file, /*password=*/NULL,
                                                   mbedtls_ctr_drbg_random, &ctr_drbg);
                } else {
                    uint8_t ca_key_buf[8192];
                    ssize_t ca_key_len = read_file(json_config.ca_key_file, ca_key_buf, sizeof(ca_key_buf));
                    if (ca_key_len < 0) {
                        printf("RA-TLS: Failed to read CA key file: %s (errno=%d)\n", json_config.ca_key_file, errno);
                        ret = MBEDTLS_ERR_PK_FILE_IO_ERROR;
                        mbedtls_pk_free(&ca_key_ctx);
                        mbedtls_x509_crt_free(ca_crt_heap);
                        free(ca_crt_heap);
                        ca_crt_heap = NULL;
                        goto out_json;
                    }
                    ret = mbedtls_pk_parse_key(&ca_key_ctx, ca_key_buf, ca_key_len, /*password=*/NULL, 0,
                                               mbedtls_ctr_drbg_random, &ctr_drbg);
                }
                if (ret < 0) {
                    log_mbedtls_error("Load CA key from file", ret);
                    mbedtls_pk_free(&ca_key_ctx);
                    mbedtls_x509_crt_free(ca_crt_heap);
                    free(ca_crt_heap);
                    ca_crt_heap = NULL;
                    goto out_json;
                }
                printf("RA-TLS: CA key loaded successfully, type=%s\n", get_pk_type_name(mbedtls_pk_get_type(&ca_key_ctx)));
                ca_key_ptr = &ca_key_ctx;
            } else {
                /* Generate CA key - check if user specified ca_algorithm */
                printf("RA-TLS: Generating new CA key (no ca_key_file exists)\n");
                
                const algorithm_config_t* ca_algo_config = NULL;
                
                /* Check if user specified ca_algorithm in JSON */
                if (json_config.ca_algorithm) {
                    printf("RA-TLS: User specified ca_algorithm: %s\n", json_config.ca_algorithm);
                    
                    /* Find the algorithm configuration */
                    for (size_t i = 0; i < NUM_SUPPORTED_ALGORITHMS; i++) {
                        if (strcasecmp(g_supported_algorithms[i].name, json_config.ca_algorithm) == 0) {
                            ca_algo_config = &g_supported_algorithms[i];
                            break;
                        }
                    }
                    
                    if (!ca_algo_config) {
                        printf("RA-TLS: WARNING: CA algorithm '%s' not found, will use same algorithm as user key\n", 
                               json_config.ca_algorithm);
                    } else {
                        printf("RA-TLS: Using user-specified CA algorithm: %s (type=%s)\n", 
                               ca_algo_config->name, get_pk_type_name(ca_algo_config->pk_type));
                    }
                }
                
                /* If no ca_algorithm specified or not found, use same algorithm as user key */
                if (!ca_algo_config) {
                    printf("RA-TLS: No valid ca_algorithm specified, using same algorithm as user key\n");
                    mbedtls_pk_type_t user_pk_type = mbedtls_pk_get_type(key);
                    printf("RA-TLS: User key type: %s\n", get_pk_type_name(user_pk_type));
                    
                    ret = mbedtls_pk_setup(&ca_key_ctx, mbedtls_pk_info_from_type(user_pk_type));
                    if (ret < 0) {
                        log_mbedtls_error("CA PK setup", ret);
                        mbedtls_pk_free(&ca_key_ctx);
                        mbedtls_x509_crt_free(ca_crt_heap);
                        free(ca_crt_heap);
                        ca_crt_heap = NULL;
                        goto out_json;
                    }
                    
                    /* Generate CA key based on user key algorithm type */
                    if (user_pk_type == MBEDTLS_PK_ECKEY || user_pk_type == MBEDTLS_PK_ECDSA) {
                        /* Get EC curve from user key */
                        mbedtls_ecp_keypair* user_ec = mbedtls_pk_ec(*key);
                        if (!user_ec) {
                            printf("RA-TLS: ERROR: Failed to get EC keypair from user key\n");
                            ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
                            mbedtls_pk_free(&ca_key_ctx);
                            mbedtls_x509_crt_free(ca_crt_heap);
                            free(ca_crt_heap);
                            ca_crt_heap = NULL;
                            goto out_json;
                        }
                        mbedtls_ecp_group_id grp_id = mbedtls_ecp_keypair_get_group_id(user_ec);
                        printf("RA-TLS:   Generating CA EC key with curve ID: %d\n", grp_id);
                        ret = mbedtls_ecp_gen_key(grp_id, mbedtls_pk_ec(ca_key_ctx),
                                                  mbedtls_ctr_drbg_random, &ctr_drbg);
                        if (ret < 0) {
                            log_mbedtls_error("CA EC key generation", ret);
                            mbedtls_pk_free(&ca_key_ctx);
                            mbedtls_x509_crt_free(ca_crt_heap);
                            free(ca_crt_heap);
                            ca_crt_heap = NULL;
                            goto out_json;
                        }
                    } else if (user_pk_type == MBEDTLS_PK_RSA) {
                        /* Get RSA bit length from user key */
                        size_t user_key_bits = mbedtls_pk_get_bitlen(key);
                        printf("RA-TLS:   Generating CA RSA key (%zu bits)\n", user_key_bits);
                        ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(ca_key_ctx), mbedtls_ctr_drbg_random, &ctr_drbg,
                                                  user_key_bits, 65537);
                        if (ret < 0) {
                            log_mbedtls_error("CA RSA key generation", ret);
                            mbedtls_pk_free(&ca_key_ctx);
                            mbedtls_x509_crt_free(ca_crt_heap);
                            free(ca_crt_heap);
                            ca_crt_heap = NULL;
                            goto out_json;
                        }
                    } else if (user_pk_type == MBEDTLS_PK_OPAQUE) {
                        /* Generate ED25519 CA key using PSA Crypto API */
                        printf("RA-TLS:   Generating CA ED25519 key using PSA Crypto API...\n");
                        
                        /* Initialize PSA Crypto */
                        psa_status_t psa_status = psa_crypto_init();
                        if (psa_status != PSA_SUCCESS) {
                            printf("RA-TLS: ERROR: PSA crypto init failed: %d\n", psa_status);
                            ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
                            mbedtls_pk_free(&ca_key_ctx);
                            mbedtls_x509_crt_free(ca_crt_heap);
                            free(ca_crt_heap);
                            ca_crt_heap = NULL;
                            goto out_json;
                        }
                        
                        /* Set up key attributes for ED25519 */
                        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
                        psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
                        psa_set_key_bits(&attributes, 255);  /* ED25519 uses 255-bit keys */
                        psa_set_key_algorithm(&attributes, PSA_ALG_PURE_EDDSA);
                        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_EXPORT);
                        
                        /* Generate the key */
                        mbedtls_svc_key_id_t ca_key_id;
                        psa_status = psa_generate_key(&attributes, &ca_key_id);
                        psa_reset_key_attributes(&attributes);
                        
                        if (psa_status != PSA_SUCCESS) {
                            printf("RA-TLS: ERROR: PSA CA key generation failed: %d\n", psa_status);
                            ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
                            mbedtls_pk_free(&ca_key_ctx);
                            mbedtls_x509_crt_free(ca_crt_heap);
                            free(ca_crt_heap);
                            ca_crt_heap = NULL;
                            goto out_json;
                        }
                        
                        /* Setup the PK context to use the PSA key */
                        ret = mbedtls_pk_setup_opaque(&ca_key_ctx, ca_key_id);
                        if (ret < 0) {
                            log_mbedtls_error("CA PK setup opaque for ED25519", ret);
                            psa_destroy_key(ca_key_id);
                            mbedtls_pk_free(&ca_key_ctx);
                            mbedtls_x509_crt_free(ca_crt_heap);
                            free(ca_crt_heap);
                            ca_crt_heap = NULL;
                            goto out_json;
                        }
                        
                        printf("RA-TLS:   CA ED25519 key generated successfully (PSA key ID: %lu)\n", (unsigned long)ca_key_id);
                    } else {
                        printf("RA-TLS: ERROR: Unsupported user key type for CA key generation\n");
                        ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
                        mbedtls_pk_free(&ca_key_ctx);
                        mbedtls_x509_crt_free(ca_crt_heap);
                        free(ca_crt_heap);
                        ca_crt_heap = NULL;
                        goto out_json;
                    }
                } else {
                    /* Use user-specified ca_algorithm */
                    printf("RA-TLS: Generating CA key with user-specified algorithm: %s\n", ca_algo_config->name);
                    
                    ret = mbedtls_pk_setup(&ca_key_ctx, mbedtls_pk_info_from_type(ca_algo_config->pk_type));
                    if (ret < 0) {
                        log_mbedtls_error("CA PK setup", ret);
                        mbedtls_pk_free(&ca_key_ctx);
                        mbedtls_x509_crt_free(ca_crt_heap);
                        free(ca_crt_heap);
                        ca_crt_heap = NULL;
                        goto out_json;
                    }
                    
                    /* Generate CA key based on specified algorithm type */
                    if (ca_algo_config->pk_type == MBEDTLS_PK_ECKEY) {
                        printf("RA-TLS:   Generating CA EC key with curve ID: %d\n", ca_algo_config->params.ecp_group_id);
                        ret = mbedtls_ecp_gen_key(ca_algo_config->params.ecp_group_id, mbedtls_pk_ec(ca_key_ctx),
                                                  mbedtls_ctr_drbg_random, &ctr_drbg);
                        if (ret < 0) {
                            log_mbedtls_error("CA EC key generation", ret);
                            mbedtls_pk_free(&ca_key_ctx);
                            mbedtls_x509_crt_free(ca_crt_heap);
                            free(ca_crt_heap);
                            ca_crt_heap = NULL;
                            goto out_json;
                        }
                    } else if (ca_algo_config->pk_type == MBEDTLS_PK_RSA) {
                        printf("RA-TLS:   Generating CA RSA key (%u bits)\n", ca_algo_config->params.rsa_key_size);
                        ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(ca_key_ctx), mbedtls_ctr_drbg_random, &ctr_drbg,
                                                  ca_algo_config->params.rsa_key_size, 65537);
                        if (ret < 0) {
                            log_mbedtls_error("CA RSA key generation", ret);
                            mbedtls_pk_free(&ca_key_ctx);
                            mbedtls_x509_crt_free(ca_crt_heap);
                            free(ca_crt_heap);
                            ca_crt_heap = NULL;
                            goto out_json;
                        }
                    } else if (ca_algo_config->pk_type == MBEDTLS_PK_OPAQUE) {
                        /* Generate ED25519 CA key using PSA Crypto API */
                        printf("RA-TLS:   Generating CA ED25519 key using PSA Crypto API...\n");
                        
                        /* Initialize PSA Crypto */
                        psa_status_t psa_status = psa_crypto_init();
                        if (psa_status != PSA_SUCCESS) {
                            printf("RA-TLS: ERROR: PSA crypto init failed: %d\n", psa_status);
                            ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
                            mbedtls_pk_free(&ca_key_ctx);
                            mbedtls_x509_crt_free(ca_crt_heap);
                            free(ca_crt_heap);
                            ca_crt_heap = NULL;
                            goto out_json;
                        }
                        
                        /* Set up key attributes for ED25519 */
                        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
                        psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS));
                        psa_set_key_bits(&attributes, 255);  /* ED25519 uses 255-bit keys */
                        psa_set_key_algorithm(&attributes, PSA_ALG_PURE_EDDSA);
                        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_EXPORT);
                        
                        /* Generate the key */
                        mbedtls_svc_key_id_t ca_key_id;
                        psa_status = psa_generate_key(&attributes, &ca_key_id);
                        psa_reset_key_attributes(&attributes);
                        
                        if (psa_status != PSA_SUCCESS) {
                            printf("RA-TLS: ERROR: PSA CA key generation failed: %d\n", psa_status);
                            ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
                            mbedtls_pk_free(&ca_key_ctx);
                            mbedtls_x509_crt_free(ca_crt_heap);
                            free(ca_crt_heap);
                            ca_crt_heap = NULL;
                            goto out_json;
                        }
                        
                        /* Setup the PK context to use the PSA key */
                        ret = mbedtls_pk_setup_opaque(&ca_key_ctx, ca_key_id);
                        if (ret < 0) {
                            log_mbedtls_error("CA PK setup opaque for ED25519", ret);
                            psa_destroy_key(ca_key_id);
                            mbedtls_pk_free(&ca_key_ctx);
                            mbedtls_x509_crt_free(ca_crt_heap);
                            free(ca_crt_heap);
                            ca_crt_heap = NULL;
                            goto out_json;
                        }
                        
                        printf("RA-TLS:   CA ED25519 key generated successfully (PSA key ID: %lu)\n", (unsigned long)ca_key_id);
                    } else {
                        printf("RA-TLS: ERROR: Unsupported CA algorithm type\n");
                        ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
                        mbedtls_pk_free(&ca_key_ctx);
                        mbedtls_x509_crt_free(ca_crt_heap);
                        free(ca_crt_heap);
                        ca_crt_heap = NULL;
                        goto out_json;
                    }
                }
                
                printf("RA-TLS: CA key generated successfully\n");
                ca_key_ptr = &ca_key_ctx;
                
                /* Write CA private key to file if path is specified */
                if (json_config.ca_key_file) {
                    printf("RA-TLS: Writing generated CA private key to file (PEM format): %s\n", json_config.ca_key_file);
                    ret = write_key_pem(json_config.ca_key_file, &ca_key_ctx);
                    if (ret < 0) {
                        printf("RA-TLS: WARNING: Failed to write CA private key file (continuing anyway)\n");
                    } else {
                        ca_key_file_path = strdup(json_config.ca_key_file);
                    }
                }
            }
            
            /* Generate CA certificate with the CA key (loaded or generated) */
            mbedtls_md_type_t ca_md_type = get_recommended_md_for_key(&ca_key_ctx);
            printf("RA-TLS: Auto-detected signature MD for CA certificate: %s (based on CA key)\n", 
                   get_md_name(ca_md_type));
            
            printf("RA-TLS: Generating CA certificate\n");
            ret = generate_ca_certificate(&ca_key_ctx, ca_crt_heap, ca_subject_to_use,
                                         ca_not_before_to_use, ca_not_after_to_use,
                                         ca_md_type, &ctr_drbg);
            if (ret < 0) {
                printf("RA-TLS: ERROR: Failed to generate CA certificate\n");
                mbedtls_pk_free(&ca_key_ctx);
                mbedtls_x509_crt_free(ca_crt_heap);
                free(ca_crt_heap);
                ca_crt_heap = NULL;
                goto out_json;
            }
            
            ca_crt_ptr = ca_crt_heap;
            ca_was_generated = true;
            
            /* Determine CA cert file path for writing */
            if (json_config.ca_cert_file) {
                ca_cert_file_path = strdup(json_config.ca_cert_file);
            } else if (json_config.ca_key_file) {
                /* Write cert next to CA key file */
                char* ca_key_dir = get_directory_from_path(json_config.ca_key_file);
                const char* ca_key_basename = get_basename_from_path(json_config.ca_key_file);
                
                if (ca_key_dir && ca_key_basename) {
                    char ca_cert_path[1024];
                    snprintf(ca_cert_path, sizeof(ca_cert_path), "%s/crt.%s.crt", 
                            ca_key_dir, ca_key_basename);
                    ca_cert_file_path = strdup(ca_cert_path);
                    free(ca_key_dir);
                } else {
                    ca_cert_file_path = strdup("/tmp/ca.crt");
                }
            } else {
                /* Fallback: write to same directory as user key file */
                char* output_dir = NULL;
                if (json_config.key_file) {
                    output_dir = get_directory_from_path(json_config.key_file);
                } else {
                    output_dir = strdup("/tmp");
                }
                
                char ca_cert_path[1024];
                snprintf(ca_cert_path, sizeof(ca_cert_path), "%s/ca.crt", output_dir);
                ca_cert_file_path = strdup(ca_cert_path);
                free(output_dir);
            }
        }
    } else {
        printf("RA-TLS: No CA key specified, will generate self-signed certificate\n");
        
        /* Auto-detect signature MD based on user key if not specified by user (self-signed case) */
        if (!json_config.signature_md) {
            mbedtls_md_type_t recommended_md = get_recommended_md_for_key(key);
            if (recommended_md != md_type) {
                printf("RA-TLS: Auto-detected signature MD for self-signed leaf key: %s (was %s)\n", 
                       get_md_name(recommended_md), get_md_name(md_type));
                md_type = recommended_md;
            }
        } else {
            /* Validate that user-specified MD is compatible with user key (self-signed case) */
            mbedtls_md_type_t recommended_md = get_recommended_md_for_key(key);
            if (recommended_md != md_type) {
                printf("RA-TLS: WARNING: User-specified signature_md=%s may be incompatible with user key\n",
                       get_md_name(md_type));
                printf("RA-TLS: WARNING: User key type: %s\n", get_pk_type_name(mbedtls_pk_get_type(key)));
                printf("RA-TLS: WARNING: Recommended signature_md for this user key: %s\n", 
                       get_md_name(recommended_md));
                printf("RA-TLS: WARNING: To fix: either remove 'signature_md' from JSON (auto-detect) or set it to '%s'\n",
                       get_md_name(recommended_md));
            }
        }
    }
    printf("RA-TLS: =================================================\n");
    
    /* Get is_ca flag from JSON config (default: false) */
    bool is_ca = use_json && json_config.is_ca;
    
    /* Create RA-TLS certificate (self-signed or CA-signed) */
    const char* subject = (use_json && json_config.subject) ? json_config.subject : NULL;
    const char* not_before = (use_json && json_config.not_before) ? json_config.not_before : NULL;
    const char* not_after = (use_json && json_config.not_after) ? json_config.not_after : NULL;
    
    printf("RA-TLS: ========== Creating RA-TLS Certificate ==========\n");
    printf("RA-TLS: Certificate mode: %s\n", ca_key_ptr ? "CA-signed" : "self-signed");
    printf("RA-TLS: Leaf subject: %s\n", subject ? subject : "(using default)");
    printf("RA-TLS: Leaf not_before: %s\n", not_before ? not_before : "(using default/env)");
    printf("RA-TLS: Leaf not_after: %s\n", not_after ? not_after : "(using default/env)");
    printf("RA-TLS: Leaf is_ca flag: %s\n", is_ca ? "true" : "false");
    printf("RA-TLS: Issuer subject: %s\n", ca_subject_ptr ? ca_subject_ptr : "(same as leaf - self-signed)");
    
    /* Determine signature MD for leaf certificate:
     * - If CA-signed: must use hash algorithm compatible with CA key (issuer determines signature)
     * - If self-signed: use user-specified or auto-detected hash from leaf key */
    mbedtls_md_type_t leaf_md_type = md_type;
    if (ca_key_ptr) {
        leaf_md_type = get_recommended_md_for_key(ca_key_ptr);
        printf("RA-TLS: Leaf signature MD: %s (derived from CA key)\n", get_md_name(leaf_md_type));
    } else {
        printf("RA-TLS: Leaf signature MD: %s (self-signed)\n", get_md_name(leaf_md_type));
    }
    
    ret = create_x509(key, &writecrt, ca_key_ptr, ca_subject_ptr, subject, not_before, not_after, leaf_md_type, is_ca);
    
    free(ca_subject_from_cert);
    
    if (ret < 0) {
        /* On error, clean up CA cert */
        printf("RA-TLS: Failed to create X.509 certificate\n");
        if (ca_crt_heap) {
            mbedtls_x509_crt_free(ca_crt_heap);
            free(ca_crt_heap);
            ca_crt_heap = NULL;
        }
        goto out_json;
    }

    /* Additional diagnostic logging before DER write */
    printf("RA-TLS: ========== Pre-DER-Write Diagnostics ==========\n");
    if (ca_key_ptr) {
        mbedtls_pk_type_t issuer_type = mbedtls_pk_get_type(ca_key_ptr);
        printf("RA-TLS:   Issuer key type (numeric): %d\n", issuer_type);
        printf("RA-TLS:   Issuer key type (string): %s\n", get_pk_type_name(issuer_type));
        printf("RA-TLS:   Issuer can_do ECDSA: %d\n", mbedtls_pk_can_do(ca_key_ptr, MBEDTLS_PK_ECDSA));
    }
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(leaf_md_type);
    printf("RA-TLS:   MD info for leaf_md_type (%d): %s\n", leaf_md_type, md_info ? "valid" : "NULL");
    printf("RA-TLS: =================================================\n");
    
    int size = mbedtls_x509write_crt_der(&writecrt, output_buf, output_buf_size,
                                         mbedtls_ctr_drbg_random, &ctr_drbg);
    if (size < 0) {
        printf("RA-TLS: Failed to write X.509 certificate in DER format\n");
        printf("RA-TLS:   Error code: %d (0x%04x)\n", size, -size);
        log_mbedtls_error("Leaf certificate DER write", size);
        ret = size;
        /* Clean up CA key on error */
        if (ca_key_ptr) {
            mbedtls_pk_free(&ca_key_ctx);
        }
        goto out_json;
    }
    
    /* DER write succeeded, now safe to clean up CA key (but keep ca_crt_heap for chain linking) */
    if (ca_key_ptr) {
        mbedtls_pk_free(&ca_key_ctx);
    }

    /* Write generated CA certificate to file (regardless of crt parameter) */
    if (ca_was_generated && ca_crt_heap && ca_crt_heap->raw.p && ca_crt_heap->raw.len > 0) {
        char ca_path_buf[1024] = {0};
        char ca_path_fallback[1024] = {0};
        
        /* Determine CA certificate file path based on how CA was created */
        if (ca_cert_file_path) {
            /* Case C: CA key was generated, use pre-determined path */
            snprintf(ca_path_buf, sizeof(ca_path_buf), "%s", ca_cert_file_path);
        } else if (use_json && json_config.ca_key_file) {
            /* Case B: CA key was provided, write cert next to CA key file */
            char* ca_key_dir = get_directory_from_path(json_config.ca_key_file);
            const char* ca_key_basename = get_basename_from_path(json_config.ca_key_file);
            
            if (ca_key_dir && ca_key_basename) {
                snprintf(ca_path_buf, sizeof(ca_path_buf), "%s/crt.%s.crt", 
                        ca_key_dir, ca_key_basename);
                snprintf(ca_path_fallback, sizeof(ca_path_fallback), "/tmp/crt.%s.crt", ca_key_basename);
            } else {
                /* Fallback if path parsing fails */
                snprintf(ca_path_buf, sizeof(ca_path_buf), "/tmp/ca.crt");
            }
            
            free(ca_key_dir);
        } else {
            /* Fallback */
            snprintf(ca_path_buf, sizeof(ca_path_buf), "/tmp/ca.crt");
        }
        
        printf("RA-TLS: Writing generated CA certificate to file (PEM format): %s\n", ca_path_buf);
        int write_ret = write_cert_pem(ca_path_buf, ca_crt_heap->raw.p, ca_crt_heap->raw.len);
        if (write_ret < 0 && ca_path_fallback[0] != '\0') {
            /* Try fallback path if primary path failed */
            printf("RA-TLS: Primary path failed, trying fallback: %s\n", ca_path_fallback);
            write_ret = write_cert_pem(ca_path_fallback, ca_crt_heap->raw.p, ca_crt_heap->raw.len);
        }
        
        if (write_ret < 0) {
            printf("RA-TLS: WARNING: Failed to write CA certificate file (continuing anyway)\n");
        } else {
            printf("RA-TLS: CA certificate written successfully\n");
        }
    }

    if (crt_der && crt_der_size) {
        crt_der_buf = malloc(size);
        if (!crt_der_buf) {
            printf("RA-TLS: Failed to allocate memory for DER certificate\n");
            ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
            goto out_json;
        }

        /* note that mbedtls_x509write_crt_der() wrote data at the end of the output_buf */
        memcpy(crt_der_buf, output_buf + output_buf_size - size, size);
        *crt_der      = crt_der_buf;
        *crt_der_size = size;
    }

    if (crt) {
        printf("RA-TLS: Parsing generated X.509 certificate\n");
        ret = mbedtls_x509_crt_parse_der(crt, output_buf + output_buf_size - size, size);
        if (ret < 0) {
            /* On error, clean up CA cert */
            printf("RA-TLS: Failed to parse generated X.509 certificate\n");
            if (ca_crt_heap) {
                mbedtls_x509_crt_free(ca_crt_heap);
                free(ca_crt_heap);
                ca_crt_heap = NULL;
            }
            goto out_json;
        }
        
        /* Form certificate chain by linking CA cert to leaf cert */
        if (ca_crt_ptr) {
            crt->next = ca_crt_heap;
            ca_crt_heap = NULL;  /* Ownership transferred to chain */
        }
    }

    ret = 0;
out_json:
    /* Clean up allocated paths */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
    if (ca_key_file_path)
        free(ca_key_file_path);
    if (ca_cert_file_path)
        free(ca_cert_file_path);
#pragma GCC diagnostic pop
    
    if (use_json) {
        free_cert_config(&json_config);
    }
out:
    if (ret < 0) {
        free(crt_der_buf);
    }
    mbedtls_x509write_crt_free(&writecrt);
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    free(output_buf);
    return ret;
}

int ra_tls_create_key_and_crt(mbedtls_pk_context* key, mbedtls_x509_crt* crt) {
    return create_key_and_crt(key, crt, NULL, NULL);
}

int ra_tls_create_key_and_crt_der(uint8_t** der_key, size_t* der_key_size, uint8_t** der_crt,
                                  size_t* der_crt_size) {
    int ret;

    if (!der_key || !der_key_size || !der_crt || !der_crt_size)
        return -EINVAL;

    mbedtls_pk_context key;
    mbedtls_pk_init(&key);

    uint8_t* der_key_buf   = NULL;
    uint8_t* output_buf    = NULL;
    size_t output_buf_size = 4096; /* enough for any public key in DER format */

    output_buf = malloc(output_buf_size);
    if (!output_buf) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    ret = create_key_and_crt(&key, NULL, der_crt, der_crt_size);
    if (ret < 0) {
        goto out;
    }

    /* populate der_key; note that der_crt was already populated */
    int size = mbedtls_pk_write_key_der(&key, output_buf, output_buf_size);
    if (size < 0) {
        ret = size;
        goto out;
    }

    der_key_buf = malloc(size);
    if (!der_key_buf) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    /* note that mbedtls_pk_write_key_der() wrote data at the end of the output_buf */
    memcpy(der_key_buf, output_buf + output_buf_size - size, size);
    *der_key      = der_key_buf;
    *der_key_size = size;

    ret = 0;
out:
    if (ret < 0) {
        free(der_key_buf);
    }
    mbedtls_pk_free(&key);
    free(output_buf);
    return ret;
}
