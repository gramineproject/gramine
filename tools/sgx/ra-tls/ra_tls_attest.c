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

#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

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
};

#define DEFAULT_ALGORITHM_NAME "secp384r1"
#define NUM_SUPPORTED_ALGORITHMS (sizeof(g_supported_algorithms) / sizeof(g_supported_algorithms[0]))

#define CERT_SUBJECT_NAME_VALUES  "CN=RATLS,O=GramineDevelopers,C=US"
#define CERT_TIMESTAMP_NOT_BEFORE_DEFAULT "20010101000000"
#define CERT_TIMESTAMP_NOT_AFTER_DEFAULT  "20301231235959"

static ssize_t rw_file(const char* path, uint8_t* buf, size_t len, bool do_write) {
    ssize_t bytes = 0;
    ssize_t ret = 0;

    int fd = open(path, do_write ? O_WRONLY : O_RDONLY);
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
    /* CA certificate fields */
    char* ca_key_file;
    char* ca_key_format;  /* "pem" or "der" */
    char* ca_subject;
    char* ca_algorithm;
    char* ca_not_before;
    char* ca_not_after;
    char* ca_signature_md;
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
    /* CA fields */
    json_get_string((const char*)json_buf, tokens, num_tokens, "ca_key_file", &config->ca_key_file);
    json_get_string((const char*)json_buf, tokens, num_tokens, "ca_key_format", &config->ca_key_format);
    json_get_string((const char*)json_buf, tokens, num_tokens, "ca_subject", &config->ca_subject);
    json_get_string((const char*)json_buf, tokens, num_tokens, "ca_algorithm", &config->ca_algorithm);
    json_get_string((const char*)json_buf, tokens, num_tokens, "ca_not_before", &config->ca_not_before);
    json_get_string((const char*)json_buf, tokens, num_tokens, "ca_not_after", &config->ca_not_after);
    json_get_string((const char*)json_buf, tokens, num_tokens, "ca_signature_md", &config->ca_signature_md);

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
    free(config->ca_subject);
    free(config->ca_algorithm);
    free(config->ca_not_before);
    free(config->ca_not_after);
    free(config->ca_signature_md);
}

/* Generate CA certificate path from key file path */
static char* get_ca_cert_path(const char* key_file) {
    if (!key_file)
        return NULL;
    
    /* Find the last '/' to get directory */
    const char* last_slash = strrchr(key_file, '/');
    if (!last_slash) {
        /* No directory, use current directory */
        return strdup("ca.crt");
    }
    
    size_t dir_len = last_slash - key_file + 1;
    char* ca_path = malloc(dir_len + strlen("ca.crt") + 1);
    if (!ca_path)
        return NULL;
    
    memcpy(ca_path, key_file, dir_len);
    strcpy(ca_path + dir_len, "ca.crt");
    return ca_path;
}

/* Generate or load CA key and create CA certificate */
static int generate_ca_cert(mbedtls_pk_context* ca_key, mbedtls_x509_crt* ca_crt,
                            const cert_config_t* config, mbedtls_ctr_drbg_context* ctr_drbg) {
    int ret;
    mbedtls_x509write_cert ca_writecrt;
    mbedtls_mpi serial;
    
    mbedtls_x509write_crt_init(&ca_writecrt);
    mbedtls_mpi_init(&serial);
    
    /* Load or generate CA key */
    if (config->ca_key_file) {
        /* Load CA key from file */
        bool is_pem = !config->ca_key_format || strcasecmp(config->ca_key_format, "pem") == 0;
        if (is_pem) {
            ret = mbedtls_pk_parse_keyfile(ca_key, config->ca_key_file, /*password=*/NULL,
                                           mbedtls_ctr_drbg_random, ctr_drbg);
        } else {
            uint8_t key_buf[8192];
            ssize_t key_len = read_file(config->ca_key_file, key_buf, sizeof(key_buf));
            if (key_len < 0) {
                ret = MBEDTLS_ERR_PK_FILE_IO_ERROR;
                goto out;
            }
            ret = mbedtls_pk_parse_key(ca_key, key_buf, key_len, /*password=*/NULL, 0,
                                       mbedtls_ctr_drbg_random, ctr_drbg);
        }
        if (ret < 0)
            goto out;
    } else {
        /* Generate new CA key */
        const char* ca_algo = config->ca_algorithm ? config->ca_algorithm : DEFAULT_ALGORITHM_NAME;
        const algorithm_config_t* algo_config = NULL;
        
        for (size_t i = 0; i < NUM_SUPPORTED_ALGORITHMS; i++) {
            if (strcasecmp(g_supported_algorithms[i].name, ca_algo) == 0) {
                algo_config = &g_supported_algorithms[i];
                break;
            }
        }
        if (!algo_config) {
            algo_config = &g_supported_algorithms[0];
        }
        
        ret = mbedtls_pk_setup(ca_key, mbedtls_pk_info_from_type(algo_config->pk_type));
        if (ret < 0)
            goto out;
        
        if (algo_config->pk_type == MBEDTLS_PK_ECKEY) {
            ret = mbedtls_ecp_gen_key(algo_config->params.ecp_group_id, mbedtls_pk_ec(*ca_key),
                                      mbedtls_ctr_drbg_random, ctr_drbg);
        } else if (algo_config->pk_type == MBEDTLS_PK_RSA) {
            ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*ca_key), mbedtls_ctr_drbg_random, ctr_drbg,
                                      algo_config->params.rsa_key_size, 65537);
        } else {
            ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
        }
        if (ret < 0)
            goto out;
    }
    
    /* Create CA certificate (self-signed) */
    mbedtls_x509write_crt_set_md_alg(&ca_writecrt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(&ca_writecrt, ca_key);
    mbedtls_x509write_crt_set_issuer_key(&ca_writecrt, ca_key);
    
    const char* ca_subject = config->ca_subject ? config->ca_subject : "CN=RATLS-CA,O=GramineDevelopers,C=US";
    ret = mbedtls_x509write_crt_set_subject_name(&ca_writecrt, ca_subject);
    if (ret < 0)
        goto out;
    
    ret = mbedtls_x509write_crt_set_issuer_name(&ca_writecrt, ca_subject);
    if (ret < 0)
        goto out;
    
    ret = mbedtls_mpi_read_string(&serial, 10, "1");
    if (ret < 0)
        goto out;
    
    ret = mbedtls_x509write_crt_set_serial(&ca_writecrt, &serial);
    if (ret < 0)
        goto out;
    
    const char* ca_not_before = config->ca_not_before ? config->ca_not_before : CERT_TIMESTAMP_NOT_BEFORE_DEFAULT;
    const char* ca_not_after = config->ca_not_after ? config->ca_not_after : CERT_TIMESTAMP_NOT_AFTER_DEFAULT;
    ret = mbedtls_x509write_crt_set_validity(&ca_writecrt, ca_not_before, ca_not_after);
    if (ret < 0)
        goto out;
    
    /* Set CA:TRUE */
    ret = mbedtls_x509write_crt_set_basic_constraints(&ca_writecrt, /*is_ca=*/1, /*max_pathlen=*/-1);
    if (ret < 0)
        goto out;
    
    ret = mbedtls_x509write_crt_set_subject_key_identifier(&ca_writecrt);
    if (ret < 0)
        goto out;
    
    ret = mbedtls_x509write_crt_set_authority_key_identifier(&ca_writecrt);
    if (ret < 0)
        goto out;
    
    /* Write CA certificate to DER and parse it */
    uint8_t ca_der_buf[4096];
    int ca_der_size = mbedtls_x509write_crt_der(&ca_writecrt, ca_der_buf, sizeof(ca_der_buf),
                                                 mbedtls_ctr_drbg_random, ctr_drbg);
    if (ca_der_size < 0) {
        ret = ca_der_size;
        goto out;
    }
    
    ret = mbedtls_x509_crt_parse_der(ca_crt, ca_der_buf + sizeof(ca_der_buf) - ca_der_size, ca_der_size);
    if (ret < 0)
        goto out;
    
    /* Write CA certificate to file */
    char* ca_cert_path = get_ca_cert_path(config->key_file);
    if (ca_cert_path) {
        /* Convert DER to PEM */
        size_t pem_len = 0;
        ret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n",
                                       "-----END CERTIFICATE-----\n",
                                       ca_der_buf + sizeof(ca_der_buf) - ca_der_size,
                                       ca_der_size, NULL, 0, &pem_len);
        if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
            uint8_t* pem_buf = malloc(pem_len);
            if (pem_buf) {
                ret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n",
                                               "-----END CERTIFICATE-----\n",
                                               ca_der_buf + sizeof(ca_der_buf) - ca_der_size,
                                               ca_der_size, pem_buf, pem_len, &pem_len);
                if (ret == 0) {
                    write_file(ca_cert_path, pem_buf, pem_len - 1); /* -1 to exclude null terminator */
                }
                free(pem_buf);
            }
        }
        free(ca_cert_path);
    }
    
    ret = 0;
out:
    mbedtls_mpi_free(&serial);
    mbedtls_x509write_crt_free(&ca_writecrt);
    return ret;
}

/*! given public key \p pk, generate an RA-TLS certificate \p writecrt with \p quote (legacy format)
 *  and \p evidence (new standard format) embedded */
static int generate_x509(mbedtls_pk_context* pk, const uint8_t* quote, size_t quote_size,
                         const uint8_t* evidence, size_t evidence_size,
                         mbedtls_x509write_cert* writecrt,
                         mbedtls_pk_context* ca_key, const char* ca_subject_name,
                         const char* subject_name, const char* not_before, const char* not_after) {
    int ret;
    char* cert_timestamp_not_before = NULL;
    char* cert_timestamp_not_after  = NULL;

    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);

    mbedtls_x509write_crt_init(writecrt);
    mbedtls_x509write_crt_set_md_alg(writecrt, MBEDTLS_MD_SHA256);

    /* Set subject key (always the RA-TLS key) */
    mbedtls_x509write_crt_set_subject_key(writecrt, pk);
    
    /* Set issuer key: CA key if provided, otherwise self-signed */
    if (ca_key) {
        mbedtls_x509write_crt_set_issuer_key(writecrt, ca_key);
    } else {
        mbedtls_x509write_crt_set_issuer_key(writecrt, pk);
    }

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

    ret = mbedtls_x509write_crt_set_basic_constraints(writecrt, /*is_ca=*/0, /*max_pathlen=*/-1);
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

/*! given public key \p pk, generate an RA-TLS certificate \p writecrt */
static int create_x509(mbedtls_pk_context* pk, mbedtls_x509write_cert* writecrt,
                       mbedtls_pk_context* ca_key, const char* ca_subject,
                       const char* subject, const char* not_before, const char* not_after) {
    int ret;

    /*
     * We put both "legacy Gramine" OID with plain SGX quote as well as standardized TCG DICE "tagged
     * evidence" OID with CBOR-formatted SGX quote into the RA-TLS X.509 cert. This is for keeping
     * backward compatibility at the price of a larger size of the resulting cert.
     */
    uint8_t* quote = NULL;
    uint8_t* evidence = NULL;

    /* TODO: this legacy OID with plain SGX quote should be removed at some point */
    size_t quote_size;
    ret = generate_quote_with_pk_hash(pk, &quote, &quote_size);
    if (ret < 0)
        goto out;

    size_t evidence_size;
    ret = generate_tcg_dice_tagged_evidence(pk, &evidence, &evidence_size);
    if (ret < 0)
        goto out;

    /* TODO: currently, the Endorsement extension is not implemented (contains TCB info, CRL, etc.);
     *       should be added in the future */

    ret = generate_x509(pk, quote, quote_size, evidence, evidence_size, writecrt,
                       ca_key, ca_subject, subject, not_before, not_after);
out:
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

    if (!algo_env && config_b64) {
        /* Parse JSON configuration if algorithm not specified */
        ret = parse_json_config(config_b64, &json_config);
        if (ret == 0) {
            use_json = true;
        }
    }

    /* Load or generate key */
    if (use_json && json_config.key_file) {
        /* Load private key from file specified in JSON */
        bool is_pem = !json_config.key_format || strcasecmp(json_config.key_format, "pem") == 0;
        
        if (is_pem) {
            ret = mbedtls_pk_parse_keyfile(key, json_config.key_file, /*password=*/NULL,
                                           mbedtls_ctr_drbg_random, &ctr_drbg);
        } else {
            /* DER format - read file and parse */
            uint8_t key_buf[8192];
            ssize_t key_len = read_file(json_config.key_file, key_buf, sizeof(key_buf));
            if (key_len < 0) {
                ret = MBEDTLS_ERR_PK_FILE_IO_ERROR;
                goto out_json;
            }
            ret = mbedtls_pk_parse_key(key, key_buf, key_len, /*password=*/NULL, 0,
                                       mbedtls_ctr_drbg_random, &ctr_drbg);
        }
        if (ret < 0)
            goto out_json;
    } else {
        /* Generate new key based on algorithm */
        const char* algo_name = algo_env;
        if (!algo_name && use_json && json_config.algorithm) {
            algo_name = json_config.algorithm;
        }
        if (!algo_name) {
            algo_name = DEFAULT_ALGORITHM_NAME;
        }

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
            algo_config = &g_supported_algorithms[0];
        }

        ret = mbedtls_pk_setup(key, mbedtls_pk_info_from_type(algo_config->pk_type));
        if (ret < 0)
            goto out_json;

        /* Generate key based on algorithm type */
        if (algo_config->pk_type == MBEDTLS_PK_ECKEY) {
            ret = mbedtls_ecp_gen_key(algo_config->params.ecp_group_id, mbedtls_pk_ec(*key),
                                      mbedtls_ctr_drbg_random, &ctr_drbg);
            if (ret < 0)
                goto out_json;
        } else if (algo_config->pk_type == MBEDTLS_PK_RSA) {
            ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key), mbedtls_ctr_drbg_random, &ctr_drbg,
                                      algo_config->params.rsa_key_size, 65537);
            if (ret < 0)
                goto out_json;
        } else {
            ret = MBEDTLS_ERR_PK_BAD_INPUT_DATA;
            goto out_json;
        }
    }

    /* Generate CA certificate if JSON config has key_file */
    mbedtls_pk_context ca_key_ctx;
    mbedtls_x509_crt ca_crt_ctx;
    mbedtls_pk_context* ca_key_ptr = NULL;
    const char* ca_subject_ptr = NULL;
    
    if (use_json && json_config.key_file) {
        /* Initialize CA structures */
        mbedtls_pk_init(&ca_key_ctx);
        mbedtls_x509_crt_init(&ca_crt_ctx);
        
        /* Generate or load CA certificate */
        ret = generate_ca_cert(&ca_key_ctx, &ca_crt_ctx, &json_config, &ctr_drbg);
        if (ret < 0) {
            mbedtls_pk_free(&ca_key_ctx);
            mbedtls_x509_crt_free(&ca_crt_ctx);
            goto out_json;
        }
        
        ca_key_ptr = &ca_key_ctx;
        ca_subject_ptr = json_config.ca_subject ? json_config.ca_subject : "CN=RATLS-CA,O=GramineDevelopers,C=US";
    }
    
    /* Create RA-TLS certificate (self-signed or CA-signed) */
    const char* subject = (use_json && json_config.subject) ? json_config.subject : NULL;
    const char* not_before = (use_json && json_config.not_before) ? json_config.not_before : NULL;
    const char* not_after = (use_json && json_config.not_after) ? json_config.not_after : NULL;
    
    ret = create_x509(key, &writecrt, ca_key_ptr, ca_subject_ptr, subject, not_before, not_after);
    
    /* Clean up CA structures if used */
    if (ca_key_ptr) {
        mbedtls_pk_free(&ca_key_ctx);
        mbedtls_x509_crt_free(&ca_crt_ctx);
    }
    
    if (ret < 0)
        goto out_json;

    int size = mbedtls_x509write_crt_der(&writecrt, output_buf, output_buf_size,
                                         mbedtls_ctr_drbg_random, &ctr_drbg);
    if (size < 0) {
        ret = size;
        goto out_json;
    }

    if (crt_der && crt_der_size) {
        crt_der_buf = malloc(size);
        if (!crt_der_buf) {
            ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
            goto out_json;
        }

        /* note that mbedtls_x509write_crt_der() wrote data at the end of the output_buf */
        memcpy(crt_der_buf, output_buf + output_buf_size - size, size);
        *crt_der      = crt_der_buf;
        *crt_der_size = size;
    }

    if (crt) {
        ret = mbedtls_x509_crt_parse_der(crt, output_buf + output_buf_size - size, size);
        if (ret < 0)
            goto out_json;
    }

    ret = 0;
out_json:
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
