/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

/*!
 * \file
 *
 * This file contains the implementation of server-side attestation for TLS libraries. It contains
 * functions to create a self-signed RA-TLS certificate with an SGX quote embedded in it. It works
 * with both EPID-based (quote v2) and ECDSA-based (quote v3 or DCAP) SGX quotes (in fact, it is
 * agnostic to the format of the SGX quote).
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

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

#include "ra_tls.h"
#include "ra_tls_common.h"

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

/*! given public key \p pk, generate an RA-TLS certificate \p writecrt with \p quote (legacy format)
 *  and \p evidence (new standard format) embedded */
static int generate_x509(mbedtls_pk_context* pk, const uint8_t* quote, size_t quote_size,
                         const uint8_t* evidence, size_t evidence_size,
                         mbedtls_x509write_cert* writecrt) {
    int ret;
    char* cert_timestamp_not_before = NULL;
    char* cert_timestamp_not_after  = NULL;

    mbedtls_mpi serial;
    mbedtls_mpi_init(&serial);

    mbedtls_x509write_crt_init(writecrt);
    mbedtls_x509write_crt_set_md_alg(writecrt, MBEDTLS_MD_SHA256);

    /* generated certificate is self-signed, so declares itself both a subject and an issuer */
    mbedtls_x509write_crt_set_subject_key(writecrt, pk);
    mbedtls_x509write_crt_set_issuer_key(writecrt, pk);

    /* set (dummy) subject names for both subject and issuer */
    ret = mbedtls_x509write_crt_set_subject_name(writecrt, CERT_SUBJECT_NAME_VALUES);
    if (ret < 0)
        goto out;

    ret = mbedtls_x509write_crt_set_issuer_name(writecrt, CERT_SUBJECT_NAME_VALUES);
    if (ret < 0)
        goto out;

    /* set a serial number (dummy "1") for the generated certificate */
    ret = mbedtls_mpi_read_string(&serial, 10, "1");
    if (ret < 0)
        goto out;

    ret = mbedtls_x509write_crt_set_serial(writecrt, &serial);
    if (ret < 0)
        goto out;

    cert_timestamp_not_before = strdup(getenv(RA_TLS_CERT_TIMESTAMP_NOT_BEFORE) ? :
                                       CERT_TIMESTAMP_NOT_BEFORE_DEFAULT);
    if (!cert_timestamp_not_before) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    cert_timestamp_not_after = strdup(getenv(RA_TLS_CERT_TIMESTAMP_NOT_AFTER) ? :
                                      CERT_TIMESTAMP_NOT_AFTER_DEFAULT);
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
static int create_x509(mbedtls_pk_context* pk, mbedtls_x509write_cert* writecrt) {
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

    ret = generate_x509(pk, quote, quote_size, evidence, evidence_size, writecrt);
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

    ret = mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret < 0)
        goto out;

    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP384R1, mbedtls_pk_ec(*key), mbedtls_ctr_drbg_random,
                              &ctr_drbg);
    if (ret < 0)
        goto out;

    ret = create_x509(key, &writecrt);
    if (ret < 0)
        goto out;

    int size = mbedtls_x509write_crt_der(&writecrt, output_buf, output_buf_size,
                                         mbedtls_ctr_drbg_random, &ctr_drbg);
    if (size < 0) {
        ret = size;
        goto out;
    }

    if (crt_der && crt_der_size) {
        crt_der_buf = malloc(size);
        if (!crt_der_buf) {
            ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
            goto out;
        }

        /* note that mbedtls_x509write_crt_der() wrote data at the end of the output_buf */
        memcpy(crt_der_buf, output_buf + output_buf_size - size, size);
        *crt_der      = crt_der_buf;
        *crt_der_size = size;
    }

    if (crt) {
        ret = mbedtls_x509_crt_parse_der(crt, output_buf + output_buf_size - size, size);
        if (ret < 0)
            goto out;
    }

    ret = 0;
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
