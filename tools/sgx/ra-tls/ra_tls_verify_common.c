/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

/*!
 * \file
 *
 * This file contains the common code of verification callbacks for TLS libraries. All functions
 * here are internal (not accessible from outside the shared library).
 */

#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

#include "quote.h"
#include "util.h"

#include "ra_tls.h"
#include "ra_tls_common.h"

verify_measurements_cb_t g_verify_measurements_cb = NULL;

static char* getenv_critical(const char* name) {
    char* value = getenv(name);
    if (!value) {
        INFO("WARNING: The default enclave verification hook is being used, but %s is not set. "
             "This is deprecated and will become an error in the future. "
             "If you wish to accept any value, please specify %s=any explicitly.\n",
             name, name);
    }

    if (value && strcmp(value, "any") == 0) {
        value = NULL;
    }

    return value;
}

static int getenv_enclave_measurements(sgx_measurement_t* mrsigner, bool* validate_mrsigner,
                                       sgx_measurement_t* mrenclave, bool* validate_mrenclave,
                                       sgx_prod_id_t* isv_prod_id, bool* validate_isv_prod_id,
                                       sgx_isv_svn_t* isv_svn, bool* validate_isv_svn) {
    *validate_mrsigner    = false;
    *validate_mrenclave   = false;
    *validate_isv_prod_id = false;
    *validate_isv_svn     = false;

    const char* mrsigner_hex;
    const char* mrenclave_hex;
    const char* isv_prod_id_dec;
    const char* isv_svn_dec;

    /* any of the below variables may be NULL (and then not used in validation) */
    mrsigner_hex = getenv_critical(RA_TLS_MRSIGNER);
    if (mrsigner_hex) {
        if (parse_hex(mrsigner_hex, mrsigner, sizeof(*mrsigner), NULL) != 0)
            return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        *validate_mrsigner = true;
    }

    mrenclave_hex = getenv_critical(RA_TLS_MRENCLAVE);
    if (mrenclave_hex) {
        if (parse_hex(mrenclave_hex, mrenclave, sizeof(*mrenclave), NULL) != 0)
            return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        *validate_mrenclave = true;
    }

    isv_prod_id_dec = getenv_critical(RA_TLS_ISV_PROD_ID);
    if (isv_prod_id_dec) {
        errno = 0;
        *isv_prod_id = strtoul(isv_prod_id_dec, NULL, 10);
        if (errno)
            return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        *validate_isv_prod_id = true;
    }

    isv_svn_dec = getenv_critical(RA_TLS_ISV_SVN);
    if (isv_svn_dec) {
        errno = 0;
        *isv_svn = strtoul(isv_svn_dec, NULL, 10);
        if (errno)
            return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        *validate_isv_svn = true;
    }

    if (!*validate_mrsigner && !*validate_mrenclave) {
        INFO("WARNING: Neither " RA_TLS_MRSIGNER " nor " RA_TLS_MRENCLAVE " are specified. "
             "This will accept any enclave and provides no security whatsoever.\n");
    }

    return 0;
}

bool getenv_allow_outdated_tcb(void) {
    char* str = getenv(RA_TLS_ALLOW_OUTDATED_TCB_INSECURE);
    return (str && !strcmp(str, "1"));
}

bool getenv_allow_debug_enclave(void) {
    char* str = getenv(RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE);
    return (str && !strcmp(str, "1"));
}

/*! searches for specific \p oid among \p exts and returns pointer to its value in \p out_val;
 *  tailored for SGX quotes with size strictly from 128 to 65535 bytes (fails on other sizes) */
static int find_oid(const uint8_t* exts, size_t exts_size, const uint8_t* oid, size_t oid_size,
                    uint8_t** out_val, size_t* out_size) {
    /* TODO: searching with memmem is not robust (what if some extension contains exactly these
     *       chars?), but mbedTLS has nothing generic enough for our purposes; this is still
     *       secure because this func is used for extracting the SGX quote which is verified
     *       later, but may lead to unexpected failures (hardly possible in real world though) */
    uint8_t* p = memmem(exts, exts_size, oid, oid_size);
    if (!p)
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

    const uint8_t* exts_end = exts + exts_size;

    /* move pointer past OID string and to the OID value (which is encoded in ASN.1 DER) */
    p += oid_size;

    if (p >= exts_end)
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

    if (*p == 0x01) {
        /* some TLS libs generate a BOOLEAN (ASN.1 tag 1) for the criticality of the extension
         * before the extension value itself; check its value and skip it */
        p++;
        if (p >= exts_end || *p++ != 0x01) {
            /* BOOLEAN length must be 0x01 */
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }
        if (p >= exts_end || *p++ != 0x00) {
            /* BOOLEAN value must be 0x00 (non-critical extension) */
            return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        }
    }

    /* now comes the octet string containing the SGX quote (ASN.1 tag 4) */
    if (p >= exts_end || *p++ != 0x04) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }
    if (p >= exts_end || *p++ != 0x82) {
        /* length of octet string must be 0x82 = 0b10000010 (the long form, with bit 8 set and bits
         * 7-0 indicating how many more bytes are in the length field); SGX quotes always have
         * lengths of 128 to 65535 bytes, so length must be encoded in exactly two bytes */
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }
    static_assert(sizeof(sgx_quote_t) >= 128, "need to change ASN.1 length-of-octet-string limit");
    static_assert(SGX_QUOTE_MAX_SIZE <= 65535, "need to change ASN.1 length-of-octet-string limit");

    if (p + 2 > exts_end)
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

    size_t val_size;
    val_size = *p++;
    val_size <<= 8;
    val_size += *p++;

    uint8_t* val = p;

    assert(val <= exts_end);
    if (val_size < 128 || val_size > SGX_QUOTE_MAX_SIZE || val_size > (size_t)(exts_end - val))
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

    *out_size = val_size;
    *out_val  = val;
    return 0;
}

/*! calculate sha256 over public key from \p crt and copy it into \p sha */
static int sha256_over_crt_pk(mbedtls_x509_crt* crt, uint8_t* sha) {
    mbedtls_ecp_keypair* key = mbedtls_pk_ec(crt->pk);
    if (key == NULL || key->MBEDTLS_PRIVATE(grp).id != MBEDTLS_ECP_DP_SECP384R1) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    uint8_t pk_der[PUB_KEY_SIZE_MAX] = {0};

    /* below function writes data at the end of the buffer */
    int pk_der_size_byte = mbedtls_pk_write_pubkey_der(&crt->pk, pk_der, sizeof(pk_der));
    if (pk_der_size_byte < 0)
        return pk_der_size_byte;

    /* move the data to the beginning of the buffer, to avoid pointer arithmetic later */
    memmove(pk_der, pk_der + PUB_KEY_SIZE_MAX - pk_der_size_byte, pk_der_size_byte);

    return mbedtls_sha256(pk_der, pk_der_size_byte, sha, /*is224=*/0);
}

/*! compares if report_data from \quote corresponds to sha256 of public key in \p crt */
int cmp_crt_pk_against_quote_report_data(mbedtls_x509_crt* crt, sgx_quote_t* quote) {
    int ret;

    uint8_t sha[SHA256_DIGEST_SIZE];
    ret = sha256_over_crt_pk(crt, sha);
    if (ret < 0)
        return ret;

    ret = memcmp(quote->body.report_body.report_data.d, sha, SHA256_DIGEST_SIZE);
    if (ret)
        return MBEDTLS_ERR_X509_SIG_MISMATCH;

    return 0;
}

int extract_quote_and_verify_pubkey(mbedtls_x509_crt* crt, sgx_quote_t** out_quote,
                                    size_t* out_quote_size) {
    sgx_quote_t* quote;
    size_t quote_size;
    int ret = find_oid(crt->v3_ext.p, crt->v3_ext.len, g_quote_oid, g_quote_oid_size,
                       (uint8_t**)&quote, &quote_size);
    if (ret < 0)
        return ret;

    if (quote_size < sizeof(*quote))
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

    /* currently only one check: public key's hash from cert must match SGX quote's report_data */
    ret = cmp_crt_pk_against_quote_report_data(crt, quote);
    if (ret < 0)
        return ret;

    *out_quote = quote;
    *out_quote_size = quote_size;
    return 0;
}

void ra_tls_set_measurement_callback(int (*f_cb)(const char* mrenclave, const char* mrsigner,
                                                 const char* isv_prod_id, const char* isv_svn)) {
    g_verify_measurements_cb = f_cb;
}

int ra_tls_verify_callback_der(uint8_t* der_crt, size_t der_crt_size) {
    int ret;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);

    ret = mbedtls_x509_crt_parse(&crt, der_crt, der_crt_size);
    if (ret < 0)
        goto out;

    ret = ra_tls_verify_callback(/*unused data=*/NULL, &crt, /*depth=*/0, /*flags=*/NULL);
    if (ret < 0)
        goto out;

    ret = 0;
out:
    mbedtls_x509_crt_free(&crt);
    return ret;
}

int verify_quote_body_against_envvar_measurements(const sgx_quote_body_t* quote_body) {
    int ret;

    sgx_measurement_t expected_mrsigner;
    sgx_measurement_t expected_mrenclave;
    sgx_prod_id_t expected_isv_prod_id;
    sgx_isv_svn_t expected_isv_svn;

    bool validate_mrsigner    = false;
    bool validate_mrenclave   = false;
    bool validate_isv_prod_id = false;
    bool validate_isv_svn     = false;

    ret = getenv_enclave_measurements(&expected_mrsigner, &validate_mrsigner,
                                      &expected_mrenclave, &validate_mrenclave,
                                      &expected_isv_prod_id, &validate_isv_prod_id,
                                      &expected_isv_svn, &validate_isv_svn);
    if (ret < 0)
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;

    ret = verify_quote_body(quote_body, validate_mrsigner ? (char*)&expected_mrsigner : NULL,
                            validate_mrenclave ? (char*)&expected_mrenclave : NULL,
                            validate_isv_prod_id ? (char*)&expected_isv_prod_id : NULL,
                            validate_isv_svn ? (char*)&expected_isv_svn : NULL,
                            /*report_data=*/NULL, /*expected_as_str=*/false);
    if (ret < 0)
        return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;

    return 0;
}
