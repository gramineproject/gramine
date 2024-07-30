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

#include <cbor.h>

#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/x509_crt.h>

#include "quote.h"
#include "util.h"

#include "ra_tls.h"
#include "ra_tls_common.h"

verify_measurements_cb_t g_verify_measurements_cb = NULL;

static bool getenv_critical(const char* name, const char** out_value) {
    const char* value = getenv(name);
    if (!value) {
        ERROR("ERROR: A required environment variable %s is not set.\n", name);
        return false;
    }

    if (strcmp(value, "any") == 0) {
        value = NULL;
    }

    *out_value = value;
    return true;
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
    if (!getenv_critical(RA_TLS_MRSIGNER, &mrsigner_hex))
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    if (mrsigner_hex) {
        if (parse_hex(mrsigner_hex, mrsigner, sizeof(*mrsigner), NULL) != 0)
            return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        *validate_mrsigner = true;
    }

    if (!getenv_critical(RA_TLS_MRENCLAVE, &mrenclave_hex))
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    if (mrenclave_hex) {
        if (parse_hex(mrenclave_hex, mrenclave, sizeof(*mrenclave), NULL) != 0)
            return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        *validate_mrenclave = true;
    }

    if (!getenv_critical(RA_TLS_ISV_PROD_ID, &isv_prod_id_dec))
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
    if (isv_prod_id_dec) {
        errno = 0;
        *isv_prod_id = strtoul(isv_prod_id_dec, NULL, 10);
        if (errno)
            return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
        *validate_isv_prod_id = true;
    }

    if (!getenv_critical(RA_TLS_ISV_SVN, &isv_svn_dec))
        return MBEDTLS_ERR_X509_BAD_INPUT_DATA;
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
    return str && !strcmp(str, "1");
}

bool getenv_allow_hw_config_needed(void) {
    char* str = getenv(RA_TLS_ALLOW_HW_CONFIG_NEEDED);
    return str && !strcmp(str, "1");
}

bool getenv_allow_sw_hardening_needed(void) {
    char* str = getenv(RA_TLS_ALLOW_SW_HARDENING_NEEDED);
    return str && !strcmp(str, "1");
}

bool getenv_allow_debug_enclave(void) {
    char* str = getenv(RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE);
    return str && !strcmp(str, "1");
}

/*! searches for specific \p oid among \p exts and returns pointer to its value in \p out_val;
 *  tailored for SGX quotes with size strictly from 128 to 65535 bytes (fails on other sizes) */
int find_oid_in_cert_extensions(const uint8_t* exts, size_t exts_size, const uint8_t* oid,
                                size_t oid_size, uint8_t** out_val, size_t* out_size) {
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

/*! fill buffer \p pk_der with DER-formatted public key from \p crt */
static int fill_crt_pk_der(mbedtls_x509_crt* crt, uint8_t* pk_der, size_t* inout_pk_der_size) {
    if (mbedtls_pk_get_type(&crt->pk) != MBEDTLS_PK_ECKEY)
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;

    mbedtls_ecp_keypair* key = mbedtls_pk_ec(crt->pk);
    if (key == NULL ||
            (key->MBEDTLS_PRIVATE(grp).id != MBEDTLS_ECP_DP_SECP384R1
                && key->MBEDTLS_PRIVATE(grp).id != MBEDTLS_ECP_DP_SECP256R1)) {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    /* below function writes data at the end of the buffer */
    int pk_der_size_int = mbedtls_pk_write_pubkey_der(&crt->pk, pk_der, *inout_pk_der_size);
    if (pk_der_size_int < 0)
        return pk_der_size_int;

    /* move the data to the beginning of the buffer, to avoid pointer arithmetic later */
    memmove(pk_der, pk_der + *inout_pk_der_size - pk_der_size_int, pk_der_size_int);
    *inout_pk_der_size = (size_t)pk_der_size_int;
    return 0;
}

/*! compares if report_data from \p quote corresponds to sha256 of public key in \p crt */
int cmp_crt_pk_against_quote_report_data(mbedtls_x509_crt* crt, sgx_quote_t* quote) {
    uint8_t pk_der[PUB_KEY_SIZE_MAX] = {0};
    size_t pk_der_size = sizeof(pk_der);
    int ret = fill_crt_pk_der(crt, pk_der, &pk_der_size);
    if (ret < 0)
        return ret;

    uint8_t sha[SHA256_DIGEST_SIZE];
    ret = mbedtls_sha256(pk_der, pk_der_size, sha, /*is224=*/0);
    if (ret < 0)
        return ret;

    ret = memcmp(quote->body.report_body.report_data.d, sha, SHA256_DIGEST_SIZE);
    if (ret)
        return MBEDTLS_ERR_X509_SIG_MISMATCH;

    return 0;
}

/*! compares if CBOR array \p cbor_hash_entry from claims corresponds to public key in \p crt */
static int cmp_crt_pk_against_cbor_claim_hash_entry(mbedtls_x509_crt* crt,
                                                    cbor_item_t* cbor_hash_entry) {
    uint8_t pk_der[PUB_KEY_SIZE_MAX] = {0};
    size_t pk_der_size = sizeof(pk_der);
    int ret = fill_crt_pk_der(crt, pk_der, &pk_der_size);
    if (ret < 0)
        return ret;

    if (!cbor_isa_array(cbor_hash_entry) || !cbor_array_is_definite(cbor_hash_entry)
            || cbor_array_size(cbor_hash_entry) != 2) {
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
    }

    cbor_item_t* cbor_hash_alg_id = NULL;
    cbor_item_t* cbor_hash_value  = NULL;

    cbor_hash_alg_id = cbor_array_get(cbor_hash_entry, /*index=*/0);
    if (!cbor_hash_alg_id || !cbor_isa_uint(cbor_hash_alg_id)) {
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }

    cbor_hash_value = cbor_array_get(cbor_hash_entry, /*index=*/1);
    if (!cbor_hash_value || !cbor_isa_bytestring(cbor_hash_value)
            || !cbor_bytestring_is_definite(cbor_hash_value)) {
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }

    uint8_t sha[SHA512_DIGEST_SIZE]; /* enough to hold SHA-256, -384, or -512 */
    size_t sha_size;

    uint64_t hash_alg_id;
    switch (cbor_int_get_width(cbor_hash_alg_id)) {
        case CBOR_INT_8:  hash_alg_id = cbor_get_uint8(cbor_hash_alg_id); break;
        case CBOR_INT_16: hash_alg_id = cbor_get_uint16(cbor_hash_alg_id); break;
        case CBOR_INT_32: hash_alg_id = cbor_get_uint32(cbor_hash_alg_id); break;
        case CBOR_INT_64: hash_alg_id = cbor_get_uint64(cbor_hash_alg_id); break;
        default:          ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS; goto out;
    }

    switch (hash_alg_id) {
        case IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA256:
            sha_size = SHA256_DIGEST_SIZE;
            break;
        case IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA384:
            sha_size = SHA384_DIGEST_SIZE;
            break;
        case IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA512:
            sha_size = SHA512_DIGEST_SIZE;
            break;
        default:
            ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
            goto out;
    }

    if (cbor_bytestring_length(cbor_hash_value) != sha_size) {
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }

    switch (hash_alg_id) {
        case IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA256:
            ret = mbedtls_sha256(pk_der, pk_der_size, sha, /*is224=*/0);
            break;
        case IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA384:
            ret = mbedtls_sha512(pk_der, pk_der_size, sha, /*is384=*/1);
            break;
        case IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA512:
            ret = mbedtls_sha512(pk_der, pk_der_size, sha, /*is384=*/0);
            break;
    }

    if (ret < 0)
        goto out;

    ret = memcmp(cbor_bytestring_handle(cbor_hash_value), sha, sha_size);
    if (ret) {
        ret = MBEDTLS_ERR_X509_SIG_MISMATCH;
        goto out;
    }

    ret = 0;
out:
    if (cbor_hash_alg_id)
        cbor_decref(&cbor_hash_alg_id);
    if (cbor_hash_value)
        cbor_decref(&cbor_hash_value);
    return ret;
}

static int extract_standard_quote_and_verify_claims(mbedtls_x509_crt* crt, bool* out_found_oid,
                                                    sgx_quote_t** out_quote,
                                                    size_t* out_quote_size) {
    /* for description of evidence format, see ra_tls_attest.c:generate_evidence_with_claims() */
    cbor_item_t* cbor_tagged_evidence = NULL;
    cbor_item_t* cbor_evidence = NULL;
    cbor_item_t* cbor_quote = NULL;
    cbor_item_t* cbor_claims = NULL; /* serialized CBOR map of claims (as bytestring) */
    cbor_item_t* cbor_claims_map = NULL;
    cbor_item_t* cbor_hash_entry = NULL;
    sgx_quote_t* quote = NULL;

    uint8_t* evidence_buf;
    size_t evidence_buf_size;
    int ret = find_oid_in_cert_extensions(crt->v3_ext.p, crt->v3_ext.len, g_ratls_evidence_oid_raw,
                                          sizeof(g_ratls_evidence_oid_raw), &evidence_buf,
                                          &evidence_buf_size);
    if (ret < 0) {
        *out_found_oid = false;
        return ret;
    }

    *out_found_oid = true;

    struct cbor_load_result cbor_result;
    cbor_tagged_evidence = cbor_load(evidence_buf, evidence_buf_size, &cbor_result);
    if (cbor_result.error.code != CBOR_ERR_NONE) {
        ERROR("Certificate: cannot parse 'tagged evidence' OID in CBOR format (error %d)\n",
              cbor_result.error.code);
        ret = (cbor_result.error.code == CBOR_ERR_MEMERROR) ? MBEDTLS_ERR_X509_ALLOC_FAILED
                                                            : MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }

    if (!cbor_isa_tag(cbor_tagged_evidence)
            || cbor_tag_value(cbor_tagged_evidence) != TCG_DICE_TAGGED_EVIDENCE_TEE_QUOTE_CBOR_TAG) {
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }

    cbor_evidence = cbor_tag_item(cbor_tagged_evidence);
    if (!cbor_evidence || !cbor_isa_array(cbor_evidence)
            || !cbor_array_is_definite(cbor_evidence)) {
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }

    if (cbor_array_size(cbor_evidence) != 2) {
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }

    cbor_quote = cbor_array_get(cbor_evidence, /*index=*/0);
    if (!cbor_quote || !cbor_isa_bytestring(cbor_quote)
            || !cbor_bytestring_is_definite(cbor_quote)) {
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }

    size_t quote_size = cbor_bytestring_length(cbor_quote);
    if (quote_size < sizeof(*quote)) {
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }
    quote = malloc(quote_size);
    if (!quote) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }
    memcpy(quote, cbor_bytestring_handle(cbor_quote), quote_size);

    cbor_claims = cbor_array_get(cbor_evidence, /*index=*/1);
    if (!cbor_claims || !cbor_isa_bytestring(cbor_claims)
            || !cbor_bytestring_is_definite(cbor_claims)
            || cbor_bytestring_length(cbor_claims) == 0) {
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }

    /* claims object is borrowed, no need to free separately */
    uint8_t* claims_buf    = cbor_bytestring_handle(cbor_claims);
    size_t claims_buf_size = cbor_bytestring_length(cbor_claims);
    assert(claims_buf && claims_buf_size);

    /* verify that SGX quote corresponds to the attached serialized claims */
    uint8_t sha[SHA256_DIGEST_SIZE];
    ret = mbedtls_sha256(claims_buf, claims_buf_size, sha, /*is224=*/0);
    if (ret < 0) {
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }

    ret = memcmp(quote->body.report_body.report_data.d, sha, SHA256_DIGEST_SIZE);
    if (ret) {
        ret = MBEDTLS_ERR_X509_SIG_MISMATCH;
        goto out;
    }

    /* parse and verify CBOR claims */
    cbor_claims_map = cbor_load(claims_buf, claims_buf_size, &cbor_result);
    if (cbor_result.error.code != CBOR_ERR_NONE) {
        ERROR("Certificate: cannot parse serialized CBOR map of claims (error %d)\n",
              cbor_result.error.code);
        ret = (cbor_result.error.code == CBOR_ERR_MEMERROR) ? MBEDTLS_ERR_X509_ALLOC_FAILED
                                                            : MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }

    if (!cbor_isa_map(cbor_claims_map) || !cbor_map_is_definite(cbor_claims_map)
            || cbor_map_size(cbor_claims_map) < 1) {
        ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
        goto out;
    }

    struct cbor_pair* claims_pairs = cbor_map_handle(cbor_claims_map);
    for (size_t i = 0; i < cbor_map_size(cbor_claims_map); i++) {
        if (!claims_pairs[i].key || !cbor_isa_string(claims_pairs[i].key)
                || !cbor_string_is_definite(claims_pairs[i].key)
                || cbor_string_length(claims_pairs[i].key) == 0) {
            ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
            goto out;
        }

#define PUBKEY_HASH_STR "pubkey-hash"
        if ((cbor_string_length(claims_pairs[i].key) == sizeof(PUBKEY_HASH_STR) - 1)
                && (memcmp(cbor_string_handle(claims_pairs[i].key), PUBKEY_HASH_STR,
                           sizeof(PUBKEY_HASH_STR) - 1) == 0)) {
            /* claim { "pubkey-hash" : serialized CBOR array hash-entry (as CBOR bstr) } */
            if (!claims_pairs[i].value || !cbor_isa_bytestring(claims_pairs[i].value)
                    || !cbor_bytestring_is_definite(claims_pairs[i].value)
                    || cbor_bytestring_length(claims_pairs[i].value) == 0) {
                ret = MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
                goto out;
            }

            uint8_t* hash_entry_buf = cbor_bytestring_handle(claims_pairs[i].value);
            size_t hash_entry_buf_size = cbor_bytestring_length(claims_pairs[i].value);

            cbor_hash_entry = cbor_load(hash_entry_buf, hash_entry_buf_size, &cbor_result);
            if (cbor_result.error.code != CBOR_ERR_NONE) {
                ERROR("Certificate: cannot parse " PUBKEY_HASH_STR " array in CBOR format "
                      "(error %d)\n", cbor_result.error.code);
                ret = (cbor_result.error.code == CBOR_ERR_MEMERROR) ? MBEDTLS_ERR_X509_ALLOC_FAILED
                      : MBEDTLS_ERR_X509_INVALID_EXTENSIONS;
                goto out;
            }

            ret = cmp_crt_pk_against_cbor_claim_hash_entry(crt, cbor_hash_entry);
            if (ret < 0)
                goto out;
#undef PUBKEY_HASH_STR
        } else {
            INFO("WARNING: Unrecognized claim in TCG DICE 'tagged evidence' OID, ignoring.\n");
        }
    }

    *out_quote = quote;
    *out_quote_size = quote_size;
    ret = 0;
out:
    if (ret < 0)
        free(quote);
    if (cbor_hash_entry)
        cbor_decref(&cbor_hash_entry);
    if (cbor_claims_map)
        cbor_decref(&cbor_claims_map);
    if (cbor_claims)
        cbor_decref(&cbor_claims);
    if (cbor_quote)
        cbor_decref(&cbor_quote);
    if (cbor_evidence)
        cbor_decref(&cbor_evidence);
    if (cbor_tagged_evidence)
        cbor_decref(&cbor_tagged_evidence);
    return ret;
}

static int extract_legacy_quote_and_verify_pubkey(mbedtls_x509_crt* crt, sgx_quote_t** out_quote,
                                                  size_t* out_quote_size) {
    sgx_quote_t* quote;
    size_t quote_size;
    int ret = find_oid_in_cert_extensions(crt->v3_ext.p, crt->v3_ext.len, g_ratls_quote_oid,
                                          sizeof(g_ratls_quote_oid), (uint8_t**)&quote,
                                          &quote_size);
    if (ret < 0)
        return ret;

    if (quote_size < sizeof(*quote))
        return MBEDTLS_ERR_X509_INVALID_EXTENSIONS;

    /* currently only one check: public key's hash from cert must match SGX quote's report_data */
    ret = cmp_crt_pk_against_quote_report_data(crt, quote);
    if (ret < 0)
        return ret;

    /* quote returned by find_oid_in_cert_extensions() is a pointer somewhere inside of the X.509
     * cert object; let's copy it into a newly allocated object to make tracing ownership easier */
    sgx_quote_t* allocated_quote = malloc(quote_size);
    if (!allocated_quote)
        return MBEDTLS_ERR_X509_ALLOC_FAILED;
    memcpy(allocated_quote, quote, quote_size);

    *out_quote = allocated_quote;
    *out_quote_size = quote_size;
    return 0;
}

int extract_quote_and_verify_claims(mbedtls_x509_crt* crt, sgx_quote_t** out_quote,
                                    size_t* out_quote_size) {
    bool found_oid;
    int ret = extract_standard_quote_and_verify_claims(crt, &found_oid, out_quote, out_quote_size);
    if (ret == 0)
        return 0;
    if (found_oid) {
        /* TCG DICE 'tagged evidence' OID was found, but verification failed for other reasons */
        assert(ret < 0);
        return ret;
    }

    INFO("WARNING: TCG DICE 'tagged evidence' OID was not found. Checking non-standard legacy "
         "Gramine OID. This will be deprecated in the future.\n");
    return extract_legacy_quote_and_verify_pubkey(crt, out_quote, out_quote_size);
}

void ra_tls_set_measurement_callback(int (*f_cb)(const char* mrenclave, const char* mrsigner,
                                                 const char* isv_prod_id, const char* isv_svn)) {
    g_verify_measurements_cb = f_cb;
}

int ra_tls_verify_callback_der(uint8_t* der_crt, size_t der_crt_size) {
    INFO("WARNING: The ra_tls_verify_callback_der() API is deprecated in favor of the "
         "ra_tls_verify_callback_extended_der() version of API.\n");
    return ra_tls_verify_callback_extended_der(der_crt, der_crt_size, /*unused results=*/NULL);
}

int ra_tls_verify_callback_extended_der(uint8_t* der_crt, size_t der_crt_size,
                                        struct ra_tls_verify_callback_results* results) {
    int ret;
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);

    ret = mbedtls_x509_crt_parse(&crt, der_crt, der_crt_size);
    if (ret < 0)
        goto out;

    if (results) {
        /* ensure that all the not-filled fields of callback results are always zeroized */
        memset(results, 0, sizeof(*results));
    }

    ret = ra_tls_verify_callback(results, &crt, /*depth=*/0, /*flags=*/NULL);
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
        return ret;

    ret = verify_quote_body(quote_body, validate_mrsigner ? (char*)&expected_mrsigner : NULL,
                            validate_mrenclave ? (char*)&expected_mrenclave : NULL,
                            validate_isv_prod_id ? (char*)&expected_isv_prod_id : NULL,
                            validate_isv_svn ? (char*)&expected_isv_svn : NULL,
                            /*report_data=*/NULL, /*expected_as_str=*/false);
    if (ret < 0)
        return MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;

    return 0;
}
