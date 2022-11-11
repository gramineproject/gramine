/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Labs */

/*
 * Internal RA-TLS details, to be used by external RA-TLS implementations:
 *   - external implementation must implement ra_tls_verify_callback(),
 *   - external implementation can call all other funcs declared here.
 *
 * Note that external implementations must use static mbedTLS libraries (shipped together with
 * Gramine).
 */

#pragma once

#include <mbedtls/x509_crt.h>
#include <stdint.h>

#include "sgx_attest.h"

#define SHA256_DIGEST_SIZE       32
#define SHA384_DIGEST_SIZE       48
#define SHA512_DIGEST_SIZE       64

#define PUB_KEY_SIZE_MAX         128 /* enough for the only currently supported algo (ECDSA-384) */
#define IAS_REQUEST_NONCE_LEN    32

/* below OID is actually wrong: it shouldn't have the first two bytes (0x06 0x09) because they
 * represent the ASN.1 Type (6 = OBJECT IDENTIFIER) and ASN.1 Length (9 bytes); we don't modify it
 * because it is non-standard anyway and we don't want to break backwards-compatibility */
#define NON_STANDARD_INTEL_SGX_QUOTE_OID \
    { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, 0x06 }
static const uint8_t g_quote_oid[] = NON_STANDARD_INTEL_SGX_QUOTE_OID;
static const size_t g_quote_oid_size = sizeof(g_quote_oid);

/* standard TCG DICE "tagged evidence" OID (2.23.133.5.4.9) */
#define TCG_DICE_TAGGED_EVIDENCE_OID { 0x67, 0x81, 0x05, 0x05, 0x04, 0x09 }
#define TCG_DICE_TAGGED_EVIDENCE_OID_RAW { 0x06, 0x06, 0x67, 0x81, 0x05, 0x05, 0x04, 0x09 }
static const uint8_t g_evidence_oid[] = TCG_DICE_TAGGED_EVIDENCE_OID;
static const size_t g_evidence_oid_size = sizeof(g_evidence_oid);
static const uint8_t g_evidence_oid_raw[] = TCG_DICE_TAGGED_EVIDENCE_OID_RAW;
static const size_t g_evidence_oid_raw_size = sizeof(g_evidence_oid_raw);

/* attestation evidence data tags, https://www.iana.org/assignments/cbor-tags/cbor-tags.xhtml */
#define TCG_DICE_TAGGED_EVIDENCE_TEE_QUOTE_CBOR_TAG 60000

/* hash IDs per IANA: https://www.iana.org/assignments/named-information/named-information.xhtml */
#define IANA_NAMED_INFO_HASH_ALG_REGISTRY_RESERVED 0
#define IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA256   1
#define IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA384   7
#define IANA_NAMED_INFO_HASH_ALG_REGISTRY_SHA512   8

bool getenv_allow_outdated_tcb(void);
bool getenv_allow_hw_config_needed(void);
bool getenv_allow_sw_hardening_needed(void);
bool getenv_allow_debug_enclave(void);

int find_oid_in_cert_extensions(const uint8_t* exts, size_t exts_size, const uint8_t* oid,
                                size_t oid_size, uint8_t** out_val, size_t* out_size);
int cmp_crt_pk_against_quote_report_data(mbedtls_x509_crt* crt, sgx_quote_t* quote);
int extract_quote_and_verify_claims(mbedtls_x509_crt* crt, sgx_quote_t** out_quote,
                                    size_t* out_quote_size);
int verify_quote_body_against_envvar_measurements(const sgx_quote_body_t* quote_body);
int ra_tls_create_key_and_crt(mbedtls_pk_context* key, mbedtls_x509_crt* crt);

/* to be implemented by an RA-TLS implementation (e.g. talk to IAS for EPID implementation) */
int ra_tls_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags);
