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
#define PUB_KEY_SIZE_MAX         128 /* enough for the only currently supported algo (ECDSA-384) */
#define IAS_REQUEST_NONCE_LEN    32

#define OID(N) \
    { 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, (N) }
static const uint8_t g_quote_oid[] = OID(0x06);
static const size_t g_quote_oid_size = sizeof(g_quote_oid);

bool getenv_allow_outdated_tcb(void);
bool getenv_allow_debug_enclave(void);
int cmp_crt_pk_against_quote_report_data(mbedtls_x509_crt* crt, sgx_quote_t* quote);
int extract_quote_and_verify_pubkey(mbedtls_x509_crt* crt, sgx_quote_t** out_quote,
                                    size_t* out_quote_size);
int verify_quote_body_against_envvar_measurements(const sgx_quote_body_t* quote_body);
int ra_tls_create_key_and_crt(mbedtls_pk_context* key, mbedtls_x509_crt* crt);

/* to be implemented by an RA-TLS implementation (e.g. talk to IAS for EPID implementation) */
int ra_tls_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags);
