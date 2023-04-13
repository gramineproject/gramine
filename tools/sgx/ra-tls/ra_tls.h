/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Labs */

/*
 * RA-TLS user API:
 *   - ra_tls_set_measurement_callback() and ra_tls_verify_callback_der() for verifier side,
 *   - ra_tls_create_key_and_crt_der() for attester (SGX enclave) side.
 */

#pragma once

#include <stdint.h>

#define RA_TLS_EPID_API_KEY "RA_TLS_EPID_API_KEY"

#define RA_TLS_ALLOW_OUTDATED_TCB_INSECURE  "RA_TLS_ALLOW_OUTDATED_TCB_INSECURE"
#define RA_TLS_ALLOW_HW_CONFIG_NEEDED       "RA_TLS_ALLOW_HW_CONFIG_NEEDED"
#define RA_TLS_ALLOW_SW_HARDENING_NEEDED    "RA_TLS_ALLOW_SW_HARDENING_NEEDED"
#define RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE "RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE"

#define RA_TLS_MRSIGNER    "RA_TLS_MRSIGNER"
#define RA_TLS_MRENCLAVE   "RA_TLS_MRENCLAVE"
#define RA_TLS_ISV_PROD_ID "RA_TLS_ISV_PROD_ID"
#define RA_TLS_ISV_SVN     "RA_TLS_ISV_SVN"

#define RA_TLS_IAS_PUB_KEY_PEM "RA_TLS_IAS_PUB_KEY_PEM"
#define RA_TLS_IAS_REPORT_URL  "RA_TLS_IAS_REPORT_URL"
#define RA_TLS_IAS_SIGRL_URL   "RA_TLS_IAS_SIGRL_URL"

#define RA_TLS_CERT_TIMESTAMP_NOT_BEFORE "RA_TLS_CERT_TIMESTAMP_NOT_BEFORE"
#define RA_TLS_CERT_TIMESTAMP_NOT_AFTER  "RA_TLS_CERT_TIMESTAMP_NOT_AFTER"

typedef enum {
    RA_TLS_ATTESTATION_SCHEME_UNKNOWN = 0,
    RA_TLS_ATTESTATION_SCHEME_EPID    = 1,
    RA_TLS_ATTESTATION_SCHEME_DCAP    = 2,
} ra_tls_attestation_scheme_t;

typedef enum {
    AT_NONE                        = 0,
    AT_INIT                        = 1,
    AT_EXTRACT_QUOTE               = 2,
    AT_VERIFY_EXTERNAL             = 3,
    AT_VERIFY_ENCLAVE_ATTRS        = 4,
    AT_VERIFY_ENCLAVE_MEASUREMENTS = 5,
} ra_tls_err_loc_t;

/* Verification callback results for retrieving additional verification results from RA-TLS.
 * Note that this is (at least currently) an out-only struct (i.e., there can be no input fields
 * provided by the application/user) */
struct ra_tls_verify_callback_results {
    ra_tls_attestation_scheme_t attestation_scheme;
    ra_tls_err_loc_t err_loc; /* the step at which RA-TLS failed */

    union {
        struct {
            /* str returned in `isvEnclaveQuoteStatus`; possibly truncated (but NULL-terminated) */
            char ias_enclave_quote_status[128];
        } epid;
        struct {
            int func_verify_quote_result; /* return value of `sgx_qv_verify_quote()` itself */
            int quote_verification_result; /* value stored in `p_quote_verification_result` arg */
        } dcap;
        struct {
            /* buffer reserved for other RA-TLS plugins to store the data specific to their
             * implementations */
            char reserved[128];
        } misc;
    };
};

typedef int (*verify_measurements_cb_t)(const char* mrenclave, const char* mrsigner,
                                        const char* isv_prod_id, const char* isv_svn);

/*!
 * \brief Callback for user-specific verification of measurements in SGX quote.
 *
 * \param f_cb  Callback for user-specific verification; RA-TLS passes pointers to MRENCLAVE,
 *              MRSIGNER, ISV_PROD_ID, ISV_SVN measurements in SGX quote. Use NULL to revert to
 *              default behavior of RA-TLS.
 *
 * \returns 0 on success, specific error code (negative int) otherwise.
 *
 * If this callback is registered before RA-TLS session, then RA-TLS verification will invoke this
 * callback to allow for user-specific checks on SGX measurements reported in the SGX quote. If no
 * callback is registered (or registered as NULL), then RA-TLS defaults to verifying SGX
 * measurements against `RA_TLS_*` environment variables (if any).
 */
void ra_tls_set_measurement_callback(verify_measurements_cb_t f_cb);

/*!
 * \brief Generic verification callback for EPID-based (IAS) or ECDSA-based (DCAP) quote
 *        verification (DER format). Deprecated in favor of the
 *        `ra_tls_verify_callback_extended_der()` version of API (see below).
 *
 * \param der_crt       Self-signed RA-TLS certificate with SGX quote embedded in DER format.
 * \param der_crt_size  Size of the RA-TLS certificate.
 *
 * \returns 0 on success, specific mbedTLS error code (negative int) otherwise.
 *
 * This function must be called from a non-mbedTLS verification callback, e.g., from a user-defined
 * OpenSSL callback for SSL_CTX_set_cert_verify_callback(). All parameters required for the SGX
 * quote, IAS attestation report verification, and/or DCAP quote verification must be passed in the
 * corresponding RA-TLS environment variables.
 */
int ra_tls_verify_callback_der(uint8_t* der_crt, size_t der_crt_size);

/*!
 * \brief Generic verification callback for EPID-based (IAS) or ECDSA-based (DCAP) quote
 *        verification (DER format) with additional information.
 *
 * \param der_crt       Self-signed RA-TLS certificate with SGX quote embedded in DER format.
 * \param der_crt_size  Size of the RA-TLS certificate.
 * \param results       (Optional) Verification callback results for retrieving additional
 *                      verification results from RA-TLS.
 *
 * \returns 0 on success, specific mbedTLS error code (negative int) otherwise.
 *
 * This function must be called from a non-mbedTLS verification callback, e.g., from a user-defined
 * OpenSSL callback for SSL_CTX_set_cert_verify_callback(). All parameters required for the SGX
 * quote, IAS attestation report verification, and/or DCAP quote verification must be passed in the
 * corresponding RA-TLS environment variables.
 */
int ra_tls_verify_callback_extended_der(uint8_t* der_crt, size_t der_crt_size,
                                        struct ra_tls_verify_callback_results* results);

/*!
 * \brief Generic function to generate a key and a corresponding RA-TLS certificate (DER format).
 *
 * \param[out] der_key       Pointer to buffer populated with generated ECDSA keypair in DER format.
 * \param[out] der_key_size  Pointer to size of generated ECDSA keypair.
 * \param[out] der_crt       Pointer to buffer populated with self-signed RA-TLS certificate.
 * \param[out] der_crt_size  Pointer to size of self-signed RA-TLS certificate.
 *
 * \returns 0 on success, specific mbedTLS error code (negative int) otherwise.
 *
 * The function first generates a random ECDSA keypair with NIST P-384 (SECP384R1) elliptic curve.
 * Then it calculates the SHA256 hash over the generated public key and retrieves an SGX quote with
 * report_data equal to the calculated hash (this ties the generated certificate key to the SGX
 * quote). Finally, it generates the X.509 self-signed certificate with this key and the SGX quote
 * embedded. The function allocates memory for key and certificate; user is expected to free them
 * after use.
 */
int ra_tls_create_key_and_crt_der(uint8_t** der_key, size_t* der_key_size, uint8_t** der_crt,
                                  size_t* der_crt_size);
