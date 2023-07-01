/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Labs */

/*!
 * \file
 *
 * This file contains the implementation of verification callbacks for TLS libraries. The callbacks
 * verify the correctness of a self-signed RA-TLS certificate with an SGX quote embedded in it. The
 * callbacks call into the `libsgx_dcap_quoteverify` DCAP library for ECDSA-based verification. A
 * callback ra_tls_verify_callback() can be used directly in mbedTLS, and a more generic version
 * ra_tls_verify_callback_der() should be used for other TLS libraries.
 *
 * This file is part of the RA-TLS verification library which is typically linked into client
 * applications. This library is *not* thread-safe.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_crt.h>

#include "quote.h"
#include "util.h"

#include "ra_tls.h"
#include "ra_tls_common.h"

extern verify_measurements_cb_t g_verify_measurements_cb;

/* we cannot include libsgx_dcap_verify headers because they conflict with Gramine SGX headers,
 * so we declare the used types and functions below */

/* QL stands for Quoting Library; QV stands for Quote Verification */
#define SGX_QL_QV_MK_ERROR(x) (0x0000A000 | (x))
typedef enum _sgx_ql_qv_result_t {
    /* quote verification passed and is at the latest TCB level */
    SGX_QL_QV_RESULT_OK = 0x0000,
    /* quote verification passed and the platform is patched to the latest TCB level but additional
     * configuration of the SGX platform may be needed */
    SGX_QL_QV_RESULT_CONFIG_NEEDED = SGX_QL_QV_MK_ERROR(0x0001),
    /* quote is good but TCB level of the platform is out of date; platform needs patching to be at
     * the latest TCB level */
    SGX_QL_QV_RESULT_OUT_OF_DATE = SGX_QL_QV_MK_ERROR(0x0002),
    /* quote is good but the TCB level of the platform is out of date and additional configuration
     * of the SGX platform at its current patching level may be needed; platform needs patching to
     * be at the latest TCB level */
    SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED = SGX_QL_QV_MK_ERROR(0x0003),
    /* signature over the application report is invalid */
    SGX_QL_QV_RESULT_INVALID_SIGNATURE = SGX_QL_QV_MK_ERROR(0x0004),
    /* attestation key or platform has been revoked */
    SGX_QL_QV_RESULT_REVOKED = SGX_QL_QV_MK_ERROR(0x0005),
    /* quote verification failed due to an error in one of the input */
    SGX_QL_QV_RESULT_UNSPECIFIED = SGX_QL_QV_MK_ERROR(0x0006),
    /* TCB level of the platform is up to date, but SGX SW hardening is needed */
    SGX_QL_QV_RESULT_SW_HARDENING_NEEDED = SGX_QL_QV_MK_ERROR(0x0007),
    /* TCB level of the platform is up to date, but additional configuration of the platform at its
     * current patching level may be needed; moreover, SGX SW hardening is also needed */
    SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED = SGX_QL_QV_MK_ERROR(0x0008),
} sgx_ql_qv_result_t;

int sgx_qv_get_quote_supplemental_data_size(uint32_t* p_data_size);
int sgx_qv_verify_quote(const uint8_t* p_quote, uint32_t quote_size, void* p_quote_collateral,
                        const time_t expiration_check_date,
                        uint32_t* p_collateral_expiration_status,
                        sgx_ql_qv_result_t* p_quote_verification_result, void* p_qve_report_info,
                        uint32_t supplemental_data_size, uint8_t* p_supplemental_data);

static const char* sgx_ql_qv_result_to_str(sgx_ql_qv_result_t verification_result) {
    switch (verification_result) {
        case SGX_QL_QV_RESULT_OK:
            return "OK";
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
            return "CONFIG_NEEDED";
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
            return "OUT_OF_DATE";
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
            return "OUT_OF_DATE_CONFIG_NEEDED";
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
            return "SW_HARDENING_NEEDED";
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            return "CONFIG_AND_SW_HARDENING_NEEDED";
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
            return "INVALID_SIGNATURE";
        case SGX_QL_QV_RESULT_REVOKED:
            return "REVOKED";
        case SGX_QL_QV_RESULT_UNSPECIFIED:
            return "UNSPECIFIED";
    }
    return "<unrecognized error>";
}

int ra_tls_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
    struct ra_tls_verify_callback_results* results = (struct ra_tls_verify_callback_results*)data;

    int ret;

    uint8_t* supplemental_data      = NULL;
    uint32_t supplemental_data_size = 0;

    if (results) {
        results->attestation_scheme = RA_TLS_ATTESTATION_SCHEME_DCAP;
        results->err_loc = AT_INIT;
    }

    if (depth != 0) {
        /* the cert chain in RA-TLS consists of single self-signed cert, so we expect depth 0 */
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }

    if (flags) {
        /* mbedTLS sets flags to signal that the cert is not to be trusted (e.g., it is not
         * correctly signed by a trusted CA; since RA-TLS uses self-signed certs, we don't care
         * what mbedTLS thinks and ignore internal cert verification logic of mbedTLS */
        *flags = 0;
    }

    if (results)
        results->err_loc = AT_EXTRACT_QUOTE;

    /* extract SGX quote from "quote" OID extension from crt */
    sgx_quote_t* quote;
    size_t quote_size;
    ret = extract_quote_and_verify_pubkey(crt, &quote, &quote_size);
    if (ret < 0) {
        ERROR("extract_quote_and_verify_pubkey failed: %d\n", ret);
        goto out;
    }

    if (results)
        results->err_loc = AT_VERIFY_EXTERNAL;

    /* prepare user-supplied verification parameters "allow outdated TCB", etc. */
    bool allow_outdated_tcb        = getenv_allow_outdated_tcb();
    bool allow_hw_config_needed    = getenv_allow_hw_config_needed();
    bool allow_sw_hardening_needed = getenv_allow_sw_hardening_needed();
    bool allow_debug_enclave       = getenv_allow_debug_enclave();

    /* call into libsgx_dcap_quoteverify to get supplemental data size */
    ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (ret) {
        ERROR("sgx_qv_get_quote_supplemental_data_size failed: %d\n", ret);
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    supplemental_data = (uint8_t*)malloc(supplemental_data_size);
    if (!supplemental_data) {
        ret = MBEDTLS_ERR_X509_ALLOC_FAILED;
        goto out;
    }

    time_t current_time = time(NULL);
    if (current_time == ((time_t)-1)) {
        ret = MBEDTLS_ERR_X509_FATAL_ERROR;
        goto out;
    }

    uint32_t collateral_expiration_status  = 1;
    sgx_ql_qv_result_t verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;

    /* call into libsgx_dcap_quoteverify to verify ECDSA-based SGX quote */
    ret = sgx_qv_verify_quote((uint8_t*)quote, (uint32_t)quote_size, /*p_quote_collateral=*/NULL,
                              current_time, &collateral_expiration_status, &verification_result,
                              /*p_qve_report_info=*/NULL, supplemental_data_size,
                              supplemental_data);
    if (results) {
        results->dcap.func_verify_quote_result = ret;
        results->dcap.quote_verification_result = verification_result;
    }
    if (ret) {
        ERROR("sgx_qv_verify_quote failed: %d\n", ret);
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        goto out;
    }

    switch (verification_result) {
        case SGX_QL_QV_RESULT_OK:
            ret = 0;
            if (collateral_expiration_status != 0) {
                INFO("WARNING: The collateral is out of date.\n");
                if (!allow_outdated_tcb)
                    ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            }
            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
            ret = allow_hw_config_needed ? 0 : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            break;
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
            ret = allow_outdated_tcb ? 0 : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            break;
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
            ret = allow_outdated_tcb
                      ? (allow_hw_config_needed ? 0 : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
                      : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            break;
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
            ret = allow_sw_hardening_needed ? 0 : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            break;
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            ret = allow_hw_config_needed
                      ? (allow_sw_hardening_needed ? 0 : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED)
                      : MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
            break;
    }
    if (ret < 0) {
        if (verification_result == SGX_QL_QV_RESULT_OK) {
            assert(collateral_expiration_status != 0 && !allow_outdated_tcb);
            ERROR("Quote: verification failed because collateral is out of date\n");
        } else {
            ERROR("Quote: verification failed with error %s\n",
                  sgx_ql_qv_result_to_str(verification_result));
        }
        goto out;
    }
    if (verification_result != SGX_QL_QV_RESULT_OK) {
        INFO("Allowing quote status %s\n", sgx_ql_qv_result_to_str(verification_result));
    }

    if (results)
        results->err_loc = AT_VERIFY_ENCLAVE_ATTRS;

    sgx_quote_body_t* quote_body = &quote->body;

    /* verify enclave attributes from the SGX quote body */
    ret = verify_quote_body_enclave_attributes(quote_body, allow_debug_enclave);
    if (ret < 0) {
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        goto out;
    }

    if (results)
        results->err_loc = AT_VERIFY_ENCLAVE_MEASUREMENTS;

    /* verify other relevant enclave information from the SGX quote */
    if (g_verify_measurements_cb) {
        /* use user-supplied callback to verify measurements */
        ret = g_verify_measurements_cb((const char*)&quote_body->report_body.mr_enclave,
                                       (const char*)&quote_body->report_body.mr_signer,
                                       (const char*)&quote_body->report_body.isv_prod_id,
                                       (const char*)&quote_body->report_body.isv_svn);
    } else {
        /* use default logic to verify measurements */
        ret = verify_quote_body_against_envvar_measurements(quote_body);
    }
    if (ret < 0) {
        ret = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED;
        goto out;
    }

    if (results)
        results->err_loc = AT_NONE;
    ret = 0;
out:
    free(supplemental_data);
    return ret;
}
