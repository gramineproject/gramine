/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Rafal Wojdyla <omeg@invisiblethingslab.com>
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "sgx_attest.h"

/*!
 * \brief Display internal SGX quote structure.
 *
 * \param quote_data  Buffer with quote data. This can be a full quote (sgx_quote_t) or a quote
 *                    from IAS attestation report (which is missing signature fields).
 * \param quote_size  Size of \p quote_data in bytes.
 */
void display_quote(const void* quote_data, size_t quote_size);

/*!
 * \brief Verify that the provided SGX quote body contains expected values.
 *
 * \param quote_body       Quote body to verify.
 * \param mr_signer        (Optional) Expected mr_signer quote field.
 * \param mr_enclave       (Optional) Expected mr_enclave quote field.
 * \param isv_prod_id      (Optional) Expected isv_prod_id quote field.
 * \param isv_svn          (Optional) Expected isv_svn quote field.
 * \param report_data      (Optional) Expected report_data quote field.
 * \param expected_as_str  If true, then all expected SGX fields are treated as hex and decimal
 *                         strings. Otherwise, they are treated as raw bytes.
 *
 * \returns 0 on successful verification, negative value on error.
 *
 * If \p expected_as_str is true, then \p mr_signer, \p mr_enclave and \p report_data are treated
 * as hex strings, and \p isv_prod_id and a isv_svn are treated as decimal strings. This is
 * convenient for command-line utilities.
 */
int verify_quote_body(const sgx_quote_body_t* quote_body, const char* mr_signer,
                      const char* mr_enclave, const char* isv_prod_id, const char* isv_svn,
                      const char* report_data, bool expected_as_str);

/*!
 * \brief Verify enclave attributes of the provided SGX quote body.
 *
 * \param quote_body           Quote body to verify.
 * \param allow_debug_enclave  If true, then SGXREPORT.ATTRIBUTES.DEBUG can be 1.
 *
 * \returns 0 on successful verification, negative value on error.
 */
int verify_quote_body_enclave_attributes(sgx_quote_body_t* quote_body, bool allow_debug_enclave);
