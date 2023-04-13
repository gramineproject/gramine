/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Rafal Wojdyla <omeg@invisiblethingslab.com>
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*! Context used in ias_*() calls. */
struct ias_context_t;

/*!
 * \brief Create and initialize context used for IAS communication.
 *
 * \param ias_api_key     API key for IAS access.
 * \param ias_verify_url  URL for IAS attestation verification API.
 * \param ias_sigrl_url   URL for IAS "Retrieve SigRL" API.
 *
 * \returns Context to be used in further ias_* calls or NULL on failure.
 *
 * Should be called once, before handling any request.
 */
struct ias_context_t* ias_init(const char* ias_api_key, const char* ias_verify_url,
                               const char* ias_sigrl_url);

/*!
 * \brief Clean up and free context used for IAS communication.
 *
 * \param context  IAS context returned by ias_init().
 *
 * Should be called once, after serving last request.
 */
void ias_cleanup(struct ias_context_t* context);

/*!
 * \brief Get the signature revocation list for a given EPID group.
 *
 * \param      context     IAS context returned by ias_init().
 * \param      gid         EPID group ID to get SigRL for.
 * \param[out] sigrl_size  Size of the SigRL (may be 0).
 * \param[out] sigrl       SigRL data, needs to be freed by the caller.
 *
 * \returns 0 on success, -1 otherwise.
 */
int ias_get_sigrl(struct ias_context_t* context, uint8_t gid[4], size_t* sigrl_size, void** sigrl);

/*!
 * \brief Send quote to IAS for verification.
 *
 * \param context      IAS context returned by ias_init().
 * \param quote        Binary quote data blob.
 * \param quote_size   Size of \p quote.
 * \param nonce        (Optional) Nonce string to send with the IAS request (max 32 chars).
 * \param report_path  (Optional) File to save IAS report to.
 * \param sig_path     (Optional) File to save IAS report's signature to.
 * \param cert_path    (Optional) File to save IAS certificate to.
 *
 * \returns 0 on success, -1 otherwise.
 *
 *  This version of the function is convenient for command-line utilities. To get raw IAS contents,
 *  use ias_send_quote_get_report_raw().
 *
 * Sends quote to the "Verify Attestation Evidence" IAS endpoint.
 */
int ias_send_quote_get_report(struct ias_context_t* context, const void* quote, size_t quote_size,
                              const char* nonce, const char* report_path, const char* sig_path,
                              const char* cert_path);

/*!
 * \brief Send quote to IAS for verification (same as ias_send_quote_get_report() but not saving to
 *        files).
 *
 * \param      context           IAS context returned by ias_init().
 * \param      quote             Binary quote data blob.
 * \param      quote_size        Size of \p quote.
 * \param      nonce             (Optional) Nonce string to send with IAS request (max 32 chars).
 * \param[out] report_data_ptr   (Optional) Pointer to allocated IAS report.
 * \param[out] report_data_size  (Optional) Size of allocated IAS report.
 * \param[out] sig_data_ptr      (Optional) Pointer to allocated IAS report's signature.
 * \param[out] sig_data_size     (Optional) Size of allocated IAS report's signature.
 * \param[out] cert_data_ptr     (Optional) Pointer to allocated IAS certificate.
 * \param[out] cert_data_size    (Optional) Size of allocated IAS certificate.
 *
 * \returns 0 on success, -1 otherwise.
 *
 * This version of the function is convenient for library usage. This function allocates buffers
 * for IAS contents and passes them to caller via \p report_data_ptr, \p sig_data_ptr and
 * \p cert_data_ptr. The caller is responsible for freeing them.
 * To save IAS contents to files, use ias_send_quote_get_report().
 *
 * Sends quote to the "Verify Attestation Evidence" IAS endpoint.
 */
int ias_send_quote_get_report_raw(struct ias_context_t* context, const void* quote,
                                  size_t quote_size, const char* nonce, char** report_data_ptr,
                                  size_t* report_data_size, char** sig_data_ptr,
                                  size_t* sig_data_size, char** cert_data_ptr,
                                  size_t* cert_data_size);

/*!
 * \brief Verify IAS attestation report. Also extract the SGX quote contained in IAS report:
 *        allocate enough memory to hold the quote and pass it to the user.
 *
 * \param ias_report                IAS attestation verification report.
 * \param ias_report_size           Size of \p ias_report in bytes.
 * \param ias_sig_b64               IAS report signature (base64-encoded as returned by IAS).
 * \param ias_sig_b64_size          Size of \p ias_sig_b64 in bytes.
 * \param allow_outdated_tcb        Treat IAS status code GROUP_OUT_OF_DATE as OK.
 * \param allow_hw_config_needed    Treat IAS status code CONFIGURATION_NEEDED as OK.
 * \param allow_sw_hardening_needed Treat IAS status code SW_HARDENING_NEEDED as OK.
 * \param nonce                     (Optional) Nonce that's expected in the report.
 * \param ias_pub_key_pem           (Optional) IAS public RSA key (PEM format, NULL-terminated).
 *                                  If not specified, a hardcoded Intel's key is used.
 * \param enclave_quote_status      (Optional) If non-NULL, this contains the returned
 *                                  `isvEnclaveQuoteStatus` string on enclave quote status
 *                                  verification failure. The string may be truncated to fit into
 *                                  128 bytes (including the terminating NULL char).
 * \param[out] out_quote            Buffer with quote. User is responsible for freeing it.
 * \param[out] out_quote_size       Size of \p out_quote in bytes.
 *
 * \returns 0 on successful verification, negative value on error.
 *
 * To treat the IAS status code CONFIGURATION_AND_SW_HARDENING_NEEDED as OK, both
 * \p allow_hw_config_needed and \p allow_sw_hardening_needed must be set to true.
 */
int ias_verify_report_extract_quote(const uint8_t* ias_report, size_t ias_report_size,
                                    uint8_t* ias_sig_b64, size_t ias_sig_b64_size,
                                    bool allow_outdated_tcb, bool allow_hw_config_needed,
                                    bool allow_sw_hardening_needed, const char* nonce,
                                    const char* ias_pub_key_pem, char (*enclave_quote_status)[128],
                                    uint8_t** out_quote, size_t* out_quote_size);
