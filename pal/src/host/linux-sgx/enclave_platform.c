/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2019, Texas A&M University */

#include "pal_linux.h"
#include "pal_linux_error.h"

int sgx_get_quote(const sgx_spid_t* spid, const sgx_quote_nonce_t* nonce,
                  const sgx_report_data_t* report_data, bool linkable, char** quote,
                  size_t* quote_len) {
    int ret;
    int retries = 0;
    while (retries < 5) {
        if (retries) {
            /* new attempt, need to update QE target info */
            ret = ocall_get_qe_targetinfo(/*is_epid=*/!!spid, &g_pal_linuxsgx_state.qe_targetinfo);
            if (ret < 0) {
                log_error("Failed to get QE target info (error code=%d)", ret);
                return unix_to_pal_error(ret);
            }
        }

        /* must align all arguments to sgx_report() so that EREPORT doesn't complain */
        __sgx_mem_aligned sgx_report_t report;
        __sgx_mem_aligned sgx_target_info_t targetinfo = g_pal_linuxsgx_state.qe_targetinfo;
        __sgx_mem_aligned sgx_report_data_t _report_data = *report_data;

        ret = sgx_report(&targetinfo, &_report_data, &report);
        if (ret) {
            log_error("Failed to get enclave report (error code=%d)", ret);
            return -PAL_ERROR_DENIED;
        }

        /*
         * In DCAP, retrieving the SGX quote may return error AESM_ATT_KEY_NOT_INITIALIZED (42),
         * which means that the attestation key is not available and AESM service must re-generate
         * the key. When Gramine sees such error, it must perform a new INIT_QUOTE_REQUEST and then
         * re-try retrieving the SGX quote. Note that after INIT_QUOTE_REQUEST, the targetinfo of
         * Quoting Enclave (QE) may change and must be updated inside the SGX enclave (in
         * `g_pal_linuxsgx_state.qe_targetinfo`).
         *
         * In our OCALLs, AESM_ATT_KEY_NOT_INITIALIZED is transformed into EAGAIN, and
         * INIT_QUOTE_REQUEST corresponds to ocall_get_qe_targetinfo().
         */
        ret = ocall_get_quote(spid, linkable, &report, nonce, quote, quote_len);
        if (ret < 0 && ret != -EAGAIN) {
            log_error("Failed to get quote (error code=%d)", ret);
            return unix_to_pal_error(ret);
        }

        if (!ret) {
            /* success */
            return 0;
        }

        assert(ret == -EAGAIN);
        retries++;
    }

    log_error("Failed to get quote after %d attempts", retries);
    return -PAL_ERROR_DENIED;
}
