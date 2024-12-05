/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation */

/* Common utilities to parse the manifest. Since functions in this file are used in both untrusted
 * and trusted PAL, and the former uses UNIX error codes whereas the latter uses PAL error codes,
 * the functions return UNIX error codes (callers in trusted PAL must convert to PAL error codes).
 */

#include <asm/errno.h>
#include <stdbool.h>
#include <stdint.h>

#include "api.h"
#include "hex.h"
#include "pal_linux.h"
#include "sgx_attest.h"
#include "toml.h"
#include "toml_utils.h"

int parse_attestation_type(toml_table_t* manifest_root,
                           enum sgx_attestation_type* out_attestation_type) {
    int ret;
    char* sgx_attestation_type_str = NULL;
    enum sgx_attestation_type attestation_type = SGX_ATTESTATION_NONE;

    ret = toml_string_in(manifest_root, "sgx.remote_attestation", &sgx_attestation_type_str);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.remote_attestation'");
        ret = -EINVAL;
        goto out;
    }

    if (sgx_attestation_type_str) {
        if (!strcmp(sgx_attestation_type_str, "none")) {
            attestation_type = SGX_ATTESTATION_NONE;
        } else if (!strcmp(sgx_attestation_type_str, "dcap")) {
            attestation_type = SGX_ATTESTATION_DCAP;
        } else {
            log_error("Unknown 'sgx.remote_attestation' type (recognized values are \"none\" "
                      "and \"dcap\")");
            ret = -EINVAL;
            goto out;
        }
    }

    *out_attestation_type = attestation_type;
    ret = 0;
out:
    free(sgx_attestation_type_str);
    return ret;
}
