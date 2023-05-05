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

static int get_epid_params(toml_table_t* manifest_root, char** out_spid_str, bool* out_linkable) {
    int ret;

    char* spid_str;
    ret = toml_string_in(manifest_root, "sgx.ra_client_spid", &spid_str);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.ra_client_spid'");
        return -EINVAL;
    }

    bool linkable;
    ret = toml_bool_in(manifest_root, "sgx.ra_client_linkable", /*defaultval=*/false, &linkable);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.ra_client_linkable' (the value must be `true` or `false`)");
        free(spid_str);
        return -EINVAL;
    }

    *out_spid_str = spid_str;
    *out_linkable = linkable;
    return 0;
}

int parse_attestation_type(toml_table_t* manifest_root,
                           enum sgx_attestation_type* out_attestation_type) {
    int ret;
    char* sgx_attestation_type_str = NULL;
    char* sgx_ra_client_spid_str = NULL;
    bool dummy_linkable;
    enum sgx_attestation_type attestation_type = SGX_ATTESTATION_NONE;

    /* we parse SPID and linkable here even if there is no sgx.remote_attestation (or it is not
     * EPID), simply to error out early on incorrect values */
    ret = get_epid_params(manifest_root, &sgx_ra_client_spid_str, &dummy_linkable);
    if (ret < 0)
        goto out;

    ret = toml_string_in(manifest_root, "sgx.remote_attestation", &sgx_attestation_type_str);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.remote_attestation'");
        ret = -EINVAL;
        goto out;
    }

    if (sgx_attestation_type_str) {
        if (!strcmp(sgx_attestation_type_str, "none")) {
            attestation_type = SGX_ATTESTATION_NONE;
        } else if (!strcmp(sgx_attestation_type_str, "epid")) {
            attestation_type = SGX_ATTESTATION_EPID;
        } else if (!strcmp(sgx_attestation_type_str, "dcap")) {
            attestation_type = SGX_ATTESTATION_DCAP;
        } else {
            log_error("Unknown 'sgx.remote_attestation' type (recognized values are \"none\", "
                      "\"epid\" and \"dcap\")");
            ret = -EINVAL;
            goto out;
        }
    }

    *out_attestation_type = attestation_type;
    ret = 0;
out:
    free(sgx_attestation_type_str);
    free(sgx_ra_client_spid_str);
    return ret;
}

int parse_attestation_epid_params(toml_table_t* manifest_root, sgx_spid_t* out_spid,
                                  bool* out_linkable) {
    int ret;
    char* sgx_ra_client_spid_str = NULL;
    sgx_spid_t spid = {0};
    bool linkable = false;

    ret = get_epid_params(manifest_root, &sgx_ra_client_spid_str, &linkable);
    if (ret < 0)
        goto out;

    if (!sgx_ra_client_spid_str || strlen(sgx_ra_client_spid_str) != sizeof(spid) * 2) {
        log_error("Malformed 'sgx.ra_client_spid' value in the manifest: %s",
                  sgx_ra_client_spid_str);
        ret = -EINVAL;
        goto out;
    }

    /* sgx.ra_client_spid must be hex string */
    for (size_t i = 0; i < strlen(sgx_ra_client_spid_str); i++) {
        int8_t val = hex2dec(sgx_ra_client_spid_str[i]);
        if (val < 0) {
            log_error("Malformed 'sgx.ra_client_spid' value in the manifest: %s",
                      sgx_ra_client_spid_str);
            ret = -EINVAL;
            goto out;
        }
        spid[i / 2] = spid[i / 2] * 16 + (uint8_t)val;
    }

    memcpy(out_spid, &spid, sizeof(spid));
    *out_linkable = linkable;
    ret = 0;
out:
    free(sgx_ra_client_spid_str);
    return ret;
}
