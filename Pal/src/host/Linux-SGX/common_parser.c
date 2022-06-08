/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation */

/* Common utilities to parse the manifest. */

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
    char* sgx_ra_client_spid_str = NULL;

    enum sgx_attestation_type attestation_type = SGX_ATTESTATION_NONE;
    ret = toml_string_in(manifest_root, "sgx.remote_attestation", &sgx_attestation_type_str);
    if (!ret) {
        if (sgx_attestation_type_str) {
            if (!strcmp(sgx_attestation_type_str, "none")) {
                attestation_type = SGX_ATTESTATION_NONE;
            } else if (!strcmp(sgx_attestation_type_str, "epid")) {
                attestation_type = SGX_ATTESTATION_EPID;
            } else if (!strcmp(sgx_attestation_type_str, "dcap")) {
                attestation_type = SGX_ATTESTATION_DCAP;
            } else {
                log_error("Unknown 'sgx.remote_attestation' type");
                ret = -EINVAL;
                goto out;
            }
        }
    } else {
        /* TODO: Bool syntax is deprecated in v1.3, remove 2 versions later. */
        bool sgx_remote_attestation_enabled;
        ret = toml_bool_in(manifest_root, "sgx.remote_attestation", /*defaultval=*/false,
                &sgx_remote_attestation_enabled);
        if (ret < 0) {
            log_error("Cannot parse 'sgx.remote_attestation' (the value must be \"none\", \"epid\" "
                      "or \"dcap\", or in case of legacy syntax `true` or `false`)");
            ret = -EINVAL;
            goto out;
        }
        if (sgx_remote_attestation_enabled)
            attestation_type = SGX_ATTESTATION_UNCLEAR;
        log_always("Detected deprecated syntax 'sgx.remote_attestation = true|false'; "
                    "consider using 'sgx.remote_attestation = \"none\"|\"epid\"|\"dcap\"'.");
    }

    ret = toml_string_in(manifest_root, "sgx.ra_client_spid", &sgx_ra_client_spid_str);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.ra_client_spid'");
        ret = -EINVAL;
        goto out;
    }

    /* legacy syntax: EPID is used if SPID is a non-empty string in manifest, otherwise DCAP */
    if (attestation_type == SGX_ATTESTATION_UNCLEAR) {
        if (sgx_ra_client_spid_str && strlen(sgx_ra_client_spid_str)) {
            attestation_type = SGX_ATTESTATION_EPID;
        } else {
            attestation_type = SGX_ATTESTATION_DCAP;
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

    ret = toml_string_in(manifest_root, "sgx.ra_client_spid", &sgx_ra_client_spid_str);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.ra_client_spid'");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    if (!sgx_ra_client_spid_str || strlen(sgx_ra_client_spid_str) != sizeof(spid) * 2) {
        log_error("Malformed 'sgx.ra_client_spid' value in the manifest: %s",
                  sgx_ra_client_spid_str);
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    /* sgx.ra_client_spid must be hex string */
    for (size_t i = 0; i < strlen(sgx_ra_client_spid_str); i++) {
        int8_t val = hex2dec(sgx_ra_client_spid_str[i]);
        if (val < 0) {
            log_error("Malformed 'sgx.ra_client_spid' value in the manifest: %s",
                      sgx_ra_client_spid_str);
            ret = -PAL_ERROR_INVAL;
            goto out;
        }
        spid[i / 2] = spid[i / 2] * 16 + (uint8_t)val;
    }

    ret = toml_bool_in(manifest_root, "sgx.ra_client_linkable", /*defaultval=*/false, &linkable);
    if (ret < 0) {
        log_error("Cannot parse 'sgx.ra_client_linkable' (the value must be `true` or `false`)");
        ret = -PAL_ERROR_INVAL;
        goto out;
    }

    memcpy(out_spid, &spid, sizeof(spid));
    *out_linkable = linkable;
    ret = 0;
out:
    free(sgx_ra_client_spid_str);
    return ret;
}
