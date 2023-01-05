/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#include "api.h"
#include "pal_error.h"

static const char* g_pal_error_list[] = {
    [PAL_ERROR_SUCCESS] = "Success (PAL_ERROR_SUCCESS)",
    [PAL_ERROR_NOTIMPLEMENTED] = "Function not implemented (PAL_ERROR_NOTIMPLEMENTED)",
    [PAL_ERROR_NOTDEFINED] = "Symbol not defined (PAL_ERROR_NOTDEFINED)",
    [PAL_ERROR_NOTSUPPORT] = "Function not supported (PAL_ERROR_NOTSUPPORT)",
    [PAL_ERROR_INVAL] = "Invalid argument (PAL_ERROR_INVAL)",
    [PAL_ERROR_TOOLONG] = "Name/path is too long (PAL_ERROR_TOOLONG)",
    [PAL_ERROR_DENIED] = "Operation denied (PAL_ERROR_DENIED)",
    [PAL_ERROR_BADHANDLE] = "Handle corrupted (PAL_ERROR_BADHANDLE)",
    [PAL_ERROR_STREAMEXIST] = "Stream already exists (PAL_ERROR_STREAMEXIST)",
    [PAL_ERROR_STREAMNOTEXIST] = "Stream does not exist (PAL_ERROR_STREAMNOTEXIST)",
    [PAL_ERROR_STREAMISFILE] = "Stream is a file (PAL_ERROR_STREAMISFILE)",
    [PAL_ERROR_STREAMISDIR] = "Stream is a directory (PAL_ERROR_STREAMISDIR)",
    [PAL_ERROR_STREAMISDEVICE] = "Stream is a device (PAL_ERROR_STREAMISDEVICE)",
    [PAL_ERROR_INTERRUPTED] = "Operation interrupted (PAL_ERROR_INTERRUPTED)",
    [PAL_ERROR_OVERFLOW] = "Buffer overflowed (PAL_ERROR_OVERFLOW)",
    [PAL_ERROR_BADADDR] = "Invalid address (PAL_ERROR_BADADDR)",
    [PAL_ERROR_NOMEM] = "Not enough memory (PAL_ERROR_NOMEM)",
    [PAL_ERROR_INCONSIST] = "Inconsistent system state (PAL_ERROR_INCONSIST)",
    [PAL_ERROR_TRYAGAIN] = "Try again (PAL_ERROR_TRYAGAIN)",
    [PAL_ERROR_NOTSERVER] = "Not a server (PAL_ERROR_NOTSERVER)",
    [PAL_ERROR_NOTCONNECTION] = "Not a connection (PAL_ERROR_NOTCONNECTION)",
    [PAL_ERROR_CONNFAILED] = "Connection failed (PAL_ERROR_CONNFAILED)",
    [PAL_ERROR_ADDRNOTEXIST] = "Resource address does not exist (PAL_ERROR_ADDRNOTEXIST)",
    [PAL_ERROR_AFNOSUPPORT] = "Address family not supported by protocol (PAL_ERROR_AFNOSUPPORT)",
    [PAL_ERROR_CONNFAILED_PIPE] = "Broken pipe (PAL_ERROR_CONNFAILED_PIPE)",

    [PAL_ERROR_CRYPTO_FEATURE_UNAVAILABLE] = "[Crypto] Feature not available (PAL_ERROR_CRYPTO_FEATURE_UNAVAILABLE)",
    [PAL_ERROR_CRYPTO_INVALID_CONTEXT] = "[Crypto] Invalid context (PAL_ERROR_CRYPTO_INVALID_CONTEXT)",
    [PAL_ERROR_CRYPTO_INVALID_KEY_LENGTH] = "[Crypto] Invalid key length (PAL_ERROR_CRYPTO_INVALID_KEY_LENGTH)",
    [PAL_ERROR_CRYPTO_INVALID_INPUT_LENGTH] = "[Crypto] Invalid input length (PAL_ERROR_CRYPTO_INVALID_INPUT_LENGTH)",
    [PAL_ERROR_CRYPTO_INVALID_OUTPUT_LENGTH] = "[Crypto] Invalid output length (PAL_ERROR_CRYPTO_INVALID_OUTPUT_LENGTH)",
    [PAL_ERROR_CRYPTO_BAD_INPUT_DATA] = "[Crypto] Bad input parameters (PAL_ERROR_CRYPTO_BAD_INPUT_DATA)",
    [PAL_ERROR_CRYPTO_INVALID_PADDING] = "[Crypto] Invalid padding (PAL_ERROR_CRYPTO_INVALID_PADDING)",
    [PAL_ERROR_CRYPTO_DATA_MISALIGNED] = "[Crypto] Data misaligned (PAL_ERROR_CRYPTO_DATA_MISALIGNED)",
    [PAL_ERROR_CRYPTO_INVALID_FORMAT] = "[Crypto] Invalid data format (PAL_ERROR_CRYPTO_INVALID_FORMAT)",
    [PAL_ERROR_CRYPTO_AUTH_FAILED] = "[Crypto] Authentication failed (PAL_ERROR_CRYPTO_AUTH_FAILED)",
    [PAL_ERROR_CRYPTO_IO_ERROR] = "[Crypto] I/O error (PAL_ERROR_CRYPTO_IO_ERROR)",
    [PAL_ERROR_CRYPTO_KEY_GEN_FAILED] = "[Crypto] Key generation failed (PAL_ERROR_CRYPTO_KEY_GEN_FAILED)",
    [PAL_ERROR_CRYPTO_INVALID_KEY] = "[Crypto] Invalid key (PAL_ERROR_CRYPTO_INVALID_KEY)",
    [PAL_ERROR_CRYPTO_VERIFY_FAILED] = "[Crypto] Verification failed (PAL_ERROR_CRYPTO_VERIFY_FAILED)",
    [PAL_ERROR_CRYPTO_RNG_FAILED] = "[Crypto] RNG failed to generate data (PAL_ERROR_CRYPTO_RNG_FAILED)",
    [PAL_ERROR_CRYPTO_INVALID_DH_STATE] = "[Crypto] Invalid DH state (PAL_ERROR_CRYPTO_INVALID_DH_STATE)",
};

const char* pal_strerror(int err) {
    unsigned err_idx = err >= 0 ? err : -err;
    if (err_idx >= ARRAY_SIZE(g_pal_error_list) || !g_pal_error_list[err_idx]) {
        log_error("Unknown PAL error (errcode = %d)", err);
        abort();
    }
    return g_pal_error_list[err_idx];
}
