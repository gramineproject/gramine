/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains definitions of PAL error codes.
 */

#pragma once

#include <stddef.h>

typedef enum _pal_error_t {
    PAL_ERROR_SUCCESS = 0,
    PAL_ERROR_NOTIMPLEMENTED = -1,
    PAL_ERROR_NOTDEFINED = -2,
    PAL_ERROR_NOTSUPPORT = -3,
    PAL_ERROR_INVAL = -4,
    PAL_ERROR_TOOLONG = -5,
    PAL_ERROR_DENIED = -6,
    PAL_ERROR_BADHANDLE = -7,
    PAL_ERROR_STREAMEXIST = -8,
    PAL_ERROR_STREAMNOTEXIST = -9,
    PAL_ERROR_STREAMISFILE = -10,
    PAL_ERROR_STREAMISDIR = -11,
    PAL_ERROR_STREAMISDEVICE = -12,
    PAL_ERROR_INTERRUPTED = -13,
    PAL_ERROR_OVERFLOW = -14,
    PAL_ERROR_BADADDR = -15,
    PAL_ERROR_NOMEM = -16,
    PAL_ERROR_INCONSIST = -17,
    PAL_ERROR_TRYAGAIN = -18,
    PAL_ERROR_NOTSERVER = -19,
    PAL_ERROR_NOTCONNECTION = -20,
    PAL_ERROR_CONNFAILED = -21,
    PAL_ERROR_ADDRNOTEXIST = -22,
    PAL_ERROR_AFNOSUPPORT = -23,
    PAL_ERROR_CONNFAILED_PIPE = -24,

#define PAL_ERROR_NATIVE_COUNT ((-PAL_ERROR_CONNFAILED_PIPE) + 1)
#define PAL_ERROR_CRYPTO_START PAL_ERROR_CRYPTO_FEATURE_UNAVAILABLE

    /* Crypto error constants and their descriptions are adapted from mbedtls. */
    PAL_ERROR_CRYPTO_FEATURE_UNAVAILABLE = -1000,
    PAL_ERROR_CRYPTO_INVALID_CONTEXT = -1001,
    PAL_ERROR_CRYPTO_INVALID_KEY_LENGTH = -1002,
    PAL_ERROR_CRYPTO_INVALID_INPUT_LENGTH = -1003,
    PAL_ERROR_CRYPTO_INVALID_OUTPUT_LENGTH = -1004,
    PAL_ERROR_CRYPTO_BAD_INPUT_DATA = -1005,
    PAL_ERROR_CRYPTO_INVALID_PADDING = -1006,
    PAL_ERROR_CRYPTO_DATA_MISALIGNED = -1007,
    PAL_ERROR_CRYPTO_INVALID_FORMAT = -1008,
    PAL_ERROR_CRYPTO_AUTH_FAILED = -1009,
    PAL_ERROR_CRYPTO_IO_ERROR = -1010,
    PAL_ERROR_CRYPTO_KEY_GEN_FAILED = -1011,
    PAL_ERROR_CRYPTO_INVALID_KEY = -1012,
    PAL_ERROR_CRYPTO_VERIFY_FAILED = -1013,
    PAL_ERROR_CRYPTO_RNG_FAILED = -1014,
    PAL_ERROR_CRYPTO_INVALID_DH_STATE = -1015,
#define PAL_ERROR_CRYPTO_END PAL_ERROR_CRYPTO_INVALID_DH_STATE
} pal_error_t;

/* err - value of error code, either positive or negative */
const char* pal_strerror(int err);
