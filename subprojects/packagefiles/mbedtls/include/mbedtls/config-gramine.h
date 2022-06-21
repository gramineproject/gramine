/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * This is the configuration for Gramine's userspace build of mbedtls. It overrides the default
 * `mbedtls/config.h`.
 */

#pragma once

#include "mbedtls/config.h"

#define MBEDTLS_CMAC_C

#include "mbedtls/check_config.h"
