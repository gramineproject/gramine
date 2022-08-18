/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Labs */

#pragma once

#include <stdint.h>

#include "mbedtls/ssl.h"

int secret_provision_common_write(mbedtls_ssl_context* ssl, const uint8_t* buf, size_t size);
int secret_provision_common_read(mbedtls_ssl_context* ssl, uint8_t* buf, size_t size);
int secret_provision_common_close(mbedtls_ssl_context* ssl);
