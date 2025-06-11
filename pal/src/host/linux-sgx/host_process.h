/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Wojtek Porczyk <woju@invisiblethingslab.com>
 */

#pragma once

#include <stddef.h>
#include "sgx_arch.h"

int sgx_create_process(size_t nargs, const char** args, const char* manifest,
                       void* reserved_mem_ranges, size_t reserved_mem_ranges_size,
                       sgx_config_id_t config_id, sgx_config_svn_t config_svn, int* out_stream_fd);

int sgx_init_child_process(int parent_stream_fd, char** out_application_path, char** out_manifest,
                           void** out_reserved_mem_ranges, size_t* out_reserved_mem_ranges_size,
                           sgx_config_id_t* out_config_id, sgx_config_svn_t* out_config_svn);
