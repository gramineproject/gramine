/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Wojtek Porczyk <woju@invisiblethingslab.com>
 */

#pragma once

#include <stddef.h>

int sgx_create_process(size_t nargs, const char** args, const char* manifest,
                       void* reserved_mem_ranges, size_t reserved_mem_ranges_size,
                       int* out_stream_fd);

int sgx_init_child_process(int parent_stream_fd, char** out_application_path, char** out_manifest,
                           void** out_reserved_mem_ranges, size_t* out_reserved_mem_ranges_size);
