/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

#include <stdbool.h>
#include <stddef.h>

int get_norm_path(const char* path, char* buf, size_t* inout_size);

int get_base_name(const char* path, char* buf, size_t* inout_size);

bool is_dot_or_dotdot(const char* name);
