/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#pragma once

#include <stdbool.h>
#include <stddef.h>

bool get_norm_path(const char* path, char* buf, size_t* inout_size);

bool get_base_name(const char* path, char* buf, size_t* inout_size);

bool is_dot_or_dotdot(const char* name);
