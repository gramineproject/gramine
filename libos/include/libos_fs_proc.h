/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2022 IBM Corporation
 */

#pragma once

#include "pal.h"

int print_to_str(char** str, size_t off, size_t* size, const char* fmt, ...);

/* every architecture must implement the following 2 functions */
int proc_cpuinfo_display_cpu(char** str, size_t* size, size_t* max,
                             const struct pal_topo_info* topo,
                             const struct pal_cpu_info* cpu, size_t i,
                             struct pal_cpu_thread_info* thread);

int proc_cpuinfo_display_tail(char** str, size_t* size, size_t* max,
                              const struct pal_cpu_info* cpu);
