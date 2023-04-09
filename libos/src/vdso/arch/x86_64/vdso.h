/* SPDX-License-Identifier: LGPL-3.0-or-later */

#pragma once

#include "libos_types.h"

int __vdso_clock_gettime(clockid_t clock, struct timespec* t);
int __vdso_gettimeofday(struct timeval* tv, struct timezone* tz);
time_t __vdso_time(time_t* t);
long __vdso_getcpu(unsigned* cpu, void* unused_cache);
