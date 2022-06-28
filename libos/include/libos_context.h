/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * This file contains definitions for CPU context.
 */

#pragma once

#include <stdint.h>

void libos_xstate_init(void);
uint64_t libos_xstate_size(void);
void libos_xstate_restore(const void* xstate_extended);
