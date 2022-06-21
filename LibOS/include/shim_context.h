/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * This file contains definitions for CPU context.
 */

#pragma once

void shim_xstate_init(void);
uint64_t shim_xstate_size(void);
void shim_xstate_restore(const void* xstate_extended);
