/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Fortanix Inc
 *                    Nirjhar Roy <nirjhar.roy@fortanix.com>
 */

/* This file contains functions that check various features and flags specific to x86 */

#include <stddef.h>

#include "api.h"
#include "cpu.h"

bool is_x86_instr_legacy_prefix(uint8_t op) {
    uint8_t prefix_list[] = {
                             /* Group 1 */
                             0xf0, /* LOCK prefix */
                             0xf2, /* REPNE/REPNZ prefix */
                             0xf3, /* REP or REPE/REPZ prefix */
                             /* Group 2 */
                             0x2e, /* CS segment override */
                             0x36, /* SS segment override */
                             0x3e, /* DS segment override */
                             0x26, /* ES segment override */
                             0x64, /* FS segment override */
                             0x65, /* GS segment override */
                             0x2e, /* Branch not taken */
                             0x3e, /* Branch taken */
                             /* Group 3 */
                             0x66, /*  Operand-size override prefix */
                             /* Group 4 */
                             0x67, /* Address-size override prefix  */
                            };
    for (size_t i = 0; i < ARRAY_SIZE(prefix_list); i++) {
        if (op == prefix_list[i])
            return true;
    }
    return false;
}
