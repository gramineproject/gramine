/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Fortanix Inc
 *                    Nirjhar Roy <nirjhar.roy@fortanix.com>
 */

/* This file contains functions that check various features and flags specific to x86 */

#include <stddef.h>

#include "api.h"
#include "cpu.h"

#define INSTR_SIZE_MAX 15

bool is_x86_instr_legacy_prefix(uint8_t op) {
    /*
     * Official source for this list is Intel SDM, Vol. 2, Chapter 2.1.1 "Instruction Prefixes".
     * These prefixes are called "legacy" for x86-64 (64-bit mode) instructions, see Intel SDM,
     * Vol. 2, Chapter 2.2.1 and Figure 2-3 "Prefix Ordering in 64-bit Mode".
     */
    switch (op) {
        /* Group 1 */
        case 0xf0: /* LOCK prefix */
        case 0xf2: /* REPNE/REPNZ prefix */
        case 0xf3: /* REP or REPE/REPZ prefix */
        /* Group 2 */
        case 0x2e: /* CS segment override; Branch not taken */
        case 0x36: /* SS segment override */
        case 0x3e: /* DS segment override; Branch taken */
        case 0x26: /* ES segment override */
        case 0x64: /* FS segment override */
        case 0x65: /* GS segment override */
        /* Group 3 */
        case 0x66: /*  Operand-size override prefix */
        /* Group 4 */
        case 0x67: /* Address-size override prefix */
            return true;
    }
    return false;
}

bool is_x86_instr_rex_prefix(uint8_t op) {
    /*
     * Optional REX prefix is located after all legacy prefixes (see above) and right before the
     * opcode. REX prefix is 1 byte with bits [0100WRXB], from which follows that REX prefix can be
     * any of 0x40-0x4f. For details, see Intel SDM, Vol. 2, Chapter 2.2.1 "REX Prefixes".
     */
    return 0x40 <= op && op <= 0x4f;
}

bool has_lock_prefix(uint8_t* rip) {
    size_t idx = 0;
    while (is_x86_instr_legacy_prefix(rip[idx]) && idx < INSTR_SIZE_MAX) {
        if (rip[idx] == 0xf0)
            return true;
        idx++;
    }
    return false;
}

bool is_in_out(uint8_t* rip) {
    /*
     * x86-64 instructions may be at most 15 bytes in length and may have multiple instruction
     * prefixes. See description in Intel SDM, Vol. 2, Chapter 2.1.1 "Instruction Prefixes".
     */
    size_t idx = 0;
    while (is_x86_instr_legacy_prefix(rip[idx]) && idx < INSTR_SIZE_MAX)
        idx++;

    if (idx == INSTR_SIZE_MAX)
        return false;

    /* skip over the optional REX prefix */
    if (is_x86_instr_rex_prefix(rip[idx]))
        idx++;

    if (idx == INSTR_SIZE_MAX)
        return false;

    switch (rip[idx]) {
        /* INS opcodes */
        case 0x6c:
        case 0x6d:
        /* OUTS opcodes */
        case 0x6e:
        case 0x6f:
        /* IN immediate opcodes */
        case 0xe4:
        case 0xe5:
        /* OUT immediate opcodes */
        case 0xe6:
        case 0xe7:
        /* IN register opcodes */
        case 0xec:
        case 0xed:
        /* OUT register opcodes */
        case 0xee:
        case 0xef:
            return true;
    }

    return false;
}
