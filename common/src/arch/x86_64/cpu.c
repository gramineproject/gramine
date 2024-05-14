/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Fortanix Inc
 *                    Nirjhar Roy <nirjhar.roy@fortanix.com>
 */

/* This file contains functions that check various features and flags specific to x86 */

#include <stddef.h>

#include "api.h"
#include "cpu.h"

bool is_x86_instr_legacy_prefix(uint8_t op) {
    /*
     * Official source for this list is Intel SDM, Vol. 2, Chapter 2.1.1 "Instruction Prefixes".
     * These prefixes are called "legacy" for x86-64 (64-bit mode) instructions, see Intel SDM,
     * Vol. 2, Chapter 2.2.1 and Figure 2-3 "Prefix Ordering in 64-bit Mode".
     */
    uint8_t prefix_list[] = {
        /* Group 1 */
        0xf0, /* LOCK prefix */
        0xf2, /* REPNE/REPNZ prefix */
        0xf3, /* REP or REPE/REPZ prefix */
        /* Group 2 */
        0x2e, /* CS segment override; Branch not taken */
        0x36, /* SS segment override */
        0x3e, /* DS segment override; Branch taken */
        0x26, /* ES segment override */
        0x64, /* FS segment override */
        0x65, /* GS segment override */
        /* Group 3 */
        0x66, /*  Operand-size override prefix */
        /* Group 4 */
        0x67, /* Address-size override prefix */
    };
    for (size_t i = 0; i < ARRAY_SIZE(prefix_list); i++) {
        if (op == prefix_list[i])
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
    return (0x40 <= op && op <= 0x4f);
}

bool is_in_out(uint8_t* rip) {
    uint8_t opcodes[] = {
        /* INS opcodes */
        0x6c,
        0x6d,
        /* OUTS opcodes */
        0x6e,
        0x6f,
        /* IN immediate opcodes */
        0xe4,
        0xe5,
        /* OUT immediate opcodes */
        0xe6,
        0xe7,
        /* IN register opcodes */
        0xec,
        0xed,
        /* OUT register opcodes */
        0xee,
        0xef,
    };

    /*
     * x86-64 instructions can have up to four legacy prefixes. This follows from description in
     * Intel SDM, Vol. 2, Chapter 2.1.1 "Instruction Prefixes":
     *
     *   Instruction prefixes are divided into four groups, each with a set of allowable prefix
     *   codes. For each instruction, it is only useful to include up to one prefix code from each
     *   of the four groups (Groups 1, 2, 3, 4).
     */
    size_t idx = 0;
    while (is_x86_instr_legacy_prefix(rip[idx]) && idx < 4)
        idx++;

    /* skip over the optional REX prefix */
    if (is_x86_instr_rex_prefix(rip[idx]))
        idx++;

    for (size_t i = 0; i < ARRAY_SIZE(opcodes); i++)
        if (rip[idx] == opcodes[i])
            return true;

    return false;
}
