/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * This file contains Linux on x86_64 specific functions related to the PAL.
 */

#pragma once

#ifdef IN_PAL

#if defined(__i386__)
#include <asm/ldt.h>
#else
#include <asm/prctl.h>
#endif

#include "api.h"
#include "cpu.h"
#include "syscall.h"

/* Linux v5.16 supports Intel AMX. To enable this feature, Linux added several XSTATE-related
 * arch_prctl() commands. To support Gramine on older Linux kernels, we explicitly define
 * the required ARCH_REQ_XCOMP_PERM command. See
 * https://elixir.bootlin.com/linux/v5.16/source/arch/x86/include/uapi/asm/prctl.h */
#ifndef ARCH_REQ_XCOMP_PERM
#define ARCH_REQ_XCOMP_PERM 0x1023
#endif

#define ARCH_HIGHEST_ADDR ((1ul << 47) - PAGE_SIZE)

/* Gramine uses GCC's stack protector that looks for canary at gs:[0x8], but this function changes
 * the GS register value, so we disable stack protector here (even though it is mostly inlined) */
__attribute_no_stack_protector
static inline int pal_set_tcb(PAL_TCB* tcb) {
    return DO_SYSCALL(arch_prctl, ARCH_SET_GS, tcb);
}

#endif /* IN_PAL */
