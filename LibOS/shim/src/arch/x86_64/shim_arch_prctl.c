/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <asm/prctl.h>

#include "pal.h"
#include "shim_internal.h"
#include "shim_table.h"
#include "shim_tcb.h"

/* To support AMX in linux kernel v5.16, prctl add XSTATE components permission
 * control APIs, refer:
 * https://elixir.bootlin.com/linux/v5.16/source/arch/x86/include/uapi/asm/prctl.h
 */
#if !defined(ARCH_GET_XCOMP_SUPP)
#define ARCH_GET_XCOMP_SUPP	0x1021
#endif
#if !defined(ARCH_GET_XCOMP_PERM)
#define ARCH_GET_XCOMP_PERM	0x1022
#endif
#if !defined(ARCH_REQ_XCOMP_PERM)
#define ARCH_REQ_XCOMP_PERM	0x1023
#endif

long shim_do_arch_prctl(int code, unsigned long addr) {
    switch (code) {
        case ARCH_SET_FS:
            set_tls(addr);
            return 0;

        case ARCH_GET_FS:
            return pal_to_unix_errno(DkSegmentBaseGet(PAL_SEGMENT_FS, (unsigned long*)addr));

        case ARCH_GET_XCOMP_SUPP:
        case ARCH_GET_XCOMP_PERM:
            return pal_to_unix_errno(DkXCompPerm(code, (unsigned long*)addr));
        case ARCH_REQ_XCOMP_PERM:
            return pal_to_unix_errno(DkXCompPerm(code, &addr));

        default:
            log_warning("Not supported flag (0x%x) passed to arch_prctl", code);
            return -ENOSYS;
    }
}
