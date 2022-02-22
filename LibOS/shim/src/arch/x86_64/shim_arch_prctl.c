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

#define CPUID_LEAF_XSAVE 0x0000000d

long shim_do_arch_prctl(int code, unsigned long addr) {
    unsigned int value[4];
    unsigned long amx_mask;
    int ret;

    switch (code) {
        case ARCH_SET_FS:
            set_tls(addr);
            return 0;

        case ARCH_GET_FS:
            return pal_to_unix_errno(DkSegmentBaseGet(PAL_SEGMENT_FS, (unsigned long*)addr));

        /* Emulate ARCH_GET_XCOMP_SUPP, ARCH_GET_XCOMP_PERM, ARCH_REQ_XCOMP_PERM by
         * querying CPUID, it's safe because the "loader" has requested AMX permission
         */
        case ARCH_GET_XCOMP_SUPP:
        case ARCH_GET_XCOMP_PERM:
            ret = DkCpuIdRetrieve(CPUID_LEAF_XSAVE, 0, value);
            if ( ret < 0) {
                log_warning("CPUID retrieve faild: %d", ret);
                return pal_to_unix_errno(ret);
            }
            *(unsigned long*)addr = value[CPUID_WORD_EAX] | ((uint64_t)value[CPUID_WORD_EDX] << 32);
            return 0;
        case ARCH_REQ_XCOMP_PERM:
            /* The request must be the highest state component number related to that facility,
             * current kernel only support to AMX_TILEDATA (18) */
            if (addr != AMX_TILEDATA)
            {
                log_warning("Unsupported permission requested: %ld", addr);
                return -EOPNOTSUPP;
            }

            ret = DkCpuIdRetrieve(CPUID_LEAF_XSAVE, 0, value);
            if ( ret < 0) {
                log_warning("CPUID retrieve faild: %d", ret);
                return pal_to_unix_errno(ret);
            }

            amx_mask = (1 << AMX_TILECFG) | (1 << AMX_TILEDATA);
            if ((value[CPUID_WORD_EAX] & amx_mask) != amx_mask)
            {
                log_warning("AMX is not supported: 0x%x", value[CPUID_WORD_EAX]);
                return -EINVAL;
            }
            return 0;

        default:
            log_warning("Not supported flag (0x%x) passed to arch_prctl", code);
            return -ENOSYS;
    }
}
