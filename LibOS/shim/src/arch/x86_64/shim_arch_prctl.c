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

long shim_do_arch_prctl(int code, unsigned long addr) {
    unsigned int values[CPUID_WORD_NUM];
    unsigned int amx_mask;
    int ret;

    switch (code) {
        case ARCH_SET_FS:
            set_tls(addr);
            return 0;

        case ARCH_GET_FS:
            return pal_to_unix_errno(DkSegmentBaseGet(PAL_SEGMENT_FS, (unsigned long*)addr));

        /* Emulate ARCH_GET_XCOMP_SUPP, ARCH_GET_XCOMP_PERM, ARCH_REQ_XCOMP_PERM by
         * querying CPUID, it's safe because the PAL already requested AMX permission
         * at startup */
        case ARCH_GET_XCOMP_SUPP:
        case ARCH_GET_XCOMP_PERM:
            ret = DkCpuIdRetrieve(EXTENDED_STATE_LEAF, 0, values);
            if (ret < 0) {
                return pal_to_unix_errno(ret);
            }
            *(uint64_t*)addr = values[CPUID_WORD_EAX] | ((uint64_t)values[CPUID_WORD_EDX] << 32);
            return 0;

        case ARCH_REQ_XCOMP_PERM:
            /* The request must be the highest state component number related to that facility,
             * current Linux kernel supports only AMX_TILEDATA (bit 18) */
            if (addr != AMX_TILEDATA) {
                log_warning("ARCH_REQ_XCOMP_PERM on unsupported feature %lu requested", addr);
                return -EOPNOTSUPP;
            }

            ret = DkCpuIdRetrieve(EXTENDED_STATE_LEAF, 0, values);
            if (ret < 0) {
                return pal_to_unix_errno(ret);
            }

            amx_mask = (1 << AMX_TILECFG) | (1 << AMX_TILEDATA);
            if ((values[CPUID_WORD_EAX] & amx_mask) != amx_mask) {
                log_warning("AMX is not supported on this CPU (XSAVE bits are 0x%x)",
                            values[CPUID_WORD_EAX]);
                return -EINVAL;
            }

            /* PAL already requested AMX permission at startup, here just a no-op */
            return 0;

        default:
            log_warning("Not supported flag (0x%x) passed to arch_prctl", code);
            return -ENOSYS;
    }
}
