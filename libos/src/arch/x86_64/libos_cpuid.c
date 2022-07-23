/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 */

#include "cpu.h"
#include "libos_cpuid.h"
#include "libos_internal.h"
#include "libos_utils.h"

static const char* const g_cpu_flags[] = {
    "fpu",    // "x87 FPU on chip"
    "vme",    // "virtual-8086 mode enhancement"
    "de",     // "debugging extensions"
    "pse",    // "page size extensions"
    "tsc",    // "time stamp counter"
    "msr",    // "RDMSR and WRMSR support"
    "pae",    // "physical address extensions"
    "mce",    // "machine check exception"
    "cx8",    // "CMPXCHG8B inst."
    "apic",   // "APIC on chip"
    NULL,
    "sep",    // "SYSENTER and SYSEXIT"
    "mtrr",   // "memory type range registers"
    "pge",    // "PTE global bit"
    "mca",    // "machine check architecture"
    "cmov",   // "conditional move/compare instruction"
    "pat",    // "page attribute table"
    "pse36",  // "page size extension"
    "pn",     // "processor serial number"
    "clflush",    // "CLFLUSH instruction"
    NULL,
    "dts",    // "debug store"
    "acpi",   // "Onboard thermal control"
    "mmx",    // "MMX Technology"
    "fxsr",   // "FXSAVE/FXRSTOR"
    "sse",    // "SSE extensions"
    "sse2",   // "SSE2 extensions"
    "ss",     // "self snoop"
    "ht",     // "hyper-threading / multi-core supported"
    "tm",     // "therm. monitor"
    "ia64",   // "IA64"
    "pbe",    // "pending break event"
};

int libos_get_cpu_flags(char** out_cpu_flags) {
    unsigned int words[CPUID_WORD_NUM];
    int ret;

    ret = PalCpuIdRetrieve(1, 0, words);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    size_t flen = 0;
    size_t fmax = 80;
    char* flags = malloc(fmax);
    if (!flags) {
        ret = -ENOMEM;
        goto out_err;
    }

    for (size_t i = 0; i < 32; i++) {
        if (!g_cpu_flags[i])
            continue;

        if ((words[CPUID_WORD_EDX] >> i) & 1) {
            size_t len = strlen(g_cpu_flags[i]);
            if (flen + len + 1 > fmax) {
                /* TODO: use `realloc()` once it's available. */
                char* new_flags = malloc(fmax * 2);
                if (!new_flags) {
                    ret = -ENOMEM;
                    goto out_err;
                }
                memcpy(new_flags, flags, flen);
                free(flags);
                fmax *= 2;
                flags = new_flags;
            }
            memcpy(flags + flen, g_cpu_flags[i], len);
            flen += len;
            flags[flen++] = ' ';
        }
    }

    flags[flen ? flen - 1 : 0] = 0;
    *out_cpu_flags = flags;

    return 0;

out_err:
    free(flags);
    return ret;
}
