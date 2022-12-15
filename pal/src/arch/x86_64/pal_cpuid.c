/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#include "pal_internal.h"

#define BPI  32
#define POWER2(power) \
    (1ULL << (power))
#define RIGHTMASK(width) \
    (((unsigned long)(width) >= BPI) ? ~0ULL : POWER2(width) - 1ULL)

#define BIT_EXTRACT_LE(value, start, after) \
    (((unsigned long)(value) & RIGHTMASK(after)) >> start)

#define FOUR_CHARS_VALUE(s, w)      \
    (s)[0] = (w) & 0xff;            \
    (s)[1] = ((w) >>  8) & 0xff;    \
    (s)[2] = ((w) >> 16) & 0xff;    \
    (s)[3] = ((w) >> 24) & 0xff;

int _PalGetCPUInfo(struct pal_cpu_info* ci) {
    unsigned int words[CPUID_WORD_NUM];
    int rv = 0;
    char* brand = NULL;
    char* vendor_id = NULL;

    const size_t VENDOR_ID_SIZE = 13;
    vendor_id = malloc(VENDOR_ID_SIZE);
    if (!vendor_id)
        return -PAL_ERROR_NOMEM;

    _PalCpuIdRetrieve(CPU_VENDOR_LEAF, 0, words);
    FOUR_CHARS_VALUE(&vendor_id[0], words[CPUID_WORD_EBX]);
    FOUR_CHARS_VALUE(&vendor_id[4], words[CPUID_WORD_EDX]);
    FOUR_CHARS_VALUE(&vendor_id[8], words[CPUID_WORD_ECX]);
    vendor_id[VENDOR_ID_SIZE - 1] = '\0';
    ci->cpu_vendor = vendor_id;

    const size_t BRAND_SIZE = 49;
    brand = malloc(BRAND_SIZE);
    if (!brand) {
        rv = -PAL_ERROR_NOMEM;
        goto out_err;
    }
    _PalCpuIdRetrieve(CPU_BRAND_LEAF, 0, words);
    memcpy(&brand[ 0], words, sizeof(unsigned int) * CPUID_WORD_NUM);
    _PalCpuIdRetrieve(CPU_BRAND_CNTD_LEAF, 0, words);
    memcpy(&brand[16], words, sizeof(unsigned int) * CPUID_WORD_NUM);
    _PalCpuIdRetrieve(CPU_BRAND_CNTD2_LEAF, 0, words);
    memcpy(&brand[32], words, sizeof(unsigned int) * CPUID_WORD_NUM);
    brand[BRAND_SIZE - 1] = '\0';
    ci->cpu_brand = brand;

    _PalCpuIdRetrieve(FEATURE_FLAGS_LEAF, 0, words);
    ci->cpu_family   = BIT_EXTRACT_LE(words[CPUID_WORD_EAX], 8, 12);
    ci->cpu_model    = BIT_EXTRACT_LE(words[CPUID_WORD_EAX], 4, 8);
    ci->cpu_stepping = BIT_EXTRACT_LE(words[CPUID_WORD_EAX], 0, 4);

    if (!memcmp(vendor_id, "GenuineIntel", 12) || !memcmp(vendor_id, "AuthenticAMD", 12)) {
        ci->cpu_family += BIT_EXTRACT_LE(words[CPUID_WORD_EAX], 20, 28);
        ci->cpu_model  += BIT_EXTRACT_LE(words[CPUID_WORD_EAX], 16, 20) << 4;
    }

    ci->cpu_bogomips = _PalGetBogomips();
    if (ci->cpu_bogomips == 0.0) {
        log_warning("bogomips could not be retrieved, passing 0.0 to the application");
    }

    return 0;

out_err:
    free(brand);
    free(vendor_id);
    return rv;
}
