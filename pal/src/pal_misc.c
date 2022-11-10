/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs for miscellaneous use.
 */

#include "pal.h"
#include "pal_internal.h"

int PalSystemTimeQuery(uint64_t* time) {
    return _PalSystemTimeQuery(time);
}

int PalRandomBitsRead(void* buffer, size_t size) {
    return _PalRandomBitsRead(buffer, size);
}

#if defined(__x86_64__)
int PalSegmentBaseGet(enum pal_segment_reg reg, uintptr_t* addr) {
    return _PalSegmentBaseGet(reg, addr);
}

int PalSegmentBaseSet(enum pal_segment_reg reg, uintptr_t addr) {
    return _PalSegmentBaseSet(reg, addr);
}
#endif

#if defined(__x86_64__)
int PalCpuIdRetrieve(uint32_t leaf, uint32_t subleaf, uint32_t values[4]) {
    return _PalCpuIdRetrieve(leaf, subleaf, values);
}
#endif

int PalAttestationReport(const void* user_report_data, size_t* user_report_data_size,
                         void* target_info, size_t* target_info_size, void* report,
                         size_t* report_size) {
    return _PalAttestationReport(user_report_data, user_report_data_size, target_info,
                                target_info_size, report, report_size);
}

int PalAttestationQuote(const void* user_report_data, size_t user_report_data_size, void* quote,
                        size_t* quote_size) {
    return _PalAttestationQuote(user_report_data, user_report_data_size, quote, quote_size);
}

int PalGetSpecialKey(const char* name, void* key, size_t* key_size) {
    return _PalGetSpecialKey(name, key, key_size);
}
