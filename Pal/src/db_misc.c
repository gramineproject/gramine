/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs for miscellaneous use.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

int DkSystemTimeQuery(PAL_NUM* time) {
    return _DkSystemTimeQuery(time);
}

int DkRandomBitsRead(void* buffer, PAL_NUM size) {
    return _DkRandomBitsRead(buffer, size);
}

#if defined(__x86_64__)
int DkSegmentBaseGet(enum pal_segment_reg reg, uintptr_t* addr) {
    return _DkSegmentBaseGet(reg, addr);
}

int DkSegmentBaseSet(enum pal_segment_reg reg, uintptr_t addr) {
    return _DkSegmentBaseSet(reg, addr);
}
#endif

PAL_NUM DkMemoryAvailableQuota(void) {
    long quota = _DkMemoryAvailableQuota();
    if (quota < 0)
        quota = 0;

    return (PAL_NUM)quota;
}

int DkCpuIdRetrieve(PAL_IDX leaf, PAL_IDX subleaf, PAL_IDX values[4]) {
    unsigned int vals[4];
    int ret = _DkCpuIdRetrieve(leaf, subleaf, vals);
    if (ret < 0) {
        return ret;
    }

    values[0] = vals[0];
    values[1] = vals[1];
    values[2] = vals[2];
    values[3] = vals[3];

    return 0;
}

int DkAttestationReport(const void* user_report_data, PAL_NUM* user_report_data_size,
                        void* target_info, PAL_NUM* target_info_size, void* report,
                        PAL_NUM* report_size) {
    return _DkAttestationReport(user_report_data, user_report_data_size, target_info,
                                target_info_size, report, report_size);
}

int DkAttestationQuote(const void* user_report_data, PAL_NUM user_report_data_size, void* quote,
                       PAL_NUM* quote_size) {
    return _DkAttestationQuote(user_report_data, user_report_data_size, quote, quote_size);
}

int DkSetProtectedFilesKey(const char* pf_key_hex) {
    return _DkSetProtectedFilesKey(pf_key_hex);
}
