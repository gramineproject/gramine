/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs that allocate, free or protect virtual memory.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

int _PalVirtualMemoryAlloc(void* addr, uint64_t size, pal_prot_flags_t prot) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _PalVirtualMemoryFree(void* addr, uint64_t size) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _PalVirtualMemoryProtect(void* addr, uint64_t size, pal_prot_flags_t prot) {
    return -PAL_ERROR_NOTIMPLEMENTED;
}

unsigned long _PalMemoryQuota(void) {
    return 0;
}

unsigned long _PalMemoryAvailableQuota(void) {
    return 0;
}

void pal_read_one_reserved_range(uintptr_t* last_range_start, uintptr_t* last_range_end) {
    *last_range_start = 0;
    *last_range_end = 0;
}
