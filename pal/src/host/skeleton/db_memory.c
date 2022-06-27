/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs that allocate, free or protect virtual memory.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

bool _PalCheckMemoryMappable(const void* addr, size_t size) {
    return true;
}

int _PalVirtualMemoryAlloc(void** addr_ptr, uint64_t size, pal_alloc_flags_t alloc_type,
                           pal_prot_flags_t prot) {
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
