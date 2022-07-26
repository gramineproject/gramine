/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This file contains APIs that allocate, free or protect virtual memory.
 */

#include <stdalign.h>

#include "api.h"
#include "asan.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"

/* Tracks only anonymous memory - file mappings are not included. */
static size_t g_allocated_pages = 0;

int _PalVirtualMemoryAlloc(void* addr, uint64_t size, pal_prot_flags_t prot) {
    __UNUSED(prot);
    assert(WITHIN_MASK(prot, PAL_PROT_MASK));
    assert(addr && IS_ALIGNED_PTR(addr, g_page_size));
    assert(size && IS_ALIGNED(size, g_page_size));
    assert(access_ok(addr, size));
    assert(sgx_is_completely_within_enclave(addr, size));

#ifdef ASAN
    asan_unpoison_region((uintptr_t)addr, size);
#endif

    /* initialize contents of new memory region to zero (LibOS layer expects zeroed-out memory) */
    memset(addr, 0, size);

    __atomic_add_fetch(&g_allocated_pages, size / g_page_size, __ATOMIC_RELAXED);

    return 0;
}

int _PalVirtualMemoryFree(void* addr, uint64_t size) {
    assert(IS_ALIGNED_PTR(addr, g_page_size) && IS_ALIGNED(size, g_page_size));
    assert(access_ok(addr, size));

    if (sgx_is_completely_within_enclave(addr, size)) {
        assert(g_pal_linuxsgx_state.heap_min <= addr
               && addr + size <= g_pal_linuxsgx_state.heap_max);

#ifdef ASAN
        asan_poison_region((uintptr_t)addr, size, ASAN_POISON_USER);
#endif

        __atomic_sub_fetch(&g_allocated_pages, size / g_page_size, __ATOMIC_RELAXED);
    } else {
        /* possible to have untrusted mapping, simply unmap memory outside the enclave */
        ocall_munmap_untrusted(addr, size);
    }

    return 0;
}

int _PalVirtualMemoryProtect(void* addr, uint64_t size, pal_prot_flags_t prot) {
    __UNUSED(addr);
    __UNUSED(size);
    __UNUSED(prot);

    assert(WITHIN_MASK(prot, PAL_PROT_MASK));

#ifdef ASAN
    if (sgx_is_completely_within_enclave(addr, size)) {
        if (prot) {
            asan_unpoison_region((uintptr_t)addr, size);
        } else {
            asan_poison_region((uintptr_t)addr, size, ASAN_POISON_USER);
        }
    }
#endif

    if (FIRST_TIME()) {
        log_warning("PalVirtualMemoryProtect is unimplemented in Linux-SGX PAL");
    }
    return 0;
}

uint64_t _PalMemoryQuota(void) {
    return g_pal_linuxsgx_state.heap_max - g_pal_linuxsgx_state.heap_min;
}

uint64_t _PalMemoryAvailableQuota(void) {
    return (g_pal_linuxsgx_state.heap_max - g_pal_linuxsgx_state.heap_min) -
           __atomic_load_n(&g_allocated_pages, __ATOMIC_RELAXED) * g_page_size;
}

static uintptr_t (*g_urts_next_reserved_range)[2] = NULL;
static uintptr_t (*g_urts_reserved_ranges_end)[2] = NULL;

void pal_read_one_reserved_range(uintptr_t* last_range_start, uintptr_t* last_range_end) {
    if (g_urts_next_reserved_range == g_urts_reserved_ranges_end) {
        *last_range_start = 0;
        *last_range_end = 0;
        return;
    }

    uintptr_t last_range[2];
    if (!sgx_copy_to_enclave(&last_range, sizeof(last_range),
                             g_urts_next_reserved_range, sizeof(*g_urts_next_reserved_range))) {
        /* Should be impossible as we already checked the pointer. */
        BUG();
    }
    g_urts_next_reserved_range++;

    if (last_range[0] > last_range[1] || last_range[1] > *last_range_start
            || !IS_ALLOC_ALIGNED(last_range[0]) || !IS_ALLOC_ALIGNED(last_range[1])) {
        log_error("URTS passed invalid reserved memory range: %#lx-%#lx (previous was %#lx-%#lx)",
                  last_range[0], last_range[1], *last_range_start, *last_range_end);
        _PalProcessExit(1);
    }

    *last_range_start = last_range[0];
    *last_range_end = last_range[1];
}

int init_reserved_ranges(void* urts_ptr, size_t urts_size) {
    if (!urts_size) {
        return 0;
    }

    if (!IS_ALIGNED_PTR(urts_ptr, alignof(__typeof__(*g_urts_next_reserved_range)))) {
        return -PAL_ERROR_INVAL;
    }
    if (!IS_ALIGNED(urts_size, sizeof(*g_urts_next_reserved_range))) {
        return -PAL_ERROR_INVAL;
    }
    if (!access_ok(urts_ptr, urts_size)) {
        return -PAL_ERROR_INVAL;
    }
    if (!sgx_is_completely_outside_enclave(urts_ptr, urts_size)) {
        return -PAL_ERROR_INVAL;
    }

    g_urts_next_reserved_range = urts_ptr;
    g_urts_reserved_ranges_end = g_urts_next_reserved_range
                                 + urts_size / sizeof(*g_urts_next_reserved_range);
    return 0;
}
