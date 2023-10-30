/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This file contains APIs that allocate, free or change permissions of virtual memory.
 */

#include <stdalign.h>

#include "api.h"
#include "asan.h"
#include "cpu.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_sgx.h"

int _PalVirtualMemoryAlloc(void* addr, uint64_t size, pal_prot_flags_t prot) {
    assert(WITHIN_MASK(prot, PAL_PROT_MASK));
    assert(IS_ALIGNED_PTR(addr, PAGE_SIZE) && IS_ALIGNED(size, PAGE_SIZE));
    assert(access_ok(addr, size));
    assert(sgx_is_completely_within_enclave(addr, size));

    if (g_pal_linuxsgx_state.edmm_enabled) {
        int ret = sgx_edmm_add_pages((uint64_t)addr, size / PAGE_SIZE, PAL_TO_SGX_PROT(prot));
        if (ret < 0) {
            return ret;
        }
    } else {
#ifdef ASAN
        asan_unpoison_region((uintptr_t)addr, size);
#endif
        /*
         * In SGX1 the memory is already mapped (it happens at the enclave initialization). Just
         * clear the (possible) previous memory content (this function must return zeroed memory).
         */
        memset(addr, 0, size);
    }

    return 0;
}

int _PalVirtualMemoryFree(void* addr, uint64_t size) {
    assert(IS_ALIGNED_PTR(addr, PAGE_SIZE) && IS_ALIGNED(size, PAGE_SIZE));
    assert(access_ok(addr, size));

    if (sgx_is_completely_within_enclave(addr, size)) {
        assert(g_pal_linuxsgx_state.heap_min <= addr
               && addr + size <= g_pal_linuxsgx_state.heap_max);

        if (g_pal_linuxsgx_state.edmm_enabled) {
            int ret = sgx_edmm_remove_pages((uint64_t)addr, size / PAGE_SIZE);
            if (ret < 0) {
                return ret;
            }
        } else {
#ifdef ASAN
            asan_poison_region((uintptr_t)addr, size, ASAN_POISON_USER);
#endif
            /*
             * In SGX1 the memory is mapped only at the enclave initialization and cannot be
             * unmapped.
             */
        }
    } else if (sgx_is_valid_untrusted_ptr(addr, size, /*alignment=*/1)) {
        /*
         * Possible to have untrusted mapping, simply unmap memory outside the enclave. But only
         * unmap if this is not a shared-untrusted-memory region, as this whole region was mmapped
         * at startup to prevent random allocations landing in there. (Otherwise, if it would unmap
         * some shared memory, then there would be a hole in this region and unrelated allocations
         * could land here.)
         */
        if ((uintptr_t)addr + size <= (uintptr_t)g_pal_public_state.shared_address_start
                || addr >= g_pal_public_state.shared_address_end) {
            ocall_munmap_untrusted(addr, size);
        } else if ((uintptr_t)addr + size > (uintptr_t)g_pal_public_state.shared_address_end
                       || addr < g_pal_public_state.shared_address_start) {
            /* Partially inside and partially outside of the shared range. */
            BUG();
        }
    } else {
        BUG();
    }

    return 0;
}

int _PalVirtualMemoryProtect(void* addr, uint64_t size, pal_prot_flags_t prot) {
    assert(WITHIN_MASK(prot, PAL_PROT_MASK));
    assert(IS_ALIGNED_PTR(addr, PAGE_SIZE) && IS_ALIGNED(size, PAGE_SIZE));
    assert(access_ok(addr, size));
    assert(sgx_is_completely_within_enclave(addr, size));

    if (g_pal_linuxsgx_state.edmm_enabled) {
        int ret = sgx_edmm_set_page_permissions((uint64_t)addr, size / PAGE_SIZE,
                                                PAL_TO_SGX_PROT(prot));
        if (ret < 0) {
            return ret;
        }
    } else {
#ifdef ASAN
        if (prot) {
            asan_unpoison_region((uintptr_t)addr, size);
        } else {
            asan_poison_region((uintptr_t)addr, size, ASAN_POISON_USER);
        }

        if (FIRST_TIME()) {
            log_warning("PalVirtualMemoryProtect is a no-op in Linux-SGX PAL with SGX1");
        }
#endif
    }

    return 0;
}

uint64_t _PalMemoryQuota(void) {
    return g_pal_linuxsgx_state.heap_max - g_pal_linuxsgx_state.heap_min;
}

static uintptr_t (*g_urts_next_reserved_range)[2] = NULL;
static uintptr_t (*g_urts_reserved_ranges_end)[2] = NULL;

void pal_read_next_reserved_range(uintptr_t last_range_start, uintptr_t* out_next_range_start,
                                  uintptr_t* out_next_range_end) {
    if (g_urts_next_reserved_range == g_urts_reserved_ranges_end) {
        *out_next_range_start = 0;
        *out_next_range_end = 0;
        return;
    }

    uintptr_t new_range[2];
    if (!sgx_copy_to_enclave(&new_range, sizeof(new_range),
                             g_urts_next_reserved_range, sizeof(*g_urts_next_reserved_range))) {
        /* Should be impossible as we already checked the pointer. */
        BUG();
    }
    g_urts_next_reserved_range++;

    if (new_range[0] > new_range[1] || new_range[1] > last_range_start
            || !IS_ALLOC_ALIGNED(new_range[0]) || !IS_ALLOC_ALIGNED(new_range[1])) {
        log_error("URTS passed invalid reserved memory range: %#lx-%#lx (previous started at %#lx)",
                  new_range[0], new_range[1], last_range_start);
        _PalProcessExit(1);
    }

    *out_next_range_start = new_range[0];
    *out_next_range_end = new_range[1];
}

int init_reserved_ranges(void* urts_ptr, size_t urts_size) {
    if (!urts_size) {
        return 0;
    }

    if (!IS_ALIGNED(urts_size, sizeof(*g_urts_next_reserved_range))) {
        return -PAL_ERROR_INVAL;
    }
    if (!sgx_is_valid_untrusted_ptr(urts_ptr, urts_size,
            alignof(__typeof__(*g_urts_next_reserved_range)))) {
        return -PAL_ERROR_INVAL;
    }

    g_urts_next_reserved_range = urts_ptr;
    g_urts_reserved_ranges_end = g_urts_next_reserved_range
                                 + urts_size / sizeof(*g_urts_next_reserved_range);
    return 0;
}
