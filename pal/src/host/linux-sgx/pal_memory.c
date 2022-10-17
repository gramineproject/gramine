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
#include "enclave_dmm.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"

int _PalVirtualMemoryAlloc(void* addr, uint64_t size, pal_prot_flags_t prot) {
    assert(WITHIN_MASK(prot, PAL_PROT_MASK));
    assert(IS_ALIGNED_PTR(addr, g_page_size) && IS_ALIGNED(size, g_page_size));
    assert(access_ok(addr, size));
    assert(sgx_is_completely_within_enclave(addr, size));

#ifdef ASAN
    asan_unpoison_region((uintptr_t)addr, size);
#endif

    int ret;
    pal_prot_flags_t req_prot;
    if (g_pal_public_state.edmm_enable_heap) {
        req_prot = (prot & PAL_PROT_WRITE) ? prot : prot | PAL_PROT_READ | PAL_PROT_WRITE;

        ret = get_enclave_pages(addr, size, req_prot);
        if (ret < 0)
            return ret;
    }

    /*
     * This function doesn't have to do anything - in SGX1 the memory is already mapped (it happens
     * at the enclave initialization). Just clear the (possible) previous memory content (this
     * function must return zeroed memory).
     */
    memset(addr, 0, size);

    /* Reset to original request. Work around for memset to succeed. */
    if (g_pal_public_state.edmm_enable_heap && prot != req_prot) {
        ret = _PalVirtualMemoryProtect(addr, size, req_prot, prot);
        if (ret < 0)
            return ret;
    }

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

        /*
         * This function doesn't have to do anything - in SGX1 the memory is mapped only at
         * the enclave initialization and cannot be unmapped.
         */
        if (g_pal_public_state.edmm_enable_heap) {
            int ret = free_enclave_pages(addr, size);
            if (ret < 0) {
                return ret;
            }
        }
    } else {
        /* possible to have untrusted mapping, simply unmap memory outside the enclave */
        ocall_munmap_untrusted(addr, size);
    }

    return 0;
}

int _PalVirtualMemoryProtect(void* addr, uint64_t size, pal_prot_flags_t cur_prot,
                             pal_prot_flags_t req_prot) {
    int ret;
    assert(WITHIN_MASK(req_prot, PAL_PROT_MASK));

    if (!size)
        return -PAL_ERROR_INVAL;

    if (cur_prot == req_prot)
        return 0;

#ifdef ASAN
    if (sgx_is_completely_within_enclave(addr, size)) {
        if (req_prot) {
            asan_unpoison_region((uintptr_t)addr, size);
        } else {
            asan_poison_region((uintptr_t)addr, size, ASAN_POISON_USER);
        }
    }
#endif
    if (g_pal_public_state.edmm_enable_heap) {
        ret = update_enclave_page_permissions(addr, size, cur_prot, req_prot);
    } else {
        if (FIRST_TIME()) {
            log_warning("PalVirtualMemoryProtect is unimplemented in Linux-SGX PAL");
        }
        ret = 0;
    }

    return ret;
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
