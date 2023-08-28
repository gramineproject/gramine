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
#include "spinlock.h"

/*
 * Global enclave page tracker purely used for EDMM lazy allocation (based on a bitmap vector).
 *
 * This is required for the memory-free flows, where we have to know whether the to-be-freed pages
 * were already EACCEPTed (so that we need to remove them) or not not (so that we can simply skip
 * them). Note that such commit status of enclave pages cannot be provided via SGX driver APIs since
 * they're not trusted under the threat model of SGX; also no user-space SGX instruction is
 * currently giving such info.
 *
 * Besides, for the additional info required in the #PF flow (e.g., enclave-page permissions), it's
 * taken from the LibOS VMA subsystem, for which we use a special upcall.
 */
enclave_page_tracker_t* g_enclave_page_tracker = NULL;

static spinlock_t g_enclave_page_lock = INIT_SPINLOCK_UNLOCKED;

typedef struct {
    uintptr_t addr;
    size_t num_pages;
} initial_page_alloc_t;

#define MAX_INITIAL_PAGE_ALLOCS 8
static initial_page_alloc_t g_initial_page_allocs[MAX_INITIAL_PAGE_ALLOCS];
static size_t g_initial_page_allocs_count = 0;

int _PalVirtualMemoryAlloc(void* addr, uint64_t size, pal_prot_flags_t prot) {
    assert(WITHIN_MASK(prot, PAL_PROT_MASK));
    assert(IS_ALIGNED_PTR(addr, PAGE_SIZE) && IS_ALIGNED(size, PAGE_SIZE));
    assert(access_ok(addr, size));
    assert(sgx_is_completely_within_enclave(addr, size));

    if (g_pal_linuxsgx_state.edmm_enabled) {
        /* defer page accepts to page-fault events when `MAP_NORESERVE` is set */
        if (prot & PAL_PROT_LAZYALLOC)
            return 0;

        int ret;
        uint64_t prot_flags = PAL_TO_SGX_PROT(prot);

        if (g_enclave_page_tracker) {
            ret = walk_unset_pages((uintptr_t)addr, size / PAGE_SIZE,
                                   sgx_edmm_add_pages_callback, &prot_flags);
        } else {
            /* for enclave pages allocated when the tracker is not ready (on bootstrap) */
            if (g_initial_page_allocs_count < MAX_INITIAL_PAGE_ALLOCS) {
                g_initial_page_allocs[g_initial_page_allocs_count].addr = (uintptr_t)addr;
                g_initial_page_allocs[g_initial_page_allocs_count].num_pages = size / PAGE_SIZE;
                g_initial_page_allocs_count++;
            } else {
                log_error("initial page allocs buffer is full");
                _PalProcessExit(1);
            }
            ret = sgx_edmm_add_pages((uint64_t)addr, size / PAGE_SIZE, prot_flags);
        }

        if (ret < 0)
            return ret;
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
            assert(g_enclave_page_tracker);
            int ret = walk_set_pages((uintptr_t)addr, size / PAGE_SIZE,
                                     sgx_edmm_remove_pages_callback, NULL);
            if (ret < 0)
                return ret;
        } else {
#ifdef ASAN
            asan_poison_region((uintptr_t)addr, size, ASAN_POISON_USER);
#endif
            /*
             * In SGX1 the memory is mapped only at the enclave initialization and cannot be
             * unmapped.
             */
        }
    } else {
        /* possible to have untrusted mapping, simply unmap memory outside the enclave */
        ocall_munmap_untrusted(addr, size);
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

/* create a new page tracker with the specified base address, number of pages, and page size */
static enclave_page_tracker_t* create_enclave_page_tracker(uintptr_t base_address,
                                                           size_t num_pages, size_t page_size) {
    enclave_page_tracker_t* tracker = malloc(sizeof(enclave_page_tracker_t));
    if (!tracker)
        INIT_FAIL("cannot initialize enclave page tracker");
    tracker->data = (unsigned char*)calloc((num_pages + 7) / 8, sizeof(unsigned char));
    if (!tracker->data)
        INIT_FAIL("cannot initialize enclave page tracker data");

    tracker->base_address = base_address;
    tracker->size = num_pages;
    tracker->page_size = page_size;

    return tracker;
}

/* initialize the enclave page tracker with the specified base address, enclave memory region size
 * (in bytes), and page size (in bytes) */
void initialize_enclave_page_tracker(uintptr_t base_address, size_t memory_size, size_t page_size) {
    assert(!g_enclave_page_tracker);

    size_t num_pages = (memory_size + page_size - 1) / page_size;
    g_enclave_page_tracker = create_enclave_page_tracker(base_address, num_pages, page_size);

    /* set initial enclave pages allocations by slab allocator and the enclave page tracker */
    for (size_t i = 0; i < g_initial_page_allocs_count; i++)
        set_enclave_addr_range(g_initial_page_allocs[i].addr, g_initial_page_allocs[i].num_pages);
}

/* convert an address to an index in the page tracker */
static inline size_t address_to_index(uintptr_t address) {
    return (address - g_enclave_page_tracker->base_address) / g_enclave_page_tracker->page_size;
}

/* convert an index in the page tracker to an address */
static inline uintptr_t index_to_address(size_t index) {
    return g_enclave_page_tracker->base_address + index * g_enclave_page_tracker->page_size;
}

/* set an enclave page as allocated in the page tracker */
static inline void set_enclave_page(size_t index) {
    assert(spinlock_is_locked(&g_enclave_page_lock));
    g_enclave_page_tracker->data[index / 8] |= 1 << (index % 8);
}

/* set an enclave page as free in the page tracker */
static inline void unset_enclave_page(size_t index) {
    assert(spinlock_is_locked(&g_enclave_page_lock));
    g_enclave_page_tracker->data[index / 8] &= ~(1 << (index % 8));
}

/* check if an enclave page is allocated in the page tracker */
static inline bool is_enclave_page_set(size_t index) {
    assert(spinlock_is_locked(&g_enclave_page_lock));
    return (g_enclave_page_tracker->data[index / 8] & (1 << (index % 8))) != 0;
}

/* set a range of enclave pages as allocated according to the memory address and number of pages */
void set_enclave_addr_range(uintptr_t start_addr, size_t num_pages) {
    spinlock_lock(&g_enclave_page_lock);
    for (size_t i = 0; i < num_pages; i++) {
        uintptr_t address = start_addr + i * g_enclave_page_tracker->page_size;
        size_t index = address_to_index(address);
        set_enclave_page(index);
    }
    spinlock_unlock(&g_enclave_page_lock);
}

/* set a range of enclave pages as free according to the memory address and number of pages */
void unset_enclave_addr_range(uintptr_t start_addr, size_t num_pages) {
    spinlock_lock(&g_enclave_page_lock);
    for (size_t i = 0; i < num_pages; i++) {
        uintptr_t address = start_addr + i * g_enclave_page_tracker->page_size;
        size_t index = address_to_index(address);
        unset_enclave_page(index);
    }
    spinlock_unlock(&g_enclave_page_lock);
}

/* iterate over the given range of enclave pages in the tracker and perform the specified `callback`
 * on the consecutive set/unset pages; return error when `callback` failed */
static int walk_pages(uintptr_t start_addr, size_t count, bool walk_set,
                      int (*callback)(uintptr_t, size_t, void*), void* arg) {
    int ret = 0;
    size_t start = address_to_index(start_addr);
    size_t end = start + count;

    size_t i = start;
    while (i < end && i < g_enclave_page_tracker->size) {
        uintptr_t consecutive_start_addr = 0;
        size_t consecutive_count = 0;

        /* find consecutive set/unset pages */
        spinlock_lock(&g_enclave_page_lock);
        if (is_enclave_page_set(i) == walk_set) {
            consecutive_start_addr = index_to_address(i);
            while (i < end && i < g_enclave_page_tracker->size &&
                   is_enclave_page_set(i) == walk_set) {
                consecutive_count++;
                i++;
            }
        } else {
            i++;
        }
        spinlock_unlock(&g_enclave_page_lock);

        if (consecutive_count > 0) {
            /* invoke the `callback` on the consecutive pages */
            ret = callback(consecutive_start_addr, consecutive_count, arg);
            if (ret < 0)
                break;
        }
    }

    return ret;
}

/* wrapper function for walking set pages */
int walk_set_pages(uintptr_t start_addr, size_t count,
                   int (*callback)(uintptr_t, size_t, void*), void* arg) {
    return walk_pages(start_addr, count, true, callback, arg);
}

/* wrapper function for walking unset pages */
int walk_unset_pages(uintptr_t start_addr, size_t count,
                     int (*callback)(uintptr_t, size_t, void*), void* arg) {
    return walk_pages(start_addr, count, false, callback, arg);
}
