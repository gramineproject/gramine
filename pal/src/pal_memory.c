/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <stdbool.h>
#include <stdint.h>

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

int PalVirtualMemoryAlloc(void* addr, size_t size, pal_prot_flags_t prot) {
    if (!addr || !IS_ALLOC_ALIGNED_PTR(addr) || !size || !IS_ALLOC_ALIGNED(size)) {
        return -PAL_ERROR_INVAL;
    }

    return _PalVirtualMemoryAlloc(addr, size, prot);
}

int PalVirtualMemoryFree(void* addr, size_t size) {
    if (!addr || !IS_ALLOC_ALIGNED_PTR(addr) || !size || !IS_ALLOC_ALIGNED(size)) {
        return -PAL_ERROR_INVAL;
    }

    return _PalVirtualMemoryFree(addr, size);
}

int PalVirtualMemoryProtect(void* addr, size_t size, pal_prot_flags_t prot) {
    if (!addr || !IS_ALLOC_ALIGNED_PTR(addr) || !size || !IS_ALLOC_ALIGNED(size)) {
        return -PAL_ERROR_INVAL;
    }

    return _PalVirtualMemoryProtect(addr, size, prot);
}

/*
 * Allocator for PAL internal memory.
 * There are a few phases, which differ in how memory is allocated.
 * 1) PAL initial code - before LibOS is initialized. This is where most of this code is used,
 *    the exact details are described below.
 * 2) After PAL is initialized and before LibOS is ready for memory bookkeeping. At this phase we do
 *    not allocate any memory in PAL.
 * 3) After LibOS calls `PalSetMemoryBookkeepingUpcalls` (which should be done as soon as possible).
 *    From this point PAL simply calls the upcalls when it wants to free or allocate the memory,
 *    LibOS manages all the bookkeeping.
 *
 * For the initial part (1), we have an array of memory ranges (`g_initial_mem_ranges`).
 * To free a range, we simply mark it as freed in this array. To allocate some memory we first look
 * through all previously used (and now marked as freed) ranges in hope of finding something big
 * enough to hold our request. If nothing is found, we then go through this array and find a memory
 * range that was never allocated before (is not in this array), but we also make sure that it does
 * not overlap any of reserved ranges.
 * Because reserved ranges can be arbitrarily long and due to the fact that we cannot really
 * allocate memory without first inspecting them (so we do not map on top of them), we go through
 * them only once (multiple passes might be too slow). The ranges are kept sorted, so we only have
 * to hold the last seen reserved range and the last address we allocated at.
 */
static int (*g_mem_bkeep_alloc_upcall)(size_t size, uintptr_t* out_addr) = NULL;
static int (*g_mem_bkeep_free_upcall)(uintptr_t addr, size_t size) = NULL;

static bool g_initial_mem_disabled = false;
static uintptr_t g_last_alloc_addr = UINTPTR_MAX;
/* Array of initial (PAL) memory ranges. Must be kept sorted in descending order. */
struct pal_initial_mem_range g_initial_mem_ranges[0x100] = { 0 };

void PalSetMemoryBookkeepingUpcalls(int (*alloc)(size_t size, uintptr_t* out_addr),
                                    int (*free)(uintptr_t addr, size_t size)) {
    if (!FIRST_TIME()) {
        BUG();
    }
    g_mem_bkeep_alloc_upcall = alloc;
    g_mem_bkeep_free_upcall = free;
}

static void insert_range_at(size_t idx, uintptr_t addr, size_t size, pal_prot_flags_t prot,
                            const char* comment) {
    assert(idx <= g_pal_public_state.initial_mem_ranges_len);

    memmove(&g_initial_mem_ranges[idx + 1], &g_initial_mem_ranges[idx],
            (g_pal_public_state.initial_mem_ranges_len - idx) * sizeof(g_initial_mem_ranges[0]));
    g_initial_mem_ranges[idx] = (struct pal_initial_mem_range){
        .start = addr,
        .end = addr + size,
        .prot = prot,
        .is_free = false,
    };
    memcpy(&g_initial_mem_ranges[idx].comment, comment,
           MIN(sizeof(g_initial_mem_ranges[idx].comment) - 1, strlen(comment)));

    g_pal_public_state.initial_mem_ranges_len++;
    assert(g_pal_public_state.initial_mem_ranges_len <= ARRAY_SIZE(g_initial_mem_ranges));
}

int pal_add_initial_range(uintptr_t addr, size_t size, pal_prot_flags_t prot, const char* comment) {
    if (g_pal_public_state.initial_mem_ranges_len >= ARRAY_SIZE(g_initial_mem_ranges)) {
        return -PAL_ERROR_NOMEM;
    }

    for (size_t i = 0; i < g_pal_public_state.initial_mem_ranges_len; i++) {
        if (g_initial_mem_ranges[i].end <= addr) {
            insert_range_at(i, addr, size, prot, comment);
            return 0;
        }
    }

    insert_range_at(g_pal_public_state.initial_mem_ranges_len, addr, size, prot, comment);
    return 0;
}

static void mark_range_free(size_t idx) {
    g_initial_mem_ranges[idx].is_free = true;

    /* Remove `ranges_to_rm_count` ranges starting at `rm_start_idx`. */
    size_t ranges_to_rm_count = 0;
    size_t rm_start_idx;
    if (idx + 1 < g_pal_public_state.initial_mem_ranges_len && g_initial_mem_ranges[idx + 1].is_free
            && g_initial_mem_ranges[idx].start == g_initial_mem_ranges[idx + 1].end) {
        /* Next range is also free and aligned to the one being freed now, we can merge next to
         * the current. */
        g_initial_mem_ranges[idx].start = g_initial_mem_ranges[idx + 1].start;
        rm_start_idx = idx + 1;
        ranges_to_rm_count++;
    }
    if (idx > 0 && g_initial_mem_ranges[idx - 1].is_free
            && g_initial_mem_ranges[idx - 1].start == g_initial_mem_ranges[idx].end) {
        /* Previous range is also free and aligned to the one being freed now, we can merge
         * the current to the previous one. */
        g_initial_mem_ranges[idx - 1].start = g_initial_mem_ranges[idx].start;
        rm_start_idx = idx;
        ranges_to_rm_count++;
    }

    if (ranges_to_rm_count) {
        size_t tail_len = g_pal_public_state.initial_mem_ranges_len
                          - (rm_start_idx + ranges_to_rm_count);
        memmove(&g_initial_mem_ranges[rm_start_idx],
                &g_initial_mem_ranges[rm_start_idx + ranges_to_rm_count],
                tail_len * sizeof(g_initial_mem_ranges[0]));

        g_pal_public_state.initial_mem_ranges_len -= ranges_to_rm_count;
    }
}

static int remove_initial_range(uintptr_t addr, size_t size) {
    for (size_t i = 0; i < g_pal_public_state.initial_mem_ranges_len; i++) {
        if (g_initial_mem_ranges[i].start == addr && g_initial_mem_ranges[i].end == addr + size) {
            mark_range_free(i);
            return 0;
        }
        if (g_initial_mem_ranges[i].end <= addr) {
            break;
        }
    }

    return -PAL_ERROR_INVAL;
}

static bool find_free_range(size_t size, uintptr_t* out_addr) {
    size_t best_idx = g_pal_public_state.initial_mem_ranges_len;
    size_t best_size = SIZE_MAX;

    for (size_t i = 0; i < g_pal_public_state.initial_mem_ranges_len; i++) {
        if (g_initial_mem_ranges[i].is_free) {
            size_t range_size = g_initial_mem_ranges[i].end - g_initial_mem_ranges[i].start;
            if (range_size >= size && range_size < best_size) {
                best_size = range_size;
                best_idx = i;
                if (range_size == size) {
                    break;
                }
            }
        }
    }

    if (best_idx >= g_pal_public_state.initial_mem_ranges_len) {
        return false;
    }

    g_initial_mem_ranges[best_idx].end -= size;
    *out_addr = g_initial_mem_ranges[best_idx].end;

    if (g_initial_mem_ranges[best_idx].start == g_initial_mem_ranges[best_idx].end) {
        size_t tail_len = g_pal_public_state.initial_mem_ranges_len - (best_idx + 1);
        memmove(&g_initial_mem_ranges[best_idx], &g_initial_mem_ranges[best_idx + 1],
                tail_len * sizeof(g_initial_mem_ranges[0]));

        g_pal_public_state.initial_mem_ranges_len--;
    }

    return true;
}

static int find_non_reserved_range_below(uintptr_t addr, size_t size, uintptr_t* out_addr) {
    static uintptr_t g_last_reserved_range_start = UINTPTR_MAX;
    static uintptr_t g_last_reserved_range_end = UINTPTR_MAX;

    if (addr < size) {
        return -PAL_ERROR_NOMEM;
    }

    uintptr_t candidate = addr - size;

    while (candidate < g_last_reserved_range_end) {
        if (g_last_reserved_range_start < size) {
            return -PAL_ERROR_NOMEM;
        }
        candidate = MIN(candidate, g_last_reserved_range_start - size);
        pal_read_next_reserved_range(g_last_reserved_range_start,
                                     &g_last_reserved_range_start, &g_last_reserved_range_end);
    }

    *out_addr = candidate;
    return 0;
}

static bool overlaps_existing_range(uintptr_t addr, size_t size, uintptr_t* out_addr) {
    uintptr_t end = addr + size;
    assert(addr < end);

    for (size_t i = 0; i < g_pal_public_state.initial_mem_ranges_len; i++) {
        if (!(g_initial_mem_ranges[i].end <= addr || end <= g_initial_mem_ranges[i].start)) {
            *out_addr = g_initial_mem_ranges[i].start;
            return true;
        }
        if (g_initial_mem_ranges[i].end <= addr) {
            return false;
        }
    }

    return false;
}

/* This function is called only in early init code which is single-threaded, hence it does not need
 * any locking. */
static int initial_mem_bkeep(size_t size, uintptr_t* out_addr) {
    if (g_initial_mem_disabled) {
        return -PAL_ERROR_INVAL;
    }

    if (g_last_alloc_addr == UINTPTR_MAX) {
        g_last_alloc_addr = (uintptr_t)g_pal_public_state.memory_address_end;
    }

    int ret;
    uintptr_t addr;
    if (!find_free_range(size, &addr)) {
        addr = g_last_alloc_addr;
        while (1) {
            ret = find_non_reserved_range_below(addr, size, &addr);
            if (ret < 0) {
                return ret;
            }
            if (addr < (uintptr_t)g_pal_public_state.memory_address_start) {
                return -PAL_ERROR_NOMEM;
            }
            if (!overlaps_existing_range(addr, size, &addr)) {
                break;
            }
        }
        g_last_alloc_addr = addr;
    }

    ret = pal_add_initial_range(addr, size, PAL_PROT_READ | PAL_PROT_WRITE, "PAL internal memory");
    if (ret < 0) {
        return ret;
    }

    *out_addr = addr;
    return 0;
}

/* This function is called only in early init code which is single-threaded, hence it does not need
 * any locking. */
static int initial_mem_free(uintptr_t addr, size_t size) {
    if (g_initial_mem_disabled) {
        return -PAL_ERROR_INVAL;
    }

    int ret = remove_initial_range(addr, size);
    if (ret < 0) {
        return ret;
    }
    ret = _PalVirtualMemoryFree((void*)addr, size);
    if (ret < 0) {
        log_error("failed to free initial PAL internal memory: %s", pal_strerror(ret));
        _PalProcessExit(1);
    }
    return 0;
}

int pal_internal_memory_bkeep(size_t size, uintptr_t* out_addr) {
    if (!g_mem_bkeep_alloc_upcall) {
        return initial_mem_bkeep(size, out_addr);
    }

    int ret = g_mem_bkeep_alloc_upcall(size, out_addr);
    if (ret < 0) {
        log_warning("failed to bookkeep PAL internal memory: %s", unix_strerror(ret));
        return -PAL_ERROR_NOMEM;
    }
    return 0;
}

int pal_internal_memory_alloc(size_t size, void** out_addr) {
    assert(IS_ALLOC_ALIGNED(size));

    uintptr_t addr;
    int ret = pal_internal_memory_bkeep(size, &addr);
    if (ret < 0) {
        return ret;
    }

    ret = _PalVirtualMemoryAlloc((void*)addr, size, PAL_PROT_READ | PAL_PROT_WRITE);
    if (ret < 0) {
        if (!g_mem_bkeep_alloc_upcall) {
            log_error("failed to allocate initial PAL internal memory: %s", pal_strerror(ret));
            _PalProcessExit(1);
        }

        log_warning("failed to allocate PAL internal memory: %s", pal_strerror(ret));
        ret = g_mem_bkeep_free_upcall(addr, size);
        if (ret < 0) {
            BUG();
        }
        return -PAL_ERROR_NOMEM;
    }

    *out_addr = (void*)addr;
    return 0;
}

int pal_internal_memory_free(void* addr, size_t size) {
    assert(IS_ALLOC_ALIGNED(size));

    if (!g_mem_bkeep_free_upcall) {
        return initial_mem_free((uintptr_t)addr, size);
    }

    int ret = _PalVirtualMemoryFree(addr, size);
    if (ret < 0) {
        log_warning("failed to free PAL internal memory: %s", pal_strerror(ret));
        return ret;
    }
    ret = g_mem_bkeep_free_upcall((uintptr_t)addr, size);
    if (ret < 0) {
        log_error("failed to release PAL internal memory: %s", unix_strerror(ret));
        _PalProcessExit(1);
    }
    return 0;
}

void pal_disable_early_memory_bookkeeping(void) {
    g_initial_mem_disabled = true;

    /* Find some unocuppied range for initial LibOS memory. We set an arbitrary limit of 1MB and 5%
     * of total process memory - should be enough™. */
    size_t size = MIN(g_pal_public_state.mem_total / 20, 1024ul * 1024);
    uintptr_t addr = g_last_alloc_addr;
    while (1) {
        int ret = find_non_reserved_range_below(addr, size, &addr);
        if (ret < 0 || addr < (uintptr_t)g_pal_public_state.memory_address_start) {
            /* Let LibOS handle this. `early_libos_mem_range_start` and `early_libos_mem_range_end`
             * are both `0`, so LibOS will most likely fail to allocate early memory. */
            return;
        }
        if (!overlaps_existing_range(addr, size, &addr)) {
            break;
        }
    }

    g_pal_public_state.early_libos_mem_range_start = addr;
    g_pal_public_state.early_libos_mem_range_end = addr + size;
}
