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
    if (!addr || !size) {
        return -PAL_ERROR_INVAL;
    }

    if (!IS_ALLOC_ALIGNED_PTR(addr) || !IS_ALLOC_ALIGNED(size)) {
        return -PAL_ERROR_INVAL;
    }

    return _PalVirtualMemoryFree(addr, size);
}

int PalVirtualMemoryProtect(void* addr, size_t size, pal_prot_flags_t prot) {
    if (!addr || !size) {
        return -PAL_ERROR_INVAL;
    }

    if (!IS_ALLOC_ALIGNED_PTR(addr) || !IS_ALLOC_ALIGNED(size)) {
        return -PAL_ERROR_INVAL;
    }

    return _PalVirtualMemoryProtect(addr, size, prot);
}

static int (*g_mem_bkeep_alloc_upcall)(size_t size, uintptr_t* out_addr) = NULL;
static int (*g_mem_bkeep_free_upcall)(uintptr_t addr, size_t size) = NULL;

static bool g_initial_mem_disabled = false;
static uintptr_t g_last_alloc_addr = UINTPTR_MAX;
struct pal_initial_mem_range g_initial_mem_ranges[0x100] = { 0 };

void PalSetMemoryBookkeepingUpcalls(int (*alloc)(size_t size, uintptr_t* out_addr),
                                    int (*free)(uintptr_t addr, size_t size)) {
    if (!FIRST_TIME()) {
        BUG();
    }
    g_mem_bkeep_alloc_upcall = alloc;
    g_mem_bkeep_free_upcall = free;
}

int pal_add_initial_range(uintptr_t addr, size_t size, pal_prot_flags_t prot, const char* comment) {
    if (g_pal_public_state.initial_mem_ranges_len >= ARRAY_SIZE(g_initial_mem_ranges)) {
        return -PAL_ERROR_NOMEM;
    }

    g_initial_mem_ranges[g_pal_public_state.initial_mem_ranges_len].start = addr;
    g_initial_mem_ranges[g_pal_public_state.initial_mem_ranges_len].end = addr + size;
    g_initial_mem_ranges[g_pal_public_state.initial_mem_ranges_len].prot = prot;
    g_initial_mem_ranges[g_pal_public_state.initial_mem_ranges_len].comment = comment;

    g_pal_public_state.initial_mem_ranges_len++;
    return 0;
}

static int remove_initial_range(uintptr_t addr, size_t size) {
    size_t idx = g_pal_public_state.initial_mem_ranges_len;
    for (size_t i = 0; i < g_pal_public_state.initial_mem_ranges_len; i++) {
        if (g_initial_mem_ranges[i].start == addr && g_initial_mem_ranges[i].end == addr + size) {
            idx = i;
            break;
        }
    }

    if (idx >= g_pal_public_state.initial_mem_ranges_len) {
        return -PAL_ERROR_INVAL;
    }

    size_t len = g_pal_public_state.initial_mem_ranges_len - (idx + 1);
    memmove(&g_initial_mem_ranges[idx], &g_initial_mem_ranges[idx + 1],
            len * sizeof(*g_initial_mem_ranges));

    g_pal_public_state.initial_mem_ranges_len--;
    return 0;
}

static int find_non_reserved_range_above(uintptr_t* addr, size_t size) {
    static uintptr_t g_last_reserved_range_start = UINTPTR_MAX;
    static uintptr_t g_last_reserved_range_end = UINTPTR_MAX;

    if (*addr < size) {
        return -PAL_ERROR_NOMEM;
    }

    uintptr_t candidate = *addr - size;

    while (candidate < g_last_reserved_range_end) {
        if (g_last_reserved_range_start < size) {
            return -PAL_ERROR_NOMEM;
        }
        candidate = MIN(candidate, g_last_reserved_range_start - size);
        pal_read_one_reserved_range(&g_last_reserved_range_start, &g_last_reserved_range_end);
    }

    *addr = candidate;
    return 0;
}

static bool overlaps_existing_range(uintptr_t* addr, size_t size) {
    uintptr_t end = *addr + size;
    assert(*addr < end);

    for (size_t i = 0; i < g_pal_public_state.initial_mem_ranges_len; i++) {
        if (!(g_initial_mem_ranges[i].end <= *addr || end <= g_initial_mem_ranges[i].start)) {
            *addr = g_initial_mem_ranges[i].start;
            return true;
        }
    }

    return false;
}

/* This function is called only in early init code which is single-threaded, hence it does not need
 * any locking. */
static int initial_mem_alloc(size_t size, void** out_ptr) {
    if (g_initial_mem_disabled) {
        return -PAL_ERROR_NOMEM;
    }

    if (g_last_alloc_addr == UINTPTR_MAX) {
        g_last_alloc_addr = (uintptr_t)g_pal_public_state.memory_address_end;
    }

    int ret;
    uintptr_t addr = g_last_alloc_addr;
    while (1) {
        ret = find_non_reserved_range_above(&addr, size);
        if (ret < 0) {
            return ret;
        }
        if (addr < (uintptr_t)g_pal_public_state.memory_address_start) {
            return -PAL_ERROR_NOMEM;
        }
        if (!overlaps_existing_range(&addr, size)) {
            break;
        }
    }

    ret = pal_add_initial_range(addr, size, PAL_PROT_READ | PAL_PROT_WRITE, "PAL internal memory");
    if (ret < 0) {
        return ret;
    }

    ret = _PalVirtualMemoryAlloc((void*)addr, size, PAL_PROT_READ | PAL_PROT_WRITE);
    if (ret < 0) {
        log_error("%s: failed to allocate initial internal memory: %d", __func__, ret);
        _PalProcessExit(1);
    }

    g_last_alloc_addr = addr;
    *out_ptr = (void*)addr;
    return 0;
}

/* This function is called only in early init code which is single-threaded, hence it does not need
 * any locking. */
static int initial_mem_free(uintptr_t addr, size_t size) {
    if (g_initial_mem_disabled) {
        return -PAL_ERROR_NOMEM;
    }

    int ret = remove_initial_range(addr, size);
    if (ret < 0) {
        return ret;
    }
    ret = _PalVirtualMemoryFree((void*)addr, size);
    if (ret < 0) {
        log_error("%s: failed to free PAL internal memory: %d", __func__, ret);
        _PalProcessExit(1);
    }
    return 0;
}

int pal_internal_memory_alloc(size_t size, void** out_ptr) {
    assert(IS_ALLOC_ALIGNED(size));

    if (g_mem_bkeep_alloc_upcall) {
        uintptr_t addr;
        int ret = g_mem_bkeep_alloc_upcall(size, &addr);
        if (ret < 0) {
            log_warning("%s: failed to bookkeep PAL internal memory: %d", __func__, ret);
            return -PAL_ERROR_NOMEM;
        }
        ret = _PalVirtualMemoryAlloc((void*)addr, size, PAL_PROT_READ | PAL_PROT_WRITE);
        if (ret < 0) {
            log_warning("%s: failed to allocate PAL internal memory: %d", __func__, ret);
            ret = g_mem_bkeep_free_upcall(addr, size);
            if (ret < 0) {
                BUG();
            }
            return -PAL_ERROR_NOMEM;
        }

        *out_ptr = (void*)addr;
        return 0;
    }

    return initial_mem_alloc(size, out_ptr);
}

int pal_internal_memory_free(void* addr, size_t size) {
    assert(IS_ALLOC_ALIGNED(size));

    if (g_mem_bkeep_alloc_upcall) {
        int ret = _PalVirtualMemoryFree(addr, size);
        if (ret < 0) {
            log_warning("%s: failed to free PAL internal memory: %d", __func__, ret);
            return ret;
        }
        ret = g_mem_bkeep_free_upcall((uintptr_t)addr, size);
        if (ret < 0) {
            log_error("%s: failed to release PAL internal memory: %d", __func__, ret);
            _PalProcessExit(1);
        }
        return 0;
    }

    return initial_mem_free((uintptr_t)addr, size);
}

void pal_disable_early_memory_bookkeeping(void) {
    g_initial_mem_disabled = true;

    /* Find some unocuppied range for initial LibOS memory. We set an arbitrary limit of 1MB and 5%
     * of total process memory - should be enough™. */
    size_t size = MIN(g_pal_public_state.mem_total / 20, 1024ul * 1024);
    uintptr_t addr = g_last_alloc_addr;
    while (1) {
        int ret = find_non_reserved_range_above(&addr, size);
        if (ret < 0 || addr < (uintptr_t)g_pal_public_state.memory_address_start) {
            /* Let LibOS handle this. */
            return;
        }
        if (!overlaps_existing_range(&addr, size)) {
            break;
        }
    }

    g_pal_public_state.early_libos_mem_range_start = addr;
    g_pal_public_state.early_libos_mem_range_end = addr + size;
}
