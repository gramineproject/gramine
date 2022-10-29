/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "pal.h"
#include "pal_regression.h"

struct vma {
    uintptr_t begin;
    uintptr_t end;
};

/* Array of allocated memory ranges. Always kept sorted in descending order. */
static struct vma g_vmas[0x100];
static size_t g_vmas_len = 0;

int mem_bkeep_alloc(size_t size, uintptr_t* out_addr) {
    assert(g_vmas_len >= 2);
    assert(g_vmas[0].begin && g_vmas[0].end);
    if (g_vmas_len == ARRAY_LEN(g_vmas)) {
        return -PAL_ERROR_NOMEM;
    }

    if (!IS_ALIGNED(size, PAGE_SIZE)) {
        return -PAL_ERROR_INVAL;
    }

    for (size_t i = 1; i < g_vmas_len; i++) {
        assert(g_vmas[i - 1].begin >= g_vmas[i].end);
        if (g_vmas[i - 1].begin - g_vmas[i].end >= size) {
            memmove(&g_vmas[i + 1], &g_vmas[i], (g_vmas_len - i) * sizeof(g_vmas[0]));

            g_vmas[i] = (struct vma){
                .begin = g_vmas[i - 1].begin - size,
                .end = g_vmas[i - 1].begin,
            };
            g_vmas_len++;
            *out_addr = g_vmas[i].begin;
            return 0;
        }
    }

    return -PAL_ERROR_NOMEM;
}

int mem_bkeep_free(uintptr_t addr, size_t size) {
    assert(g_vmas_len);
    uintptr_t end = addr + size;

    for (size_t i = 0; i < g_vmas_len; i++) {
        if (g_vmas[i].begin == addr && g_vmas[i].end == end) {
            memmove(&g_vmas[i], &g_vmas[i + 1], (g_vmas_len - i - 1) * sizeof(g_vmas[0]));
            g_vmas_len--;
            return 0;
        } else if (!(end <= g_vmas[i].begin || g_vmas[i].end <= addr)) {
            log_error("trying to free an invalid range: %#lx-%#lx", addr, end);
            PalProcessExit(1);
        }
    }

    return -PAL_ERROR_NOMEM;
}

void init_memory_management(void) {
    struct pal_public_state* pal_public_state = PalGetPalPublicState();
    /* Because we are looking at free space between memory ranges, we need a VMA marking the end of
     * available memory. This dummy VMA is never freed. */
    g_vmas[0] = (struct vma){
        .begin = (uintptr_t)pal_public_state->memory_address_end,
        .end = (uintptr_t)pal_public_state->memory_address_end,
    };

    if (ARRAY_LEN(g_vmas) < pal_public_state->initial_mem_ranges_len + 2) {
        /* This should never happen. */
        log_error("not enough space for initial memory ranges (required %zu)",
                  pal_public_state->initial_mem_ranges_len + 2);
        PalProcessExit(1);
    }

    size_t ignored_ranges = 0;
    for (size_t i = 0; i < pal_public_state->initial_mem_ranges_len; i++) {
        g_vmas[1 + i] = (struct vma){
            .begin = pal_public_state->initial_mem_ranges[i].start,
            .end = pal_public_state->initial_mem_ranges[i].end,
        };
        if (g_vmas[1 + i].begin >= (uintptr_t)pal_public_state->memory_address_end
                || g_vmas[1 + i].end <= (uintptr_t)pal_public_state->memory_address_start) {
            /* This range is outside of available memory, we do not care about it. */
            g_vmas[1 + i] = (struct vma){ .begin = 0, .end = 0, };
            ignored_ranges++;
        }
    }
    /* Because we are looking at free space between memory ranges, we need a VMA marking
     * the beginning of available memory. This dummy VMA is never freed. */
    g_vmas[1 + pal_public_state->initial_mem_ranges_len] = (struct vma){
        .begin = (uintptr_t)pal_public_state->memory_address_start,
        .end = (uintptr_t)pal_public_state->memory_address_start,
    };
    g_vmas_len = pal_public_state->initial_mem_ranges_len + 2;

    /* Sort `g_vmas` in descending order. */
    for (size_t i = 0; i < g_vmas_len; i++) {
        for (size_t j = i + 1; j < g_vmas_len; j++) {
            if (g_vmas[i].begin < g_vmas[j].begin) {
                struct vma tmp = g_vmas[i];
                g_vmas[i] = g_vmas[j];
                g_vmas[j] = tmp;
            }
        }
    }
    g_vmas_len -= ignored_ranges;
    assert(g_vmas_len >= 2);

    PalSetMemoryBookkeepingUpcalls(mem_bkeep_alloc, mem_bkeep_free);
}

int memory_alloc(size_t size, pal_prot_flags_t prot, void** out_addr) {
    if (!IS_ALIGNED(size, PAGE_SIZE)) {
        return -PAL_ERROR_INVAL;
    }

    uintptr_t addr;
    int ret = mem_bkeep_alloc(size, &addr);
    if (ret < 0) {
        return ret;
    }

    ret = PalVirtualMemoryAlloc((void*)addr, size, prot);
    if (ret < 0) {
        log_error("failed to allocate memory at %#lx-%#lx (prot: %#x)", addr, addr + size, prot);
        PalProcessExit(1);
    }

    *out_addr = (void*)addr;
    return 0;
}

int memory_free(void* addr, size_t size) {
    if (!IS_ALIGNED_PTR(addr, PAGE_SIZE) || !IS_ALIGNED(size, PAGE_SIZE)) {
        return -PAL_ERROR_INVAL;
    }

    int ret = PalVirtualMemoryFree(addr, size);
    if (ret < 0) {
        return ret;
    }

    ret = mem_bkeep_free((uintptr_t)addr, size);
    if (ret < 0) {
        log_error("%s: mem_bkeep_free(%p, %#lx) failed: %s", __func__, addr, size,
                  pal_strerror(ret));
    }

    return 0;
}
