/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs that allocate, free or protect virtual memory.
 */

#include "api.h"
#include "asan.h"
#include "enclave_pages.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"

extern size_t g_allocated_pages;

bool _PalCheckMemoryMappable(const void* addr, size_t size) {
    if (addr < DATA_END && addr + size > TEXT_START) {
        log_error("Address %p-%p is not mappable", addr, addr + size);
        return true;
    }

    /* FIXME: this function is almost useless now; note that _PalVirtualMemoryAlloc() checks whether
     * [addr, addr + size) overlaps with VMAs and errors out */

    return false;
}

int _PalVirtualMemoryAlloc(void** addr_ptr, uint64_t size, pal_alloc_flags_t alloc_type,
                           pal_prot_flags_t prot) {
    __UNUSED(prot);

    assert(WITHIN_MASK(alloc_type, PAL_ALLOC_MASK));
    assert(WITHIN_MASK(prot,       PAL_PROT_MASK));

    if (!size)
        return -PAL_ERROR_INVAL;

    void* addr = *addr_ptr;

    void* mem = get_enclave_pages(addr, size, alloc_type & PAL_ALLOC_INTERNAL);
    if (!mem)
        return addr ? -PAL_ERROR_DENIED : -PAL_ERROR_NOMEM;

    /* initialize contents of new memory region to zero (LibOS layer expects zeroed-out memory) */
    memset(mem, 0, size);

    *addr_ptr = mem;
    return 0;
}

int _PalVirtualMemoryFree(void* addr, uint64_t size) {
    if (sgx_is_completely_within_enclave(addr, size)) {
        int ret = free_enclave_pages(addr, size);
        if (ret < 0) {
            return ret;
        }
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
