/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 *                    Kailun Qin <kailun.qin@intel.com>
 */

#include <stdalign.h>

#include "api.h"
#include "cpu.h"
#include "enclave_ocalls.h"
#include "pal_error.h"
#include "pal_linux_error.h"
#include "pal_sgx.h"
#include "sgx_arch.h"
#include "spinlock.h"

initial_page_alloc_t g_initial_page_allocs[MAX_INITIAL_PAGE_ALLOCS];
size_t g_initial_page_allocs_count = 0;

/*
 * Global enclave page tracker used for EDMM lazy allocation (based on a bitmap vector).
 *
 * This is required for the memory free() flows, where we have to know whether the to-be-freed pages
 * were already EACCEPTed (so that we need to remove them) or not (so that we can simply skip them).
 * Note that such commit status of enclave pages cannot be provided via SGX driver APIs since
 * they're not trusted under the threat model of SGX; also no user-space SGX instruction is
 * currently giving such info.
 *
 * We don't use this page tracker to store info required in the #PF flows (e.g. enclave-page
 * permissions). Instead, we get this info from the LibOS VMA subsystem, for which we use a special
 * upcall, see g_mem_bkeep_get_vma_info_upcall.
 */
enclave_page_tracker_t* g_enclave_page_tracker = NULL;

static spinlock_t g_enclave_page_tracker_lock = INIT_SPINLOCK_UNLOCKED;

static int sgx_eaccept(uint64_t addr, uint64_t flags) {
    alignas(64) sgx_arch_sec_info_t secinfo = {
        .flags = flags,
    };
    /* ENCLU returns 0 or positive error code, but Gramine as a convention denotes errors using
     * negative values. You can check the code values in Intel SDM vol 3. */
    return -enclu(EACCEPT, (uint64_t)&secinfo, addr, 0);
}

static void sgx_emodpe(uint64_t addr, uint64_t prot) {
    alignas(64) sgx_arch_sec_info_t secinfo = {
        .flags = prot,
    };
    enclu(EMODPE, (uint64_t)&secinfo, addr, 0);
    /* `EMODPE` does not return errors, it can only fault. */
}

int sgx_edmm_add_pages(uint64_t addr, size_t count, uint64_t prot) {
    int ret;

    if (prot & SGX_SECINFO_FLAGS_W) {
        /* HW limitation. */
        prot |= SGX_SECINFO_FLAGS_R;
    }

    for (size_t i = 0; i < count; i++) {
        /* SGX2 HW requires initial page permissions to be RW. */
        ret = sgx_eaccept(addr + i * PAGE_SIZE, (SGX_PAGE_TYPE_REG << SGX_SECINFO_FLAGS_TYPE_SHIFT)
                                                | SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W
                                                | SGX_SECINFO_FLAGS_PENDING);
        if (ret < 0) {
            log_error("failed to accept page at address %#lx: %d", addr + i * PAGE_SIZE, ret);
            /* Since these errors do not happen in legitimate cases and restoring already accepted
             * pages would be cumbersome, we just kill the whole process. */
            die_or_inf_loop();
        }
    }

    if (prot & ~(SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W)) {
        for (size_t i = 0; i < count; i++) {
            sgx_emodpe(addr + i * PAGE_SIZE, prot);
        }
    }

    if (~prot & (SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W)) {
        ret = ocall_edmm_restrict_pages_perm(addr, count, prot);
        if (ret < 0) {
            log_error("failed to restrict pages permissions at %#lx-%#lx: %s", addr,
                      addr + count * PAGE_SIZE, unix_strerror(ret));
            /* Since these errors do not happen in legitimate cases and restoring already allocated
             * pages would be cumbersome, we just kill the whole process. */
            die_or_inf_loop();
        }
        for (size_t i = 0; i < count; i++) {
            ret = sgx_eaccept(addr + i * PAGE_SIZE,
                              (SGX_PAGE_TYPE_REG << SGX_SECINFO_FLAGS_TYPE_SHIFT)
                              | SGX_SECINFO_FLAGS_PR | prot);
            if (ret < 0) {
                log_error("failed to accept restricted pages permissions at %#lx: %d",
                          addr + i * PAGE_SIZE, ret);
                /* Since these errors do not happen in legitimate cases and restoring already
                 * allocated pages would be cumbersome, we just kill the whole process. */
                die_or_inf_loop();
            }
        }
    }

    return 0;
}

int sgx_edmm_remove_pages(uint64_t addr, size_t count) {
    int ret = ocall_edmm_modify_pages_type(addr, count, SGX_PAGE_TYPE_TRIM);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }

    for (size_t i = 0; i < count; i++) {
        ret = sgx_eaccept(addr + i * PAGE_SIZE, (SGX_PAGE_TYPE_TRIM << SGX_SECINFO_FLAGS_TYPE_SHIFT)
                                                | SGX_SECINFO_FLAGS_MODIFIED);
        if (ret < 0) {
            log_error("failed to accept page removal at address %#lx: %d", addr + i * PAGE_SIZE,
                      ret);
            /* Since these errors do not happen in legitimate cases and restoring already accepted
             * pages would be cumbersome, we just kill the whole process. */
            die_or_inf_loop();
        }
    }

    ret = ocall_edmm_remove_pages(addr, count);
    if (ret < 0) {
        log_error("failed to remove pages at %#lx-%#lx: %s", addr, addr + count * PAGE_SIZE,
                  unix_strerror(ret));
        /* Since these errors do not happen in legitimate cases and restoring already accepted pages
         * would be cumbersome, we just kill the whole process. */
        die_or_inf_loop();
    }

    return 0;
}

/* wrapper functions for the callbacks */
static int sgx_edmm_add_pages_callback(uintptr_t addr, size_t count, void* prot) {
    int ret = sgx_edmm_add_pages(addr, count, *(uint64_t*)prot);
    if (ret < 0)
        return ret;

    set_enclave_addr_range((uintptr_t)addr, count);
    return 0;
}

static int sgx_edmm_remove_pages_callback(uintptr_t addr, size_t count,
                                   void* unused __attribute__((unused))) {
    int ret = sgx_edmm_remove_pages(addr, count);
    if (ret < 0)
        return ret;

    unset_enclave_addr_range((uintptr_t)addr, count);
    return 0;
}

int sgx_edmm_set_page_permissions(uint64_t addr, size_t count, uint64_t prot) {
    if (prot & SGX_SECINFO_FLAGS_W) {
        /* HW limitation. */
        prot |= SGX_SECINFO_FLAGS_R;
    }

    for (size_t i = 0; i < count; i++) {
        sgx_emodpe(addr + i * PAGE_SIZE, prot);
    }

    int ret = ocall_edmm_restrict_pages_perm(addr, count, prot);
    if (ret < 0) {
        log_error("failed to restrict pages permissions at %#lx-%#lx: %s", addr,
                  addr + count * PAGE_SIZE, unix_strerror(ret));
        /* Since these errors do not happen in legitimate cases and restoring old permissions would
         * be cumbersome, we just kill the whole process. */
        die_or_inf_loop();
    }

    for (size_t i = 0; i < count; i++) {
        ret = sgx_eaccept(addr + i * PAGE_SIZE, (SGX_PAGE_TYPE_REG << SGX_SECINFO_FLAGS_TYPE_SHIFT)
                                                | SGX_SECINFO_FLAGS_PR | prot);
        if (ret < 0) {
            log_error("failed to accept restricted pages permissions at %#lx: %d",
                      addr + i * PAGE_SIZE, ret);
            /* Since these errors do not happen in legitimate cases and restoring old permissions
             * would be cumbersome, we just kill the whole process. */
            die_or_inf_loop();
        }
    }

    return 0;
}

/* create a new page tracker with the specified base address, number of pages, and page size */
static enclave_page_tracker_t* create_enclave_page_tracker(uintptr_t base_address,
                                                           size_t num_pages, size_t page_size) {
    enclave_page_tracker_t* tracker = malloc(sizeof(enclave_page_tracker_t));
    if (!tracker)
        INIT_FAIL("cannot allocate enclave page tracker");
    tracker->data = (unsigned char*)calloc(ALIGN_UP(num_pages, 8) / 8, sizeof(unsigned char));
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
    assert(IS_ALIGNED(memory_size, page_size));

    size_t num_pages = memory_size / page_size;
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
    assert(spinlock_is_locked(&g_enclave_page_tracker_lock));
    g_enclave_page_tracker->data[index / 8] |= 1 << (index % 8);
}

/* set an enclave page as free in the page tracker */
static inline void unset_enclave_page(size_t index) {
    assert(spinlock_is_locked(&g_enclave_page_tracker_lock));
    g_enclave_page_tracker->data[index / 8] &= ~(1 << (index % 8));
}

/* check if an enclave page is allocated in the page tracker */
static inline bool is_enclave_page_set(size_t index) {
    assert(spinlock_is_locked(&g_enclave_page_tracker_lock));
    return (g_enclave_page_tracker->data[index / 8] & (1 << (index % 8))) != 0;
}

/* set a range of enclave pages as allocated according to the memory address and number of pages */
void set_enclave_addr_range(uintptr_t start_addr, size_t num_pages) {
    spinlock_lock(&g_enclave_page_tracker_lock);
    for (size_t i = 0; i < num_pages; i++) {
        uintptr_t address = start_addr + i * g_enclave_page_tracker->page_size;
        size_t index = address_to_index(address);
        set_enclave_page(index);
    }
    spinlock_unlock(&g_enclave_page_tracker_lock);
}

/* set a range of enclave pages as free according to the memory address and number of pages */
void unset_enclave_addr_range(uintptr_t start_addr, size_t num_pages) {
    spinlock_lock(&g_enclave_page_tracker_lock);
    for (size_t i = 0; i < num_pages; i++) {
        uintptr_t address = start_addr + i * g_enclave_page_tracker->page_size;
        size_t index = address_to_index(address);
        unset_enclave_page(index);
    }
    spinlock_unlock(&g_enclave_page_tracker_lock);
}

static void copy_bitvector_with_offset(unsigned char* dest_bitvector,
                                       const unsigned char* src_bitvector,
                                       size_t num_bytes, size_t offset) {
    assert(offset < 8);

    if (offset == 0) {
        memcpy((void*)dest_bitvector, (void*)src_bitvector, num_bytes);
    } else {
        unsigned char val_cur = src_bitvector[0];
        for (size_t i = 0; i < num_bytes; i++) {
            unsigned char val_next = src_bitvector[i + 1];
            dest_bitvector[i] = ((val_next & (0xFF >> (8 - offset))) << (8 - offset)) |
                                ((val_cur & (0xFF << offset)) >> offset);
            val_cur = val_next;
        }
    }
}

/* get a copy of bitvector slice reflecting pages starting from `addr` and with `size` in length;
 * on success, also give the actual size of the bitvector slice */
int get_bitvector_slice(uintptr_t addr, size_t size, unsigned char* bitvector,
                        size_t* bitvector_size) {
    size_t start_page = address_to_index(addr);
    size_t num_pages = ALIGN_UP(size, g_enclave_page_tracker->page_size) /
                       g_enclave_page_tracker->page_size;

    size_t num_bytes = ALIGN_UP(num_pages, 8) / 8;
    if (num_bytes > *bitvector_size)
        return -PAL_ERROR_NOMEM;
    *bitvector_size = num_bytes;

    size_t start_byte = start_page / 8;
    size_t start_offset = start_page % 8;
    spinlock_lock(&g_enclave_page_tracker_lock);
    copy_bitvector_with_offset(bitvector, &g_enclave_page_tracker->data[start_byte], num_bytes,
                               start_offset);
    spinlock_unlock(&g_enclave_page_tracker_lock);

    size_t leftover_pages = num_pages % 8;
    if (leftover_pages)
        bitvector[num_bytes - 1] &= (1 << leftover_pages) - 1;

    return 0;
}

/* iterate over the given range of enclave pages in the tracker and perform the specified `callback`
 * on the consecutive set/unset pages; return error when `callback` failed */
static int walk_pages(uintptr_t start_addr, size_t count, bool walk_set_pages,
                      int (*callback)(uintptr_t, size_t, void*), void* arg) {
    int ret = 0;
    size_t start = address_to_index(start_addr);
    size_t end = start + count;

    size_t i = start;
    while (i < end && i < g_enclave_page_tracker->size) {
        uintptr_t consecutive_start_addr = 0;
        size_t consecutive_count = 0;

        /* find consecutive set/unset pages */
        spinlock_lock(&g_enclave_page_tracker_lock);
        if (is_enclave_page_set(i) == walk_set_pages) {
            consecutive_start_addr = index_to_address(i);
            while (i < end && i < g_enclave_page_tracker->size &&
                   is_enclave_page_set(i) == walk_set_pages) {
                consecutive_count++;
                i++;
            }
        } else {
            i++;
        }
        spinlock_unlock(&g_enclave_page_tracker_lock);

        if (consecutive_count > 0) {
            /* invoke the `callback` on the consecutive pages */
            ret = callback(consecutive_start_addr, consecutive_count, arg);
            if (ret < 0)
                break;
        }
    }

    return ret;
}

int remove_committed_pages(uintptr_t start_addr, size_t count) {
    return walk_pages(start_addr, count, /*walk_set_pages=*/true, sgx_edmm_remove_pages_callback,
                      NULL);
}

int add_uncommitted_pages(uintptr_t start_addr, size_t count, uint64_t prot_flags) {
    return walk_pages(start_addr, count, /*walk_set_pages=*/false, sgx_edmm_add_pages_callback,
                      &prot_flags);
}
