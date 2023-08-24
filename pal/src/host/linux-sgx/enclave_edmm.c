/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 *                    Kailun Qin <kailun.qin@intel.com>
 */

#include <stdalign.h>

#include "api.h"
#include "cpu.h"
#include "enclave_ocalls.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux_error.h"
#include "pal_sgx.h"
#include "sgx_arch.h"
#include "spinlock.h"

/*
 * Global enclave lazy commit page tracker (based on a two-level bit vector) used for EDMM lazy
 * allocation.
 *
 * This is required for the memory free() flows, where we have to know whether the to-be-freed pages
 * were already EACCEPTed (so that we need to remove them) or not (so that we can simply skip them).
 * Note that such commit status of enclave pages cannot be provided via SGX driver APIs since
 * they're not trusted under the threat model of SGX; also no user-space SGX instruction is
 * currently giving such info. This is also required to avoid double-allocating the page in the page
 * fault handler. See "pal_exception.c" for more details.
 *
 * We don't use this lazy commit page tracker to store info required in the #PF flows (e.g.
 * enclave-page permissions). Instead, we get this info from the LibOS VMA subsystem, for which we
 * use a special upcall, see `g_mem_bkeep_get_vma_info_upcall()`.
 */
enclave_lazy_commit_page_tracker_t* g_enclave_lazy_commit_page_tracker = NULL;

static spinlock_t g_enclave_lazy_commit_page_tracker_lock = INIT_SPINLOCK_UNLOCKED;

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

    unset_enclave_lazy_commit_pages(addr, count);
    return 0;
}

static int sgx_edmm_remove_pages_callback(uintptr_t addr, size_t count,
                                          void* unused __attribute__((unused))) {
    int ret = sgx_edmm_remove_pages(addr, count);
    if (ret < 0)
        return ret;

    unset_enclave_lazy_commit_pages(addr, count);
    return 0;
}

static int sgx_edmm_remove_then_lazy_realloc_pages_callback(uintptr_t addr, size_t count,
                                                            void* unused __attribute__((unused))) {
    int ret = sgx_edmm_remove_pages(addr, count);
    if (ret < 0)
        return ret;

    set_enclave_lazy_commit_pages(addr, count);
    return 0;
}

static int sgx_edmm_set_page_permissions_callback(uintptr_t addr, size_t count, void* prot) {
    int ret = sgx_edmm_set_page_permissions(addr, count, *(uint64_t*)prot);
    if (ret < 0)
        return ret;

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

int sgx_edmm_convert_pages_to_tcs(uint64_t addr, size_t count) {
    int ret = ocall_edmm_modify_pages_type(addr, count, SGX_PAGE_TYPE_TCS);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }

    for (size_t i = 0; i < count; i++) {
        ret = sgx_eaccept(addr + i * PAGE_SIZE, (SGX_PAGE_TYPE_TCS << SGX_SECINFO_FLAGS_TYPE_SHIFT)
                                                | SGX_SECINFO_FLAGS_MODIFIED);
        if (ret < 0) {
            log_error("failed to accept modified page type at address %#lx: %d",
                      addr + i * PAGE_SIZE, ret);
            /* Since these errors do not happen in legitimate cases and restoring already accepted
             * pages would be cumbersome, we just kill the whole process. */
            die_or_inf_loop();
        }
    }
    return 0;
}

/* initializes the enclave lazy commit page tracker with the the specified enclave memory base
 * address and the count of enclave pages */
void init_enclave_lazy_commit_page_tracker(uintptr_t enclave_base_address, size_t enclave_pages) {
    assert(!g_enclave_lazy_commit_page_tracker);

    enclave_lazy_commit_page_tracker_t* tracker = calloc(1, sizeof(*tracker));
    if (!tracker)
        INIT_FAIL("Allocating enclave lazy commit page tracker failed");
    tracker->enclave_base_address = enclave_base_address;
    tracker->enclave_pages = enclave_pages;

    size_t lazy_commit_bitvector_size = UDIV_ROUND_UP(enclave_pages, 8);
    uintptr_t lazy_commit_bitvector_addr;
    int ret = initial_mem_bkeep(lazy_commit_bitvector_size, &lazy_commit_bitvector_addr);
    if (ret < 0)
        INIT_FAIL("Reserving bitvector for lazily committed pages failed");
    tracker->is_lazily_committed = (uint8_t*)lazy_commit_bitvector_addr;

    size_t bitvector_page_alloc_status_size =
        UDIV_ROUND_UP(UDIV_ROUND_UP(lazy_commit_bitvector_size, PAGE_SIZE), 8);
    tracker->is_bitvector_page_allocated = calloc(1, bitvector_page_alloc_status_size);
    if (!tracker->is_bitvector_page_allocated)
        INIT_FAIL("Allocating meta bitvector for bitvector pages failed");

    g_enclave_lazy_commit_page_tracker = tracker;
}

static inline bool completely_within_tracked_range(uintptr_t addr, size_t page_count) {
    return g_enclave_lazy_commit_page_tracker->enclave_base_address <= addr &&
           (addr + page_count * PAGE_SIZE) <=
           (g_enclave_lazy_commit_page_tracker->enclave_base_address +
            g_enclave_lazy_commit_page_tracker->enclave_pages * PAGE_SIZE);
}

/* converts an address to an index in the page tracker */
static inline size_t address_to_index(uintptr_t addr) {
    assert(completely_within_tracked_range(addr, /*page_count=*/1));
    return (addr - g_enclave_lazy_commit_page_tracker->enclave_base_address) / PAGE_SIZE;
}

/* converts an index in the page tracker to an address */
static inline uintptr_t index_to_address(size_t index) {
    return g_enclave_lazy_commit_page_tracker->enclave_base_address + index * PAGE_SIZE;
}

/* sets an enclave page as lazily-committed in the tracker */
static inline void set_enclave_lazy_commit_page(size_t index) {
    assert(spinlock_is_locked(&g_enclave_lazy_commit_page_tracker_lock));
    g_enclave_lazy_commit_page_tracker->is_lazily_committed[index / 8] |= 1 << (index % 8);
}

/* unsets a lazily-committed enclave page in the tracker */
static inline void unset_enclave_lazy_commit_page(size_t index) {
    assert(spinlock_is_locked(&g_enclave_lazy_commit_page_tracker_lock));
    g_enclave_lazy_commit_page_tracker->is_lazily_committed[index / 8] &= ~(1 << (index % 8));
}

/* checks if an enclave page is lazily-committed in the tracker */
static inline bool is_enclave_lazy_commit_page_set(size_t index) {
    assert(spinlock_is_locked(&g_enclave_lazy_commit_page_tracker_lock));
    return (g_enclave_lazy_commit_page_tracker->is_lazily_committed[index / 8] &
            (1 << (index % 8))) != 0;
}

/* sets a range of enclave pages as lazily-committed according to the memory address and number
 * of pages */
void set_enclave_lazy_commit_pages(uintptr_t start_addr, size_t page_count) {
    assert(completely_within_tracked_range(start_addr, page_count));
    assert(spinlock_is_locked(&g_enclave_lazy_commit_page_tracker_lock));
    for (size_t i = 0; i < page_count; i++) {
        uintptr_t addr = start_addr + i * PAGE_SIZE;
        size_t index = address_to_index(addr);
        set_enclave_lazy_commit_page(index);
    }
}

/* unsets a range of lazily-committed enclave pages according to the memory address and number of
 * pages */
void unset_enclave_lazy_commit_pages(uintptr_t start_addr, size_t page_count) {
    assert(completely_within_tracked_range(start_addr, page_count));
    assert(spinlock_is_locked(&g_enclave_lazy_commit_page_tracker_lock));
    for (size_t i = 0; i < page_count; i++) {
        uintptr_t addr = start_addr + i * PAGE_SIZE;
        size_t index = address_to_index(addr);
        unset_enclave_lazy_commit_page(index);
    }
}

static int unset_enclave_lazy_commit_pages_callback(uintptr_t start_addr, size_t page_count,
                                                    void* unused __attribute__((unused))) {
    unset_enclave_lazy_commit_pages(start_addr, page_count);
    return 0;
}

static void copy_bitvector_with_offset(uint8_t* dest_bitvector, const uint8_t* src_bitvector,
                                       size_t src_offset_bits, size_t size_bits) {
    assert(dest_bitvector != NULL);
    assert(src_bitvector != NULL);
    assert(src_offset_bits < 8);

    if (size_bits == 0)
        return;

    size_t full_bytes = size_bits / 8;
    size_t leftover_bits = size_bits % 8;

    if (src_offset_bits == 0) {
        memcpy((void*)dest_bitvector, (void*)src_bitvector, full_bytes);

        if (leftover_bits)
            dest_bitvector[full_bytes] = src_bitvector[full_bytes] & ((1 << leftover_bits) - 1);
    } else {
        for (size_t i = 0, bit_pos = 0; bit_pos < size_bits; i++, bit_pos += 8) {
            uint8_t val_cur = src_bitvector[i];
            uint8_t val_next = ((i + 1) * 8 < size_bits + src_offset_bits) ?
                               src_bitvector[i + 1] : 0;

            dest_bitvector[i] = (val_next << (8 - src_offset_bits)) | (val_cur >> src_offset_bits);
        }

        if (leftover_bits)
            dest_bitvector[full_bytes] &= (1 << leftover_bits) - 1;
    }
}

/* gets a copy of bitvector slice reflecting the lazily-committed pages starting from `addr` and
 * with `page_count` of pages in length */
void get_lazy_commit_pages_bitvector_slice(uintptr_t addr, size_t page_count, uint8_t* bitvector) {
    assert(completely_within_tracked_range(addr, page_count));

    size_t start_page = address_to_index(addr);
    assert(start_page + page_count <= g_enclave_lazy_commit_page_tracker->enclave_pages);

    size_t start_byte = start_page / 8;
    size_t start_offset = start_page % 8;

    spinlock_lock(&g_enclave_lazy_commit_page_tracker_lock);
    copy_bitvector_with_offset(bitvector,
                               &g_enclave_lazy_commit_page_tracker->is_lazily_committed[start_byte],
                               start_offset, page_count);
    spinlock_unlock(&g_enclave_lazy_commit_page_tracker_lock);
}

/* This function iterates over the given range of enclave pages in the tracker and performs the
 * specified `callback()` on the consecutive set/unset pages based on `walk_set_pages`. Meanwhile,
 * when enclave pages have mismatched set/unset status recorded and from the input,
 * `callback_mismatch()` will be executed if specified; otherwise they will be skipped by default.
 * This function returns an error when `callback()` or `callback_mismatch()` failed. */
static int walk_pages(uintptr_t start_addr, size_t page_count, bool walk_set_pages,
                      int (*callback)(uintptr_t, size_t, void*), void* arg,
                      int (*callback_mismatch)(uintptr_t, size_t, void*), void* arg_mismatch) {
    assert(completely_within_tracked_range(start_addr, page_count));

    int ret = 0;
    size_t start = address_to_index(start_addr);
    size_t end = start + page_count;
    assert(end <= g_enclave_lazy_commit_page_tracker->enclave_pages);

    spinlock_lock(&g_enclave_lazy_commit_page_tracker_lock);

    size_t i = start;
    while (i < end) {
        /* find consecutive set/unset pages */
        bool is_page_set = is_enclave_lazy_commit_page_set(i);
        if (is_page_set == walk_set_pages) {
            uintptr_t consecutive_start_addr = index_to_address(i);
            size_t consecutive_page_count = 0;
            while (i < end && is_enclave_lazy_commit_page_set(i) == walk_set_pages) {
                consecutive_page_count++;
                i++;
            }

            /* invoke the `callback` on the consecutive pages */
            ret = callback(consecutive_start_addr, consecutive_page_count, arg);
            if (ret < 0)
                break;
        } else {
            if (callback_mismatch) {
                uintptr_t consecutive_start_addr = index_to_address(i);
                size_t consecutive_page_count = 0;
                while (i < end && is_enclave_lazy_commit_page_set(i) != walk_set_pages) {
                    consecutive_page_count++;
                    i++;
                }

                ret = callback_mismatch(consecutive_start_addr, consecutive_page_count,
                                        arg_mismatch);
                if (ret < 0)
                    break;
            } else {
                i++;
            }
        }
    }

    spinlock_unlock(&g_enclave_lazy_commit_page_tracker_lock);

    return ret;
}

static int maybe_alloc_bitvector_pages_eagerly(uintptr_t start_addr, size_t page_count) {
    assert(completely_within_tracked_range(start_addr, page_count));

    size_t start_bitvector_index = address_to_index(start_addr);
    size_t end_bitvector_index = start_bitvector_index + page_count;
    size_t first_bitvector_page_index = start_bitvector_index / (PAGE_SIZE * 8);
    size_t last_bitvector_page_index = (end_bitvector_index - 1) / (PAGE_SIZE * 8);

    spinlock_lock(&g_enclave_lazy_commit_page_tracker_lock);

    for (size_t bitvector_page_index = first_bitvector_page_index;
         bitvector_page_index <= last_bitvector_page_index; bitvector_page_index++) {
        size_t alloc_status_index = bitvector_page_index / 8;
        uint8_t bit_mask = 1 << (bitvector_page_index % 8);

        if ((g_enclave_lazy_commit_page_tracker->is_bitvector_page_allocated[alloc_status_index]
                                                 & bit_mask) == 0) {
            int ret = sgx_edmm_add_pages(
                (uintptr_t)g_enclave_lazy_commit_page_tracker->is_lazily_committed +
                bitvector_page_index * PAGE_SIZE,
                /*count=*/1, PAL_TO_SGX_PROT(PAL_PROT_READ | PAL_PROT_WRITE));
            if (ret < 0) {
                spinlock_unlock(&g_enclave_lazy_commit_page_tracker_lock);
                return ret;
            }

            g_enclave_lazy_commit_page_tracker->is_bitvector_page_allocated[alloc_status_index]
                                                |= bit_mask;
        }
    }

    spinlock_unlock(&g_enclave_lazy_commit_page_tracker_lock);

    return 0;
}

int uncommit_pages(uintptr_t start_addr, size_t page_count) {
    assert(g_enclave_lazy_commit_page_tracker);
    assert(completely_within_tracked_range(start_addr, page_count));

    int ret = maybe_alloc_bitvector_pages_eagerly(start_addr, page_count);
    if (ret < 0)
        return ret;

    return walk_pages(start_addr, page_count, /*walk_set_pages=*/false,
                      sgx_edmm_remove_pages_callback, /*arg=*/NULL,
                      unset_enclave_lazy_commit_pages_callback, /*arg_mismatch=*/NULL);
}

int uncommit_then_lazy_realloc_pages(uintptr_t start_addr, size_t page_count) {
    assert(g_enclave_lazy_commit_page_tracker);
    assert(completely_within_tracked_range(start_addr, page_count));

    int ret = maybe_alloc_bitvector_pages_eagerly(start_addr, page_count);
    if (ret < 0)
        return ret;

    return walk_pages(start_addr, page_count, /*walk_set_pages=*/false,
                      sgx_edmm_remove_then_lazy_realloc_pages_callback, /*arg=*/NULL,
                      /*callback_mismatch=*/NULL, /*arg_mismatch=*/NULL);
}

int maybe_commit_pages(uintptr_t start_addr, size_t page_count, pal_prot_flags_t prot) {
    int ret;
    uint64_t prot_flags = PAL_TO_SGX_PROT(prot);

    if (g_enclave_lazy_commit_page_tracker) {
        assert(completely_within_tracked_range(start_addr, page_count));

        ret = maybe_alloc_bitvector_pages_eagerly(start_addr, page_count);
        if (ret < 0)
            return ret;

        if (prot & PAL_PROT_LAZYALLOC) {
            /* defer page accepts to page-fault events when `PAL_PROT_LAZYALLOC` is set */
            spinlock_lock(&g_enclave_lazy_commit_page_tracker_lock);
            set_enclave_lazy_commit_pages(start_addr, page_count);
            spinlock_unlock(&g_enclave_lazy_commit_page_tracker_lock);
            return 0;
        }

        ret = walk_pages(start_addr, page_count, /*walk_set_pages=*/false,
                         sgx_edmm_add_pages_callback, &prot_flags,
                         /*callback_mismatch=*/NULL, /*arg_mismatch=*/NULL);
    } else {
        /* for enclave pages allocated when the tracker is not ready (on bootstrap) */
        ret = sgx_edmm_add_pages(start_addr, page_count, prot_flags);
    }

    return ret;
}

int commit_lazy_alloc_pages(uintptr_t start_addr, size_t page_count, pal_prot_flags_t prot) {
    assert(g_enclave_lazy_commit_page_tracker);
    assert(completely_within_tracked_range(start_addr, page_count));

    int ret = maybe_alloc_bitvector_pages_eagerly(start_addr, page_count);
    if (ret < 0)
        return ret;

    uint64_t prot_flags = PAL_TO_SGX_PROT(prot);
    ret = walk_pages(start_addr, page_count, /*walk_set_pages=*/true, sgx_edmm_add_pages_callback,
                     &prot_flags, /*callback_mismatch=*/NULL, /*arg_mismatch=*/NULL);
    if (ret < 0)
        return ret;

    return 0;
}

int set_committed_pages_permissions(uintptr_t start_addr, size_t page_count,
                                    pal_prot_flags_t prot) {
    assert(g_enclave_lazy_commit_page_tracker);
    assert(completely_within_tracked_range(start_addr, page_count));

    int ret = maybe_alloc_bitvector_pages_eagerly(start_addr, page_count);
    if (ret < 0)
        return ret;

    uint64_t prot_flags = PAL_TO_SGX_PROT(prot);
    return walk_pages(start_addr, page_count, /*walk_set_pages=*/false,
                      sgx_edmm_set_page_permissions_callback, &prot_flags,
                      /*callback_mismatch=*/NULL, /*arg_mismatch=*/NULL);
}
