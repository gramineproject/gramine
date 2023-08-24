/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 *                    Kailun Qin <kailun.qin@intel.com>
 */

#include "pal.h"
#include "sgx_arch.h"

static inline uint64_t PAL_TO_SGX_PROT(pal_prot_flags_t pal_prot) {
    return (pal_prot & PAL_PROT_READ ? SGX_SECINFO_FLAGS_R : 0)
           | (pal_prot & PAL_PROT_WRITE ? SGX_SECINFO_FLAGS_W : 0)
           | (pal_prot & PAL_PROT_EXEC ? SGX_SECINFO_FLAGS_X : 0);
}

typedef struct {
    /* bitvector to store the lazy commit status of enclave pages:
     * `1` -- a lazily-committed page (i.e., an uncommitted page of `PAL_PROT_LAZYALLOC`);
     * `0` -- a page of nonexistent VMAs or a committed page */
    uint8_t* is_lazily_committed;

    uintptr_t enclave_base_address; /* base address of the enclave memory space */
    size_t enclave_pages;           /* number of pages in the enclave memory space */

    /* meta bitvector to store the allocation status of the enclave pages used by the
     * `is_lazily_committed` bitvector:
     * `1` -- a page of the bitvector is allocated
     * `0` -- a page of the bitvector is unallocated */
    uint8_t* is_bitvector_page_allocated;
} enclave_lazy_commit_page_tracker_t;

extern enclave_lazy_commit_page_tracker_t* g_enclave_lazy_commit_page_tracker;

void init_enclave_lazy_commit_page_tracker(uintptr_t enclave_base_address, size_t enclave_pages);
void set_enclave_lazy_commit_pages(uintptr_t start_addr, size_t page_count);
void unset_enclave_lazy_commit_pages(uintptr_t start_addr, size_t page_count);
void get_lazy_commit_pages_bitvector_slice(uintptr_t start_addr, size_t page_count,
                                           uint8_t* bitvector);
int uncommit_pages(uintptr_t start_addr, size_t page_count);
int uncommit_then_lazy_realloc_pages(uintptr_t start_addr, size_t page_count);
int maybe_commit_pages(uintptr_t start_addr, size_t page_count, pal_prot_flags_t prot);
int commit_lazy_alloc_pages(uintptr_t start_addr, size_t page_count, pal_prot_flags_t prot);
int set_committed_pages_permissions(uintptr_t start_addr, size_t page_count, pal_prot_flags_t prot);
