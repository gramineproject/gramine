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
     * `1` -- to-be-lazily-committed pages (i.e., uncommitted pages of `PAL_PROT_LAZYALLOC`);
     * `0` -- both pages of nonexistent VMAs and committed pages */
    uint8_t* lazy_commit_status;

    uintptr_t enclave_base_address; /* base address of the enclave memory space */
    size_t enclave_pages;           /* number of pages in the enclave memory space */

    /* bitvector to store the page allocation status of the `lazy_commit_pages_status` bitvector */
    uint8_t* bitvector_alloc_status;
} enclave_lazy_commit_page_tracker_t;

extern enclave_lazy_commit_page_tracker_t* g_enclave_lazy_commit_page_tracker;

int initialize_enclave_lazy_commit_page_tracker(uintptr_t enclave_base_address,
                                                size_t enclave_size);
void set_enclave_lazy_commit_addr_range(uintptr_t start_address, size_t num_pages);
void unset_enclave_lazy_commit_addr_range(uintptr_t start_address, size_t num_pages);
int get_lazy_commit_bitvector_slice(uintptr_t addr, size_t size, uint8_t* bitvector,
                                    size_t* bitvector_size);
int uncommit_pages(uintptr_t start_addr, size_t count);
int uncommit_then_lazy_realloc_pages(uintptr_t start_addr, size_t count);
int maybe_commit_pages(uintptr_t start_addr, size_t count, pal_prot_flags_t prot);
int commit_lazy_alloc_pages(uintptr_t start_addr, size_t count, pal_prot_flags_t prot);
int set_committed_page_permissions(uintptr_t start_addr, size_t count, pal_prot_flags_t prot);
