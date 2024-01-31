/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
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
    uintptr_t addr;
    size_t num_pages;
} initial_page_alloc_t;

#define MAX_INITIAL_PAGE_ALLOCS 8
extern initial_page_alloc_t g_initial_page_allocs[MAX_INITIAL_PAGE_ALLOCS];
extern size_t g_initial_page_allocs_count;

/* For a 1GB enclave, the bitmap will contain 1024*1024*1024 / 4096 / 8 = 32768 bytes, or 32KB.
 * Similarly, it will occupy 1048576 bytes (1MB) for a 32GB enclave and 32MB for a 1TB enclave.
 * So the memory overhead for the bitmap is 0.003%. */
typedef struct {
    uint8_t* data;          /* bit array to store page allocation status */
    uintptr_t base_address; /* base address of the enclave memory space */
    size_t size;            /* number of pages in the enclave memory space */
} enclave_page_tracker_t;

extern enclave_page_tracker_t* g_enclave_page_tracker;

void initialize_enclave_page_tracker(uintptr_t base_address, size_t memory_size);
void set_enclave_addr_range(uintptr_t start_address, size_t num_pages);
void unset_enclave_addr_range(uintptr_t start_address, size_t num_pages);
int get_bitvector_slice(uintptr_t addr, size_t size, uint8_t* bitvector, size_t* bitvector_size);
int uncommit_pages(uintptr_t start_addr, size_t count);
int commit_pages(uintptr_t start_addr, size_t count, uint64_t prot_flags);
int commit_one_page_strict(uintptr_t start_addr, uint64_t prot_flags);
int set_committed_page_permissions(uintptr_t start_addr, size_t count, uint64_t prot_flags);
