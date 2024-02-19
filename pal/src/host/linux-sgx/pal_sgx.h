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

/* For a 1TB enclave, the bitmap will contain 1024*1024*1024*1024 / 4096 / 8 = 33,554,432 bytes, or
 * 32MB. So we pre-define 8192 pages in the bitmap memory space. */
#define ENCLAVE_PAGE_TRACKER_BITMAP_PAGES 8192

typedef struct {
    uint8_t* data;                  /* bit array to store enclave page allocation status */
    uintptr_t enclave_base_address; /* base address of the enclave memory space */
    size_t enclave_pages;           /* number of pages in the enclave memory space */
    /* bit array to store bitmap page allocation status */
    uint8_t bitmap_pages_status[ENCLAVE_PAGE_TRACKER_BITMAP_PAGES / 8];
} enclave_page_tracker_t;

extern enclave_page_tracker_t* g_enclave_page_tracker;

int initialize_enclave_page_tracker(uintptr_t tracker_address, uintptr_t enclave_base_address,
                                    size_t memory_size);
void set_enclave_addr_range(uintptr_t start_address, size_t num_pages);
void unset_enclave_addr_range(uintptr_t start_address, size_t num_pages);
int get_bitvector_slice(uintptr_t addr, size_t size, uint8_t* bitvector, size_t* bitvector_size);
int uncommit_pages(uintptr_t start_addr, size_t count);
int commit_pages(uintptr_t start_addr, size_t count, uint64_t prot_flags);
int set_committed_page_permissions(uintptr_t start_addr, size_t count, uint64_t prot_flags);
