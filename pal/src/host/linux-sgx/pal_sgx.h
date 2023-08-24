/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "pal.h"
#include "sgx_arch.h"
#include "spinlock.h"

static inline uint64_t PAL_TO_SGX_PROT(pal_prot_flags_t pal_prot) {
    return (pal_prot & PAL_PROT_READ ? SGX_SECINFO_FLAGS_R : 0)
           | (pal_prot & PAL_PROT_WRITE ? SGX_SECINFO_FLAGS_W : 0)
           | (pal_prot & PAL_PROT_EXEC ? SGX_SECINFO_FLAGS_X : 0);
}

typedef struct {
    unsigned char* data;    /* bit array to store page allocation status */
    uintptr_t base_address; /* base address of the enclave memory region */
    size_t size;            /* number of pages in the memory region */
    size_t page_size;       /* size of each page in bytes */
    spinlock_t lock;        /* lock for the page tracker */
} enclave_page_tracker_t;

extern enclave_page_tracker_t* g_enclave_page_tracker;

void initialize_enclave_page_tracker(uintptr_t base_address, size_t memory_size, size_t page_size);
void set_enclave_addr_range(uintptr_t start_address, size_t num_pages);
void unset_enclave_addr_range(uintptr_t start_address, size_t num_pages);
int walk_set_pages(uintptr_t start_addr, size_t count,
                   int (*callback)(uintptr_t, size_t, void*), void* arg);
int walk_unset_pages(uintptr_t start_addr, size_t count,
                     int (*callback)(uintptr_t, size_t, void*), void* arg);
