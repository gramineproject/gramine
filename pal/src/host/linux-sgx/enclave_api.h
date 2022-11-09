/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#pragma once

#include "sgx_arch.h"

long sgx_ocall(uint64_t code, void* ms);

bool sgx_is_completely_within_enclave(const void* addr, size_t size);
bool sgx_is_valid_untrusted_ptr(const void* addr, size_t size, size_t alignment);

void* sgx_prepare_ustack(void);
void* sgx_alloc_on_ustack_aligned(uint64_t size, size_t alignment);
void* sgx_alloc_on_ustack(uint64_t size);
void* sgx_copy_to_ustack(const void* ptr, uint64_t size);
void sgx_reset_ustack(const void* old_ustack);

void sgx_copy_to_enclave_verified(void* ptr, const void* uptr, size_t size);
bool sgx_copy_to_enclave(void* ptr, size_t maxsize, const void* uptr, size_t usize);
bool sgx_copy_from_enclave(void* urts_ptr, const void* enclave_ptr, size_t size);
void* sgx_import_array_to_enclave(const void* uptr, size_t elem_size, size_t elem_cnt);
void* sgx_import_array2d_to_enclave(const void* uptr, size_t elem_size, size_t elem_cnt1,
                                    size_t elem_cnt2);

#define COPY_UNTRUSTED_VALUE(untrusted_ptr) ({                          \
    __typeof__(*(untrusted_ptr)) val;                                   \
    sgx_copy_to_enclave_verified(&val, (untrusted_ptr), sizeof(val));   \
    val;                                                                \
})

/*!
 * \brief Low-level wrapper around EREPORT instruction leaf.
 *
 * Caller is responsible for parameter alignment: 512B for `targetinfo`, 128B for `reportdata`,
 * and 512B for `report`.
 */
int sgx_report(const sgx_target_info_t* targetinfo, const void* reportdata, sgx_report_t* report);

/*!
 * \brief Low-level wrapper around EGETKEY instruction leaf.
 *
 * Caller is responsible for parameter alignment: 512B for `keyrequest` and 16B for `key`.
 */
int64_t sgx_getkey(sgx_key_request_t* keyrequest, sgx_key_128bit_t* key);

int sgx_edmm_add_pages(uint64_t addr, size_t count, uint64_t prot);
int sgx_edmm_remove_pages(uint64_t addr, size_t count);
int sgx_edmm_set_page_permissions(uint64_t addr, size_t count, uint64_t prot);
