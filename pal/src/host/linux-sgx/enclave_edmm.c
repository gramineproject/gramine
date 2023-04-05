/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <stdalign.h>

#include "api.h"
#include "cpu.h"
#include "enclave_ocalls.h"
#include "pal_error.h"
#include "pal_linux_error.h"
#include "pal_sgx.h"
#include "sgx_arch.h"

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

/* Updates page count such that the request is fully below the pre-allocated heap. If `count` is
 * updated to 0, then the entire request overlaps with pre-allocated heap.
 *
 * Partial overlap illustration:
                ------------------------ --> heap_max
                |                      |
addr + size <-- |  Pre-allocated heap  |
                |                      |
                ------------------------ --> edmm_heap_prealloc_start
                |                      |     (heap_max + edmm_heap_prealloc_size)
                |  Dynamically         |
       addr <-- |  allocated heap      |
                |                      |
                ------------------------
*/
static void exclude_preallocated_pages(uint64_t addr, size_t* count) {
    size_t size = *count * PAGE_SIZE;
    uint64_t edmm_heap_prealloc_start = (uint64_t)g_pal_linuxsgx_state.heap_max -
                                        g_pal_linuxsgx_state.edmm_heap_prealloc_size;

    if (addr >= edmm_heap_prealloc_start) {
        /* full overlap: entire request lies in the pre-allocated region */
        *count = 0;
    } else if (addr + size > edmm_heap_prealloc_start) {
        /* partial overlap: update count to skip the pre-allocated region */
        *count = (edmm_heap_prealloc_start - addr) / PAGE_SIZE;
    } else {
        /* no overlap: don't update count */
    }
}

int sgx_edmm_add_pages(uint64_t addr, size_t count, uint64_t prot) {
    int ret;

    if (prot & SGX_SECINFO_FLAGS_W) {
        /* HW limitation. */
        prot |= SGX_SECINFO_FLAGS_R;
    }

    if (g_pal_linuxsgx_state.edmm_heap_prealloc_size > 0) {
        size_t original_count = count;
        exclude_preallocated_pages(addr, &count);

        size_t preallocated_count = original_count - count;
        if (preallocated_count != 0) {
            memset((void*)(addr + count * PAGE_SIZE), 0, preallocated_count * PAGE_SIZE);
            if (count == 0) {
                /* Entire request is in pre-allocated range */
                return 0;
            }
        }
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
    if (g_pal_linuxsgx_state.edmm_heap_prealloc_size > 0) {
        exclude_preallocated_pages(addr, &count);
        if (count == 0)
            return 0;
    }

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

int sgx_edmm_set_page_permissions(uint64_t addr, size_t count, uint64_t prot) {
    if (g_pal_linuxsgx_state.edmm_heap_prealloc_size > 0) {
        exclude_preallocated_pages(addr, &count);
        if (count == 0)
            return 0;
    }

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
