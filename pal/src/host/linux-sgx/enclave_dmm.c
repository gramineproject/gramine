#include "enclave_dmm.h"

#include <asm/errno.h>
#include <stdalign.h>

#include "api.h"
#include "pal_error.h"
#include "pal_linux.h"
#include "pal_linux_error.h"
#include "spinlock.h"


spinlock_t g_edmm_heap_prot_lock = INIT_SPINLOCK_UNLOCKED;

/* This function allocates EPC pages within ELRANGE of an enclave. If EPC pages contain
 * executable code, page permissions are extended once the page is in a valid state. The
 * allocation sequence is described below:
 * 1. Enclave invokes EACCEPT on a new page request which triggers a page fault (#PF) as the page
 * is not available yet.
 * 2. Driver catches this #PF and issues EAUG for the page (at this point the page becomes VALID and
 * may be used by the enclave). The control returns back to enclave.
 * 3. Enclave continues the same EACCEPT and the instruction succeeds this time. */
static int get_edmm_page_range(void* start_addr, size_t size) {
    alignas(64) sgx_arch_sec_info_t secinfo;
    secinfo.flags = SGX_SECINFO_FLAGS_R | SGX_SECINFO_FLAGS_W | SGX_SECINFO_FLAGS_REG |
                    SGX_SECINFO_FLAGS_PENDING;
    memset(&secinfo.reserved, 0, sizeof(secinfo.reserved));

    void* lo = start_addr;
    void* addr = (void*)((char*)lo + size);

    while (lo < addr) {
        addr = (void*)((char*)addr - g_pal_public_state.alloc_align);

        int ret = sgx_accept(&secinfo, addr);
        if (ret) {
            log_error("EDMM accept page failed: %p %d\n", addr, ret);
            return -EFAULT;
        }
    }

    return 0;
}

int get_enclave_pages(void* addr, size_t size, pal_prot_flags_t prot) {
    int ret;

    if (!size)
        return -PAL_ERROR_NOMEM;

    size = ALIGN_UP(size, g_page_size);
    addr = ALIGN_DOWN_PTR(addr, g_page_size);

    assert(access_ok(addr, size));
    pal_prot_flags_t req_prot = (PAL_PROT_READ | PAL_PROT_WRITE | PAL_PROT_EXEC) & prot;

    ret = get_edmm_page_range(addr, size);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }

    /* Due SGX2 architectural requirement the driver sets default page permission to R | W
     * when allocating EPC pages. So, if the requested permissions is not R | W then we need
     * to update the page permissions. */
    if (req_prot != (PAL_PROT_READ | PAL_PROT_WRITE)) {
        ret = update_enclave_page_permissions(addr, size, PAL_PROT_READ | PAL_PROT_WRITE, req_prot);
        if (ret < 0) {
            log_error("%s: update_enclave_page_permissions failed, ret = %d", __func__, ret);
            return ret;
        }
    }

    return 0;
}

/* This function trims EPC pages on enclave's request. The sequence is as below:
 * 1. Enclave calls SGX driver IOCTL to change the page's type to PT_TRIM.
 * 2. Driver invokes ETRACK to track page's address on all CPUs and issues IPI to flush stale TLB
 * entries.
 * 3. Enclave issues an EACCEPT to accept changes to each EPC page.
 * 4. Enclave notifies the driver to remove EPC pages (using an IOCTL).
 * 5. Driver issues EREMOVE to complete the request. */
static int free_edmm_page_range(void* start, size_t size) {
    void* addr = ALLOC_ALIGN_DOWN_PTR(start);
    void* end = (void*)((char*)addr + size);
    int ret;

    enum sgx_page_type type = SGX_PAGE_TYPE_TRIM;
    ret = ocall_trim_epc_pages(addr, size, type);
    if (ret < 0) {
        log_error("EPC trim page on [%p, %p) failed (%d)\n", addr, end, ret);
        return ret;
    }

    alignas(64) sgx_arch_sec_info_t secinfo;
    memset(&secinfo, 0, sizeof(secinfo));
    secinfo.flags = SGX_SECINFO_FLAGS_TRIM | SGX_SECINFO_FLAGS_MODIFIED;
    for (void* page_addr = addr; page_addr < end;
        page_addr = (void*)((char*)page_addr + g_pal_public_state.alloc_align)) {
        ret = sgx_accept(&secinfo, page_addr);
        if (ret) {
            log_error("EDMM accept page failed while trimming: %p %d\n", page_addr, ret);
            return -EFAULT;
        }
    }

    ret = ocall_remove_trimmed_pages(addr, size);
    if (ret < 0) {
        log_error("EPC notify_accept on [%p, %p), %ld pages failed (%d)\n", addr, end, size, ret);
        return ret;
    }

    return 0;
}

int free_enclave_pages(void* addr, size_t size) {
    if (!size)
        return -PAL_ERROR_NOMEM;

    size = ALIGN_UP(size, g_page_size);

    if (!access_ok(addr, size)
        || !IS_ALIGNED_PTR(addr, g_page_size)
        || addr < g_pal_linuxsgx_state.heap_min
        || addr + size > g_pal_linuxsgx_state.heap_max) {
        return -PAL_ERROR_INVAL;
    }

    int ret = free_edmm_page_range(addr, size);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }

    return 0;
}

static int relax_enclave_page_permission(void* addr, size_t size, pal_prot_flags_t prot) {
    void* start = addr;
    void* end = (void*)((char*)start + size);

    alignas(64) sgx_arch_sec_info_t secinfo_relax;
    memset(&secinfo_relax, 0, sizeof(secinfo_relax));

    secinfo_relax.flags |= (prot & PAL_PROT_READ) ? SGX_SECINFO_FLAGS_R : 0;
    secinfo_relax.flags |= (prot & PAL_PROT_WRITE) ? SGX_SECINFO_FLAGS_W : 0;
    secinfo_relax.flags |= (prot & PAL_PROT_EXEC) ? SGX_SECINFO_FLAGS_X : 0;

    while (start < end) {
       sgx_modpe(&secinfo_relax, start);
       start = (void*)((char*)start + g_pal_public_state.alloc_align);
    }

    /* Update OS page tables to match new EPCM permission */
    int ret = ocall_mprotect(addr, size, prot);
    if (ret < 0) {
        log_error("mprotect for relax enclave %p page permission failed (%d)\n", addr, ret);
        return ret;
    }

    return 0;
}

static int restrict_enclave_page_permission(void* addr, size_t size, pal_prot_flags_t prot) {
    void* start = addr;
    void* end = (void*)((char*)start + size);

    uint32_t restrict_permissions;
    restrict_permissions = (prot & PAL_PROT_READ) ? SGX_SECINFO_FLAGS_R : 0;
    restrict_permissions |= (prot & PAL_PROT_WRITE) ? SGX_SECINFO_FLAGS_W : 0;
    restrict_permissions |= (prot & PAL_PROT_EXEC) ? SGX_SECINFO_FLAGS_X : 0;

    int ret = ocall_restrict_page_permissions(addr, size, restrict_permissions);
    if (ret < 0) {
        log_error("Restrict enclave page permission on %p page failed (%d)\n", addr, ret);
        return ret;
    }

    alignas(64) sgx_arch_sec_info_t secinfo_restrict;
    memset(&secinfo_restrict, 0, sizeof(secinfo_restrict));
    secinfo_restrict.flags = restrict_permissions | (SGX_SECINFO_FLAGS_REG | SGX_SECINFO_FLAGS_PR);
    while (start < end) {
        ret = sgx_accept(&secinfo_restrict, start);
        if (ret) {
            log_error("%s: EDMM accept page failed: %p %d\n", __func__, start, ret);
            return -EFAULT;
        }

        start = (void*)((char*)start + g_pal_public_state.alloc_align);
    }

    return 0;
}

int update_enclave_page_permissions(void* addr, size_t size, pal_prot_flags_t cur_prot,
                                    pal_prot_flags_t req_prot) {
    int ret;

    if (!size)
        return -PAL_ERROR_NOMEM;

    if (!access_ok(addr, size)
        || !IS_ALIGNED_PTR(addr, g_page_size)
        || !IS_ALIGNED(size, g_page_size)
        || addr < g_pal_linuxsgx_state.heap_min
        || addr + size > g_pal_linuxsgx_state.heap_max) {
        return -PAL_ERROR_INVAL;
    }

    spinlock_lock(&g_edmm_heap_prot_lock);

    req_prot = (PAL_PROT_READ | PAL_PROT_WRITE | PAL_PROT_EXEC) & req_prot;
    cur_prot = (PAL_PROT_READ | PAL_PROT_WRITE | PAL_PROT_EXEC) & cur_prot;
    /* With EDMM an EPC page is allocated with RW permission and then the desired permission is
     * is set. Restrict permission from RW -> W is architecturally not permitted and the driver will
     * returns -EINVAL error. So adding READ permission if the page permission is only WRITE. */
    if (req_prot == PAL_PROT_WRITE) {
        req_prot = PAL_PROT_READ | PAL_PROT_WRITE;
    }

    if ((req_prot & cur_prot) != cur_prot) {
        ret = restrict_enclave_page_permission(addr, size, req_prot & cur_prot);
        if (ret < 0)
            return unix_to_pal_error(ret);
    }

    if (req_prot & ~cur_prot) {
        pal_prot_flags_t missing_prot = req_prot & ~cur_prot;
        req_prot = (req_prot & cur_prot) | missing_prot;
        ret = relax_enclave_page_permission(addr, size, req_prot);
        if (ret < 0)
            return unix_to_pal_error(ret);
    }

    spinlock_unlock(&g_edmm_heap_prot_lock);
    return ret;
}
