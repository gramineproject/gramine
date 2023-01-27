#include <asm/errno.h>

#include "hex.h"
#include "host_sgx_driver.h"
#include "host_internal.h"
#include "linux_utils.h"
#include "pal_sgx.h"
#include "sgx_arch.h"

static int g_isgx_device = -1;

static void*  g_zero_pages      = NULL;
static size_t g_zero_pages_size = 0;

int open_sgx_driver(void) {
    const char* paths_to_try[] = {
#ifdef CONFIG_SGX_DRIVER_DEVICE
    /* Always try to use the device path specified in the build config first. */
    CONFIG_SGX_DRIVER_DEVICE,
#endif
#if defined(CONFIG_SGX_DRIVER_OOT)
    "/dev/isgx",
#elif defined(CONFIG_SGX_DRIVER_UPSTREAM)
    /* DCAP and upstreamed version used different paths in the past. */
    "/dev/sgx_enclave",
    "/dev/sgx/enclave",
#else
    #error This config should be unreachable.
#endif
    };
    int ret;
    for (size_t i = 0; i < ARRAY_SIZE(paths_to_try); i++) {
        ret = DO_SYSCALL(open, paths_to_try[i], O_RDWR | O_CLOEXEC, 0);
        if (ret == -EACCES) {
            log_error("Cannot open %s (permission denied). This may happen because the current "
                      "user has insufficient permissions to this device.", paths_to_try[i]);
            return ret;
        }
        if (ret >= 0) {
            g_isgx_device = ret;
            return 0;
        }
    }
    log_error("Cannot open SGX driver device. Please make sure you're using an up-to-date kernel "
              "or the standalone Intel SGX kernel module is loaded.");
    return ret;
}

int read_enclave_token(int token_file, sgx_arch_token_t* out_token) {
    struct stat stat;
    int ret;
    ret = DO_SYSCALL(fstat, token_file, &stat);
    if (ret < 0)
        return ret;

    if (stat.st_size != sizeof(sgx_arch_token_t)) {
        log_error("Token size does not match.");
        return -EINVAL;
    }

    int bytes = DO_SYSCALL(read, token_file, out_token, sizeof(sgx_arch_token_t));
    if (bytes < 0) {
        return bytes;
    } else if (bytes != sizeof(sgx_arch_token_t)) {
        log_error("Short read while reading token file.");
        return -EINVAL;
    }

    char hex[64 * 2 + 1]; /* large enough to hold any of the below fields */
#define BYTES2HEX(bytes) (bytes2hex(bytes, sizeof(bytes), hex, sizeof(hex)))
    log_debug("Read token:");
    log_debug("    valid:                 0x%08x",   out_token->body.valid);
    log_debug("    attr.flags:            0x%016lx", out_token->body.attributes.flags);
    log_debug("    attr.xfrm:             0x%016lx", out_token->body.attributes.xfrm);
    log_debug("    mr_enclave:            %s",       BYTES2HEX(out_token->body.mr_enclave.m));
    log_debug("    mr_signer:             %s",       BYTES2HEX(out_token->body.mr_signer.m));
    log_debug("    LE cpu_svn:            %s",       BYTES2HEX(out_token->cpu_svn_le.svn));
    log_debug("    LE isv_prod_id:        %02x",     out_token->isv_prod_id_le);
    log_debug("    LE isv_svn:            %02x",     out_token->isv_svn_le);
    log_debug("    LE masked_misc_select: 0x%08x",   out_token->masked_misc_select_le);
    log_debug("    LE attr.flags:         0x%016lx", out_token->attributes_le.flags);
    log_debug("    LE attr.xfrm:          0x%016lx", out_token->attributes_le.xfrm);
#undef BYTES2HEX

    return 0;
}

static int get_optional_sgx_features(uint64_t xfrm, uint64_t xfrm_mask, uint64_t* out_xfrm) {
    /* see also sgx_get_token.py:get_optional_sgx_features(), used for legacy non-FLC machines */
    const struct {
        uint64_t bits;
        const struct {
            uint32_t leaf;
            uint32_t subleaf;
            uint32_t reg;
            uint32_t bit;
        } cpuid;
    } xfrm_flags[] = {
        /* for mapping of CPUID leaves to CPU features, see libos/src/arch/x86_64/libos_cpuid.c */
        {SGX_XFRM_AVX,    { .leaf = FEATURE_FLAGS_LEAF,          .subleaf = 0, .reg = CPUID_WORD_ECX, .bit = 28 }},
        {SGX_XFRM_MPX,    { .leaf = EXTENDED_FEATURE_FLAGS_LEAF, .subleaf = 0, .reg = CPUID_WORD_EBX, .bit = 14 }},
        {SGX_XFRM_AVX512, { .leaf = EXTENDED_FEATURE_FLAGS_LEAF, .subleaf = 0, .reg = CPUID_WORD_EBX, .bit = 16 }},
        {SGX_XFRM_PKRU,   { .leaf = EXTENDED_FEATURE_FLAGS_LEAF, .subleaf = 0, .reg = CPUID_WORD_ECX, .bit = 3 }},
        {SGX_XFRM_AMX,    { .leaf = EXTENDED_FEATURE_FLAGS_LEAF, .subleaf = 0, .reg = CPUID_WORD_EDX, .bit = 24 }},
    };

    *out_xfrm = xfrm;
    for (size_t i = 0; i < ARRAY_SIZE(xfrm_flags); i++) {
        /* check if SIGSTRUCT.ATTRIBUTEMASK.XFRM doesn't care whether an optional CPU feature is
         * enabled or not (XFRM mask should completely unset these bits) */
        if ((xfrm_flags[i].bits & xfrm_mask) == 0) {
            /* set CPU feature if current system supports it (for performance) */
            uint32_t values[4];
            cpuid(xfrm_flags[i].cpuid.leaf, xfrm_flags[i].cpuid.subleaf, values);
            if (values[xfrm_flags[i].cpuid.reg] & (1u << xfrm_flags[i].cpuid.bit))
                *out_xfrm |= xfrm_flags[i].bits;
        }
    }

    return 0;
}

int create_dummy_enclave_token(sgx_sigstruct_t* sig, sgx_arch_token_t* out_token) {
    memset(out_token, 0, sizeof(*out_token));
    memcpy(&out_token->body.attributes, &sig->attributes, sizeof(sgx_attributes_t));
    out_token->masked_misc_select_le = sig->misc_select;

    return get_optional_sgx_features(sig->attributes.xfrm, sig->attribute_mask.xfrm,
                                     &out_token->body.attributes.xfrm);
}

int read_enclave_sigstruct(int sigfile, sgx_sigstruct_t* sig) {
    struct stat stat;
    int ret;
    ret = DO_SYSCALL(fstat, sigfile, &stat);
    if (ret < 0)
        return ret;

    if ((size_t)stat.st_size != sizeof(sgx_sigstruct_t)) {
        log_error("size of sigstruct size does not match");
        return -EINVAL;
    }

    ret = read_all(sigfile, sig, sizeof(sgx_sigstruct_t));
    if (ret < 0)
        return ret;

    return 0;
}

bool is_wrfsbase_supported(void) {
    uint32_t cpuinfo[4];
    cpuid(EXTENDED_FEATURE_FLAGS_LEAF, 0, cpuinfo);

    if (!(cpuinfo[1] & 0x1)) {
        log_error(
            "{RD,WR}{FS,GS}BASE instructions are not permitted on this platform. Please check the "
            "instructions under \"Building with SGX support\" from Gramine documentation.");
        return false;
    }

    return true;
}

int create_enclave(sgx_arch_secs_t* secs, sgx_arch_token_t* token) {
    assert(secs->size && IS_POWER_OF_2(secs->size));
    assert(IS_ALIGNED(secs->base, secs->size));

    secs->ssa_frame_size = SSA_FRAME_SIZE / g_page_size; /* SECS expects SSA frame size in pages */
    secs->misc_select    = token->masked_misc_select_le;
    memcpy(&secs->attributes, &token->body.attributes, sizeof(sgx_attributes_t));

    /* Do not initialize secs->mr_signer and secs->mr_enclave here as they are
     * not used by ECREATE to populate the internal SECS. SECS's mr_enclave is
     * computed dynamically and SECS's mr_signer is populated based on the
     * SIGSTRUCT during EINIT (see pp21 for ECREATE and pp34 for
     * EINIT in https://software.intel.com/sites/default/files/managed/48/88/329298-002.pdf). */

    uint64_t request_mmap_addr = secs->base;
    uint64_t request_mmap_size = secs->size;

#ifndef CONFIG_SGX_DRIVER_OOT
    /* newer DCAP/in-kernel SGX drivers allow starting enclave address space with non-zero;
     * the below trick to start from MMAP_MIN_ADDR is to avoid vm.mmap_min_addr==0 issue */
    if (request_mmap_addr < MMAP_MIN_ADDR) {
        request_mmap_size -= MMAP_MIN_ADDR - request_mmap_addr;
        request_mmap_addr  = MMAP_MIN_ADDR;
    }
#endif

    uint64_t addr = DO_SYSCALL(mmap, request_mmap_addr, request_mmap_size,
                               PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED | MAP_SHARED,
                               g_isgx_device, 0);
    if (IS_PTR_ERR(addr) && PTR_TO_ERR(addr) == -EACCES) {
        /* OOT DCAP driver (e.g. v1.33.2 found on MS Azure VMs with Ubuntu 18.04) requires
         * different mmap flags */
        /* TODO: remove this fallback after we drop Ubuntu 18.04 */
        addr = DO_SYSCALL(mmap, request_mmap_addr, request_mmap_size,
                          PROT_NONE, MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }

    if (IS_PTR_ERR(addr)) {
        int ret = PTR_TO_ERR(addr);
        if (ret == -EPERM) {
            log_error("Permission denied on mapping enclave. "
                      "You may need to set sysctl vm.mmap_min_addr to zero");
        }

        log_error("Allocation of EPC memory failed: %s", unix_strerror(ret));
        return ret;
    }

    assert(addr == request_mmap_addr);

    struct sgx_enclave_create param = {
        .src = (uint64_t)secs,
    };
    int ret = DO_SYSCALL(ioctl, g_isgx_device, SGX_IOC_ENCLAVE_CREATE, &param);

    if (ret < 0) {
        log_error("Enclave creation IOCTL failed: %s", unix_strerror(ret));
        return ret;
    }

    if (ret) {
        log_error("Enclave creation IOCTL failed: %s", unix_strerror(ret));
        return -EPERM;
    }

    secs->attributes.flags |= SGX_FLAGS_INITIALIZED;

    log_debug("Enclave created:");
    log_debug("    base:           0x%016lx", secs->base);
    log_debug("    size:           0x%016lx", secs->size);
    log_debug("    misc_select:    0x%08x",   secs->misc_select);
    log_debug("    attr.flags:     0x%016lx", secs->attributes.flags);
    log_debug("    attr.xfrm:      0x%016lx", secs->attributes.xfrm);
    log_debug("    ssa_frame_size: %d",       secs->ssa_frame_size);
    log_debug("    isv_prod_id:    0x%08x",   secs->isv_prod_id);
    log_debug("    isv_svn:        0x%08x",   secs->isv_svn);

    /* Linux v5.16 introduced support for Intel AMX feature. Any process must opt-in for AMX
     * by issuing an AMX-permission request. More technically, together with AMX, Intel introduced
     * Extended Feature Disable (XFD) which allows Linux to disable certain features from the
     * XSAVE feature set for a particular process. By default, XFD[AMX_TILEDATA] = 1, thus Gramine
     * process has AMX suppressed on startup. This would lead to an unhandled #NM exception on any
     * SGX enclave entry instruction, resulting in fatal SIGILL in Gramine. For more details, see:
     *
     *   - https://elixir.bootlin.com/linux/v5.16/source/arch/x86/kernel/fpu/xstate.c#L934
     *   - https://elixir.bootlin.com/linux/v5.16/source/arch/x86/kernel/traps.c#L1165
     *   - Chapter 3.2.6 in Intel SDM
     *
     * We call arch_prctl() to request AMX permission if the SGX enclave allows/requests it
     * (we examine enclave's SECS.ATTRIBUTES.XFRM). It's enough to do it once: child processes
     * will inherit the permission, but here for simplicity we call it in every child process as
     * well. Some deployment environments run Linux systems earlier than v5.16 but with
     * an AMX-specific patch; this patch doesn't introduce `arch_prctl(ARCH_REQ_XCOMP_PERM)`
     * syscall so an attempt to call it may return EINVAL, EOPNOTSUPP or ENOSYS. In this case,
     * we simply ignore the result of this syscall. */
    if (secs->attributes.xfrm & (1 << AMX_TILEDATA)) {
        ret = DO_SYSCALL(arch_prctl, ARCH_REQ_XCOMP_PERM, AMX_TILEDATA);
        if (ret < 0 && ret != -EINVAL && ret != -EOPNOTSUPP && ret != -ENOSYS) {
            log_error("Requesting AMX permission failed: %s", unix_strerror(ret));
            return ret;
        }
    }

    return 0;
}

int add_pages_to_enclave(sgx_arch_secs_t* secs, void* addr, void* user_addr, unsigned long size,
                         enum sgx_page_type type, int prot, bool skip_eextend,
                         const char* comment) {
    __UNUSED(secs); /* Used only under DCAP ifdefs */
    int ret;

    if (!g_zero_pages) {
        /* initialize with just one page */
        g_zero_pages = (void*)DO_SYSCALL(mmap, NULL, g_page_size, PROT_READ,
                                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (IS_PTR_ERR(g_zero_pages)) {
            ret = PTR_TO_ERR(g_zero_pages);
            log_error("Cannot mmap zero pages: %s", unix_strerror(ret));
            return ret;
        }
        g_zero_pages_size = g_page_size;
    }

    sgx_arch_sec_info_t secinfo = { 0 };
    switch (type) {
        case SGX_PAGE_TYPE_SECS:
            return -EPERM;
        case SGX_PAGE_TYPE_TCS:
            secinfo.flags = SGX_PAGE_TYPE_TCS << SGX_SECINFO_FLAGS_TYPE_SHIFT;
            break;
        case SGX_PAGE_TYPE_REG:
            secinfo.flags = SGX_PAGE_TYPE_REG << SGX_SECINFO_FLAGS_TYPE_SHIFT
                            | PAL_TO_SGX_PROT(prot);
            break;
        default:
            return -EINVAL;
    }

    char p[4] = "---";
    const char* t = (type == SGX_PAGE_TYPE_TCS) ? "TCS" : "REG";
    const char* m = skip_eextend ? "" : " measured";

    if (type == SGX_PAGE_TYPE_REG) {
        if (prot & PROT_READ)
            p[0] = 'R';
        if (prot & PROT_WRITE)
            p[1] = 'W';
        if (prot & PROT_EXEC)
            p[2] = 'X';
    }

    if (size == g_page_size)
        log_debug("Adding page  to enclave: %p [%s:%s] (%s)%s", addr, t, p, comment, m);
    else
        log_debug("Adding pages to enclave: %p-%p [%s:%s] (%s)%s", addr, addr + size, t, p,
                  comment, m);

#ifdef CONFIG_SGX_DRIVER_OOT
    /* legacy out-of-tree driver only supports adding one page at a time */
    struct sgx_enclave_add_page param = {
        .addr    = (uint64_t)addr,
        .src     = (uint64_t)(user_addr ?: g_zero_pages),
        .secinfo = (uint64_t)&secinfo,
        .mrmask  = skip_eextend ? 0 : (uint16_t)-1,
    };

    uint64_t added_size = 0;
    while (added_size < size) {
        ret = DO_SYSCALL(ioctl, g_isgx_device, SGX_IOC_ENCLAVE_ADD_PAGE, &param);
        if (ret < 0) {
            if (ret == -EINTR)
                continue;
            log_error("Enclave add-pages IOCTL failed: %s", unix_strerror(ret));
            return ret;
        }

        param.addr += g_page_size;
        if (param.src != (uint64_t)g_zero_pages)
            param.src += g_page_size;
        added_size += g_page_size;
    }

    /* need to change permissions for EADDed pages since the initial mmap was with PROT_NONE */
    ret = DO_SYSCALL(mprotect, addr, size, prot);
    if (ret < 0) {
        log_error("Changing protections of EADDed pages failed: %s", unix_strerror(ret));
        return ret;
    }
#else
    if (!user_addr && g_zero_pages_size < size) {
        /* not enough contigious zero pages to back up enclave pages, allocate more */
        /* TODO: this logic can be removed if we introduce a size cap in ENCLAVE_ADD_PAGES ioctl */
        ret = DO_SYSCALL(munmap, g_zero_pages, g_zero_pages_size);
        if (ret < 0) {
            log_error("Cannot unmap zero pages: %s", unix_strerror(ret));
            return ret;
        }

        g_zero_pages = (void*)DO_SYSCALL(mmap, NULL, size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS,
                                         -1, 0);
        if (IS_PTR_ERR(g_zero_pages)) {
            ret = PTR_TO_ERR(g_zero_pages);
            log_error("Cannot map zero pages: %s", unix_strerror(ret));
            return ret;
        }
        g_zero_pages_size = size;
    }

    struct sgx_enclave_add_pages param = {
        .offset  = (uint64_t)addr - secs->base,
        .src     = (uint64_t)(user_addr ?: g_zero_pages),
        .length  = size,
        .secinfo = (uint64_t)&secinfo,
        .flags   = skip_eextend ? 0 : SGX_PAGE_MEASURE,
        .count   = 0, /* output parameter, will be checked after IOCTL */
    };
    /* DCAP and in-kernel drivers require aligned data */
    assert(IS_ALIGNED_POW2(param.src, g_page_size));
    assert(IS_ALIGNED_POW2(param.offset, g_page_size));

    /* NOTE: SGX driver v39 removes `count` field and returns "number of bytes added" as return
     * value directly in `ret`. It also caps the maximum number of bytes to be added as 1MB, or 256
     * enclave pages. Thus, the below code must loop on the ADD_PAGES ioctl until all pages are
     * added; the code must first check `ret > 0` and only then check `count` field to support all
     * versions of the SGX driver. Note that even though `count` is removed in v39, it is the last
     * field of struct and thus may stay redundant (and unused by driver v39). We hope that this
     * contrived logic won't be needed when the SGX driver stabilizes its ioctl interface.
     * (https://git.kernel.org/pub/scm/linux/kernel/git/jarkko/linux-sgx.git/tag/?h=v39) */
    while (param.length > 0) {
        ret = DO_SYSCALL(ioctl, g_isgx_device, SGX_IOC_ENCLAVE_ADD_PAGES, &param);
        if (ret < 0) {
            if (ret == -EINTR)
                continue;
            log_error("Enclave add-pages IOCTL failed: %s", unix_strerror(ret));
            return ret;
        }

        uint64_t added_size = ret > 0 ? (uint64_t)ret : param.count;
        if (!added_size) {
            log_error("Intel SGX driver did not perform EADD. This may indicate a buggy "
                      "driver, please update to the most recent version.");
            return -EPERM;
        }

        param.offset += added_size;
        if (param.src != (uint64_t)g_zero_pages)
            param.src += added_size;
        param.length -= added_size;
    }

    /* ask Intel SGX driver to actually mmap the added enclave pages */
    uint64_t mapped = DO_SYSCALL(mmap, addr, size, prot, MAP_FIXED | MAP_SHARED, g_isgx_device, 0);
    if (IS_PTR_ERR(mapped)) {
        ret = PTR_TO_ERR(mapped);
        log_error("Cannot map enclave pages: %s", unix_strerror(ret));
        return ret;
    }
#endif /* CONFIG_SGX_DRIVER_OOT */

    return 0;
}

int edmm_restrict_pages_perm(uint64_t addr, size_t count, uint64_t prot) {
    assert(addr >= g_pal_enclave.baseaddr);

    size_t i = 0;
    while (i < count) {
        struct sgx_enclave_restrict_permissions params = {
            .offset = addr + i * PAGE_SIZE - g_pal_enclave.baseaddr,
            .length = (count - i) * PAGE_SIZE,
            .permissions = prot,
        };
        int ret = DO_SYSCALL(ioctl, g_isgx_device, SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS, &params);
        assert(params.count % PAGE_SIZE == 0);
        i += params.count / PAGE_SIZE;
        if (ret < 0) {
            if (ret == -EBUSY || ret == -EAGAIN || ret == -EINTR) {
                continue;
            }
            log_error("SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS failed (%llu) %s",
                      (unsigned long long)params.result, unix_strerror(ret));
            return ret;
        }
    }

    return 0;
}

int edmm_modify_pages_type(uint64_t addr, size_t count, uint64_t type) {
    assert(addr >= g_pal_enclave.baseaddr);

    size_t i = 0;
    while (i < count) {
        struct sgx_enclave_modify_types params = {
            .offset = addr + i * PAGE_SIZE - g_pal_enclave.baseaddr,
            .length = (count - i) * PAGE_SIZE,
            .page_type = type,
        };
        int ret = DO_SYSCALL(ioctl, g_isgx_device, SGX_IOC_ENCLAVE_MODIFY_TYPES, &params);
        assert(params.count % PAGE_SIZE == 0);
        i += params.count / PAGE_SIZE;
        if (ret < 0) {
            if (ret == -EBUSY || ret == -EAGAIN || ret == -EINTR) {
                continue;
            }
            log_error("SGX_IOC_ENCLAVE_MODIFY_TYPES failed: (%llu) %s",
                      (unsigned long long)params.result, unix_strerror(ret));
            return ret;
        }
    }

    return 0;
}

int edmm_remove_pages(uint64_t addr, size_t count) {
    assert(addr >= g_pal_enclave.baseaddr);

    size_t i = 0;
    while (i < count) {
        struct sgx_enclave_remove_pages params = {
            .offset = addr + i * PAGE_SIZE - g_pal_enclave.baseaddr,
            .length = (count - i) * PAGE_SIZE,
        };
        int ret = DO_SYSCALL(ioctl, g_isgx_device, SGX_IOC_ENCLAVE_REMOVE_PAGES, &params);
        assert(params.count % PAGE_SIZE == 0);
        i += params.count / PAGE_SIZE;
        if (ret < 0) {
            if (ret == -EBUSY || ret == -EAGAIN || ret == -EINTR) {
                continue;
            }
            return ret;
        }
    }

    return 0;
}

/* must be called after open_sgx_driver() */
int edmm_supported_by_driver(bool* out_supported) {
    struct sgx_enclave_remove_pages params = { .offset = 0, .length = 0 }; /* dummy */
    int ret = DO_SYSCALL(ioctl, g_isgx_device, SGX_IOC_ENCLAVE_REMOVE_PAGES, &params);
    if (ret != -EINVAL && ret != -ENOTTY) {
        /* we expect either -EINVAL (REMOVE_PAGES ioctl exists but fails due to params.length == 0)
         * or -ENOTTY (REMOVE_PAGES ioctl doesn't exist) */
        return ret >= 0 ? -EPERM : ret;
    }
    *out_supported = ret == -EINVAL;
    return 0;
}

int init_enclave(sgx_arch_secs_t* secs, sgx_sigstruct_t* sigstruct, sgx_arch_token_t* token) {
#ifndef CONFIG_SGX_DRIVER_OOT
    __UNUSED(token);
#endif
    unsigned long enclave_valid_addr = secs->base + secs->size - g_page_size;

    char hex[sizeof(sigstruct->enclave_hash.m) * 2 + 1];
    log_debug("Enclave initializing:");
    log_debug("    enclave id:   0x%016lx", enclave_valid_addr);
    log_debug("    mr_enclave:   %s", bytes2hex(sigstruct->enclave_hash.m,
                                                sizeof(sigstruct->enclave_hash.m),
                                                hex, sizeof(hex)));

    struct sgx_enclave_init param = {
#ifdef CONFIG_SGX_DRIVER_OOT
        .addr = enclave_valid_addr,
#endif
        .sigstruct = (uint64_t)sigstruct,
#ifdef CONFIG_SGX_DRIVER_OOT
        .einittoken = (uint64_t)token,
#endif
    };
    int ret = DO_SYSCALL(ioctl, g_isgx_device, SGX_IOC_ENCLAVE_INIT, &param);

    if (ret < 0) {
        return ret;
    }

    if (ret) {
        const char* error;
        switch (ret) {
            case SGX_INVALID_SIG_STRUCT:
                error = "Invalid SIGSTRUCT";
                break;
            case SGX_INVALID_ATTRIBUTE:
                error = "Invalid enclave attribute";
                break;
            case SGX_INVALID_MEASUREMENT:
                error = "Invalid measurement";
                break;
            case SGX_INVALID_SIGNATURE:
                error = "Invalid signature";
                break;
            case SGX_INVALID_EINITTOKEN:
                error = "Invalid EINIT token";
                break;
            case SGX_INVALID_CPUSVN:
                error = "Invalid CPU SVN";
                break;
            default:
                error = "Unknown reason";
                break;
        }
        log_error("enclave EINIT failed - %s", error);
        return -EPERM;
    }

    /* all enclave pages were EADDed, don't need zero pages anymore */
    ret = DO_SYSCALL(munmap, g_zero_pages, g_zero_pages_size);
    if (ret < 0) {
        log_error("Cannot unmap zero pages: %s", unix_strerror(ret));
        return ret;
    }

    return 0;
}
