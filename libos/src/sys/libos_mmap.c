/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Invisible Things Lab
 * Copyright (C) 2020 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

/*
 * Implementation of system calls "mmap", "munmap" and "mprotect".
 */

#include "libos_flags_conv.h"
#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_table.h"
#include "libos_vma.h"
#include "linux_abi/errors.h"
#include "linux_abi/memory.h"
#include "pal.h"
#include "pal_error.h"

#ifdef MAP_32BIT /* x86_64-specific */
#define MAP_32BIT_IF_SUPPORTED MAP_32BIT
#else
#define MAP_32BIT_IF_SUPPORTED 0
#endif

#define LEGACY_MAP_MASK (MAP_SHARED             \
                       | MAP_PRIVATE            \
                       | MAP_FIXED              \
                       | MAP_ANONYMOUS          \
                       | MAP_DENYWRITE          \
                       | MAP_EXECUTABLE         \
                       | MAP_UNINITIALIZED      \
                       | MAP_GROWSDOWN          \
                       | MAP_LOCKED             \
                       | MAP_NORESERVE          \
                       | MAP_POPULATE           \
                       | MAP_NONBLOCK           \
                       | MAP_STACK              \
                       | MAP_HUGETLB            \
                       | MAP_32BIT_IF_SUPPORTED \
                       | MAP_HUGE_2MB           \
                       | MAP_HUGE_1GB)

static int check_prot(int prot) {
    if (prot & ~(PROT_NONE | PROT_READ | PROT_WRITE | PROT_EXEC | PROT_GROWSDOWN | PROT_GROWSUP |
                 PROT_SEM)) {
        return -EINVAL;
    }

    if ((prot & (PROT_GROWSDOWN | PROT_GROWSUP)) == (PROT_GROWSDOWN | PROT_GROWSUP)) {
        return -EINVAL;
    }

    /* We do not support these flags (at least yet). */
    if (prot & (PROT_GROWSUP | PROT_SEM)) {
        return -EOPNOTSUPP;
    }

    return 0;
}

long libos_syscall_mmap(unsigned long addr, unsigned long length, unsigned long prot,
                        unsigned long flags, unsigned long fd, unsigned long offset) {
    struct libos_handle* hdl = NULL;
    long ret = 0;

    ret = check_prot(prot);
    if (ret < 0)
        return ret;

    if (!(flags & MAP_FIXED) && addr)
        addr = ALLOC_ALIGN_DOWN_PTR(addr);

    /*
     * According to the manpage, both addr and offset have to be page-aligned,
     * but not the length. mmap() will automatically round up the length.
     */
    if (addr && !IS_ALLOC_ALIGNED_PTR(addr))
        return -EINVAL;

    if (!IS_ALLOC_ALIGNED(offset))
        return -EINVAL;

    if (!IS_ALLOC_ALIGNED(length))
        length = ALLOC_ALIGN_UP(length);

    if (!length || !access_ok((void*)addr, length))
        return -EINVAL;

    /* This check is Gramine specific. */
    if (flags & (VMA_UNMAPPED | VMA_TAINTED | VMA_INTERNAL)) {
        return -EINVAL;
    }

    if (flags & MAP_ANONYMOUS) {
        switch (flags & MAP_TYPE) {
            case MAP_SHARED:
            case MAP_PRIVATE:
                break;
            default:
                return -EINVAL;
        }
    } else {
        /* MAP_FILE is the opposite of MAP_ANONYMOUS and is implicit */
        switch (flags & MAP_TYPE) {
            case MAP_SHARED:
                flags &= LEGACY_MAP_MASK;
                /* fall through */
            case MAP_SHARED_VALIDATE:
                /* Currently we do not support additional flags like MAP_SYNC */
                if (flags & ~LEGACY_MAP_MASK) {
                    return -EOPNOTSUPP;
                }
                /* fall through */
            case MAP_PRIVATE:
                hdl = get_fd_handle(fd, NULL, NULL);
                if (!hdl) {
                    return -EBADF;
                }

                if (!hdl->fs || !hdl->fs->fs_ops || !hdl->fs->fs_ops->mmap) {
                    ret = -ENODEV;
                    goto out_handle;
                }

                if (hdl->flags & O_WRONLY) {
                    ret = -EACCES;
                    goto out_handle;
                }

                if ((flags & MAP_SHARED) && (prot & PROT_WRITE) && !(hdl->flags & O_RDWR)) {
                    ret = -EACCES;
                    goto out_handle;
                }

                break;
            default:
                return -EINVAL;
        }

        /* ignore MAP_NORESERVE for file-backed mappings as we consider this rare and not worth
         * optimizing */
        flags &= ~MAP_NORESERVE;
    }

#ifdef MAP_32BIT
    /* ignore MAP_32BIT when MAP_FIXED is set */
    if ((flags & (MAP_32BIT | MAP_FIXED)) == (MAP_32BIT | MAP_FIXED))
        flags &= ~MAP_32BIT;
#endif

    void* memory_range_start = NULL;
    void* memory_range_end   = NULL;

    /* Shared mappings of files of "untrusted_shm" type use a different memory range.
     * See "libos/src/fs/shm/fs.c" for more details. */
    if ((flags & MAP_SHARED) && hdl && hdl->fs && !strcmp(hdl->fs->name, "untrusted_shm")) {
        memory_range_start = g_pal_public_state->shared_address_start;
        memory_range_end = g_pal_public_state->shared_address_end;
    } else {
        memory_range_start = g_pal_public_state->memory_address_start;
        memory_range_end = g_pal_public_state->memory_address_end;
    }
    if (flags & (MAP_FIXED | MAP_FIXED_NOREPLACE)) {
        /* We know that `addr + length` does not overflow (`access_ok` above). */
        if (addr < (uintptr_t)memory_range_start || (uintptr_t)memory_range_end < addr + length) {
            ret = -EINVAL;
            goto out_handle;
        }
        if (!(flags & MAP_FIXED_NOREPLACE)) {
            /* Flush any file mappings we're about to replace */
            ret = msync_range(addr, addr + length);
            if (ret < 0) {
                goto out_handle;
            }

            struct libos_vma_info* vmas;
            size_t vmas_length;
            ret = dump_vmas_in_range(addr, addr + length,
                                     /*include_unmapped=*/false, &vmas, &vmas_length);
            if (ret < 0) {
                goto out_handle;
            }

            void* tmp_vma = NULL;
            ret = bkeep_munmap((void*)addr, length, /*is_internal=*/false, &tmp_vma);
            if (ret < 0) {
                free_vma_info_array(vmas, vmas_length);
                goto out_handle;
            }

            for (struct libos_vma_info* vma = vmas; vma < vmas + vmas_length; vma++) {
                uintptr_t begin = MAX((uintptr_t)addr, (uintptr_t)vma->addr);
                uintptr_t end = MIN((uintptr_t)vma->addr + vma->length, (uintptr_t)addr + length);
                /* `vma` contains at least one byte from `[addr; addr + length)` range, so: */
                assert(begin < end);

                if (PalVirtualMemoryFree((void*)begin, end - begin) < 0) {
                    BUG();
                }
            }

            free_vma_info_array(vmas, vmas_length);

            bkeep_convert_tmp_vma_to_user(tmp_vma);

            ret = bkeep_mmap_fixed((void*)addr, length, prot, flags, hdl, offset, NULL);
            if (ret < 0) {
                BUG();
            }
        } else {
            ret = bkeep_mmap_fixed((void*)addr, length, prot, flags, hdl, offset, NULL);
            if (ret < 0) {
                goto out_handle;
            }
        }
    } else {
        /* We know that `addr + length` does not overflow (`access_ok` above). */
        if (addr && (uintptr_t)memory_range_start <= (uintptr_t)addr
                && (uintptr_t)addr + length <= (uintptr_t)memory_range_end) {
            ret = bkeep_mmap_any_in_range(memory_range_start, (void*)addr + length, length, prot,
                                          flags, hdl, offset, NULL, (void**)&addr);
        } else {
            /* Hacky way to mark we had no hit and need to search below. */
            ret = -1;
        }
        if (ret < 0) {
            /* We either had no hinted address or could not allocate memory at it. */
            if (memory_range_start == g_pal_public_state->memory_address_start) {
                ret = bkeep_mmap_any_aslr(length, prot, flags, hdl, offset, NULL, (void**)&addr);
            } else {
                /* Shared memory range does not have ASLR. */
                ret = bkeep_mmap_any_in_range(memory_range_start, memory_range_end, length, prot,
                                              flags, hdl, offset, NULL, (void**)&addr);
            }
        }
        if (ret < 0) {
            ret = -ENOMEM;
            goto out_handle;
        }
    }

    /* From now on `addr` contains the actual address we want to map (and already bookkeeped). */

    if (!hdl) {
        ret = PalVirtualMemoryAlloc((void*)addr, length, LINUX_PROT_TO_PAL(prot, flags));
        if (ret < 0) {
            if (ret == PAL_ERROR_DENIED) {
                ret = -EPERM;
            } else {
                ret = pal_to_unix_errno(ret);
            }
        }
    } else {
        size_t valid_length;
        ret = hdl->fs->fs_ops->mmap(hdl, (void*)addr, length, prot, flags, offset, &valid_length);
        if (ret == 0) {
            int update_valid_length_ret = bkeep_vma_update_valid_length((void*)addr, valid_length);
            if (update_valid_length_ret < 0) {
                log_error("[mmap] Failed to update valid length to %lu of bookkeeped memory at "
                          "%#lx-%#lx!", valid_length, addr, addr + length);
                BUG();
            }
        }
    }

    if (ret < 0) {
        void* tmp_vma = NULL;
        if (bkeep_munmap((void*)addr, length, /*is_internal=*/false, &tmp_vma) < 0) {
            log_error("[mmap] Failed to remove bookkeeped memory that was not allocated at "
                      "%#lx-%#lx!", addr, addr + length);
            BUG();
        }
        bkeep_remove_tmp_vma(tmp_vma);
    }

out_handle:
    if (hdl) {
        put_handle(hdl);
    }

    if (ret < 0) {
        return ret;
    }
    return addr;
}

long libos_syscall_mprotect(void* addr, size_t length, int prot) {
    int ret = check_prot(prot);
    if (ret < 0)
        return ret;

    /*
     * According to the manpage, addr has to be page-aligned, but not the
     * length. mprotect() will automatically round up the length.
     */
    if (!addr || !IS_ALLOC_ALIGNED_PTR(addr))
        return -EINVAL;

    if (length == 0) {
        return 0;
    }

    if (!IS_ALLOC_ALIGNED(length))
        length = ALLOC_ALIGN_UP(length);

    if (!access_ok(addr, length)) {
        return -EINVAL;
    }

    /* `bkeep_mprotect` and then `PalVirtualMemoryProtect` is racy, but it's hard to do it properly.
     * On the other hand if this race happens, it means user app is buggy, so not a huge problem. */

    ret = bkeep_mprotect(addr, length, prot, /*is_internal=*/false);
    if (ret < 0) {
        return ret;
    }

    if (prot & PROT_GROWSDOWN) {
        struct libos_vma_info vma_info = {0};
        if (lookup_vma(addr, &vma_info) >= 0) {
            assert(vma_info.addr <= addr);
            length += addr - vma_info.addr;
            addr = vma_info.addr;
            if (vma_info.file) {
                put_handle(vma_info.file);
            }
        } else {
            log_warning("Memory that was about to be mprotected was unmapped, your program is "
                        "buggy!");
            return -ENOTRECOVERABLE;
        }
    }

    ret = PalVirtualMemoryProtect(addr, length, LINUX_PROT_TO_PAL(prot, /*map_flags=*/0));
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    return 0;
}

long libos_syscall_munmap(void* _addr, size_t length) {
    uintptr_t addr = (uintptr_t)_addr;
    /*
     * According to the manpage, addr has to be page-aligned, but not the
     * length. munmap() will automatically round up the length.
     */
    if (!addr || !IS_ALLOC_ALIGNED(addr))
        return -EINVAL;

    if (!length || !access_ok(_addr, length))
        return -EINVAL;

    if (!IS_ALLOC_ALIGNED(length))
        length = ALLOC_ALIGN_UP(length);

    int ret;

    /* Flush any file mappings we're about to remove */
    ret = msync_range(addr, addr + length);
    if (ret < 0) {
        return ret;
    }

    struct libos_vma_info* vmas;
    size_t vmas_length;
    ret = dump_vmas_in_range(addr, addr + length, /*include_unmapped=*/false, &vmas, &vmas_length);
    if (ret < 0) {
        return ret;
    }

    for (struct libos_vma_info* vma = vmas; vma < vmas + vmas_length; vma++) {
        uintptr_t begin = MAX(addr, (uintptr_t)vma->addr);
        uintptr_t end = MIN((uintptr_t)vma->addr + vma->length, addr + length);
        /* `vma` contains at least one byte from `[addr; addr + length)` range, so: */
        assert(begin < end);

        void* tmp_vma = NULL;
        ret = bkeep_munmap((void*)begin, end - begin, /*is_internal=*/false, &tmp_vma);
        if (ret < 0) {
            BUG();
        }

        if (PalVirtualMemoryFree((void*)begin, end - begin) < 0) {
            BUG();
        }

        bkeep_remove_tmp_vma(tmp_vma);
    }

    free_vma_info_array(vmas, vmas_length);
    return 0;
}

/* This emulation of mincore() always pessimistically tells that pages are _NOT_ in RAM due to lack
 * of a good way to know it.
 * This lying may possibly cause performance (or other) issues.
 */
long libos_syscall_mincore(void* addr, size_t len, unsigned char* vec) {
    if (!IS_ALLOC_ALIGNED_PTR(addr))
        return -EINVAL;

    if (!access_ok(addr, len)) {
        return -ENOMEM;
    }

    if (!is_in_adjacent_user_vmas(addr, len, /*prot=*/0)) {
        return -ENOMEM;
    }

    unsigned long pages = ALLOC_ALIGN_UP(len) / ALLOC_ALIGNMENT;
    if (!is_user_memory_writable(vec, pages))
        return -EFAULT;

    if (FIRST_TIME()) {
        log_warning("mincore emulation always tells pages are _NOT_ in RAM. This may cause "
                    "issues.");
    }

    /* There is no good way to know if the page is in RAM.
     * Conservatively tell that it's not in RAM. */
    for (unsigned long i = 0; i < pages; i++) {
        vec[i] = 0;
    }

    return 0;
}

long libos_syscall_mbind(void* start, unsigned long len, int mode, unsigned long* nmask,
                         unsigned long maxnode, int flags) {
    /* dummy implementation, always return success */
    __UNUSED(start);
    __UNUSED(len);
    __UNUSED(mode);
    __UNUSED(nmask);
    __UNUSED(maxnode);
    __UNUSED(flags);
    return 0;
}

static bool madvise_behavior_valid(int behavior) {
    switch (behavior) {
        case MADV_DOFORK:
        case MADV_DONTFORK:
        case MADV_NORMAL:
        case MADV_SEQUENTIAL:
        case MADV_RANDOM:
        case MADV_REMOVE:
        case MADV_WILLNEED:
        case MADV_DONTNEED:
        case MADV_FREE:
        case MADV_MERGEABLE:
        case MADV_UNMERGEABLE:
        case MADV_HUGEPAGE:
        case MADV_NOHUGEPAGE:
        case MADV_DONTDUMP:
        case MADV_DODUMP:
        case MADV_WIPEONFORK:
        case MADV_KEEPONFORK:
        case MADV_SOFT_OFFLINE:
        case MADV_HWPOISON:
            return true;
    }
    return false;
}

long libos_syscall_madvise(unsigned long start, size_t len_in, int behavior) {
    if (!madvise_behavior_valid(behavior))
        return -EINVAL;

    if (!IS_ALIGNED_POW2(start, PAGE_SIZE))
        return -EINVAL;

    size_t len = ALIGN_UP(len_in, PAGE_SIZE);
    if (len < len_in)
        return -EINVAL; // overflow when rounding up

    if (!access_ok((void*)start, len))
        return -EINVAL;

    if (len == 0)
        return 0;

    switch (behavior) {
        case MADV_NORMAL:
        case MADV_RANDOM:
        case MADV_SEQUENTIAL:
        case MADV_WILLNEED:
        case MADV_FREE:
        case MADV_SOFT_OFFLINE:
        case MADV_MERGEABLE:
        case MADV_UNMERGEABLE:
        case MADV_HUGEPAGE:
        case MADV_NOHUGEPAGE:
            return 0; // Doing nothing is semantically correct for these modes.

        case MADV_DONTFORK:
        case MADV_DOFORK:
        case MADV_WIPEONFORK:
        case MADV_KEEPONFORK:
        case MADV_HWPOISON:
        case MADV_DONTDUMP:
        case MADV_DODUMP:
        case MADV_REMOVE:
            return -ENOSYS; // Not implemented

        case MADV_DONTNEED: {
            return madvise_dontneed_range(start, start + len);
        }
    }
    return -EINVAL;
}

long libos_syscall_msync(unsigned long start, size_t len_orig, int flags) {
    if (flags & ~(MS_ASYNC | MS_SYNC | MS_INVALIDATE)) {
        return -EINVAL;
    }

    if ((flags & MS_ASYNC) && (flags & MS_SYNC)) {
        return -EINVAL;
    }

    if (!IS_ALIGNED_POW2(start, PAGE_SIZE)) {
        return -EINVAL;
    }

    size_t len = ALIGN_UP_POW2(len_orig, PAGE_SIZE);
    if (len < len_orig) {
        return -ENOMEM;
    }

    if (!(flags & (MS_SYNC | MS_ASYNC))) {
        /* Currently Linux permits a call without either `MS_SYNC` or `MS_ASYNC`, and treats it as
         * equivalent to specifying `MS_ASYNC`. */
        flags |= MS_ASYNC;
    }

    if (!is_user_memory_readable((void*)start, len)) {
        return -ENOMEM;
    }

    if (flags & MS_INVALIDATE) {
        log_warning("Gramine does not support MS_INVALIDATE");
        return -ENOSYS;
    }

    /* `MS_ASYNC` is emulated as `MS_SYNC`; this sacrifices performance for correctness. */
    return msync_range(start, start + len);
}
