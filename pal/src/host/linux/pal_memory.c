/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This file contains APIs that allocate, free or protect virtual memory.
 */

#include <asm/fcntl.h>
#include <asm/mman.h>

#include "api.h"
#include "linux_utils.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_flags_conv.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"

uintptr_t g_vdso_start = 0;
uintptr_t g_vdso_end = 0;

bool is_in_vdso(uintptr_t addr) {
    return (g_vdso_start || g_vdso_end) && g_vdso_start <= addr && addr < g_vdso_end;
}

int _PalVirtualMemoryAlloc(void* addr, size_t size, pal_prot_flags_t prot) {
    assert(WITHIN_MASK(prot, PAL_PROT_MASK));
    assert(addr);

    int flags = PAL_MEM_FLAGS_TO_LINUX(prot);
    int linux_prot = PAL_PROT_TO_LINUX(prot);

    flags |= MAP_ANONYMOUS | MAP_FIXED;
    addr = (void*)DO_SYSCALL(mmap, addr, size, linux_prot, flags, -1, 0);

    if (IS_PTR_ERR(addr)) {
        return unix_to_pal_error(PTR_TO_ERR(addr));
    }

    return 0;
}

int _PalVirtualMemoryFree(void* addr, size_t size) {
    int ret = DO_SYSCALL(munmap, addr, size);
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

int _PalVirtualMemoryProtect(void* addr, size_t size, pal_prot_flags_t prot) {
    int ret = DO_SYSCALL(mprotect, addr, size, PAL_PROT_TO_LINUX(prot));
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

static int read_proc_meminfo(const char* key, unsigned long* val) {
    int fd = DO_SYSCALL(open, "/proc/meminfo", O_RDONLY | O_CLOEXEC, 0);

    if (fd < 0)
        return -PAL_ERROR_DENIED;

    char buffer[40];
    int ret = 0;
    size_t n;
    size_t r = 0;
    size_t len = strlen(key);

    ret = -PAL_ERROR_DENIED;
    while (1) {
        ret = DO_SYSCALL(read, fd, buffer + r, 40 - r);
        if (ret < 0) {
            ret = -PAL_ERROR_DENIED;
            break;
        }

        for (n = r; n < r + ret; n++)
            if (buffer[n] == '\n')
                break;

        r += ret;
        if (n == r + ret || n <= len) {
            ret = -PAL_ERROR_INVAL;
            break;
        }

        if (!memcmp(key, buffer, len) && buffer[len] == ':') {
            for (size_t i = len + 1; i < n; i++)
                if (buffer[i] != ' ') {
                    *val = atol(buffer + i);
                    break;
                }
            ret = 0;
            break;
        }

        memmove(buffer, buffer + n + 1, r - n - 1);
        r -= n + 1;
    }

    DO_SYSCALL(close, fd);
    return ret;
}

unsigned long _PalMemoryQuota(void) {
    if (g_pal_linux_state.memory_quota == (unsigned long)-1)
        return 0;

    if (g_pal_linux_state.memory_quota)
        return g_pal_linux_state.memory_quota;

    unsigned long quota = 0;
    if (read_proc_meminfo("MemTotal", &quota) < 0) {
        g_pal_linux_state.memory_quota = (unsigned long)-1;
        return 0;
    }

    return (g_pal_linux_state.memory_quota = quota * 1024);
}

struct proc_maps_info {
    uintptr_t vdso_start;
    uintptr_t vdso_end;
    uintptr_t highest_addr;
    uintptr_t stack_top;
};

static int proc_maps_info_callback(struct proc_maps_range* r, void* arg) {
    struct proc_maps_info* proc_maps_info = arg;

    if (r->name) {
        if (!strcmp(r->name, "[vdso]")) {
            proc_maps_info->vdso_start = r->start;
            proc_maps_info->vdso_end = r->end;
        } else if (!strcmp(r->name, "[stack]")) {
            proc_maps_info->stack_top = r->start;
        }
    }

    if (proc_maps_info->highest_addr < r->end) {
        proc_maps_info->highest_addr = r->end;
    }

    return pal_add_initial_range(r->start, r->end - r->start, r->prot, r->name ?: "");
}

int init_memory_bookkeeping(void) {
    struct proc_maps_info proc_maps_info = { 0 };
    int ret = parse_proc_maps("/proc/self/maps", &proc_maps_info_callback, &proc_maps_info);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }

    if (proc_maps_info.stack_top == 0) {
        log_error("failed to find the stack in \"/proc/self/maps\"");
        return -PAL_ERROR_NOMEM;
    }

#ifdef __hppa__
#error "Your arch grows stack towards high addresses, this is not supported."
#endif
    /* Allocate a guard page above the stack. We do not support further stack auto growth. */
    void* ptr = (void*)(proc_maps_info.stack_top - PAGE_SIZE);
    ptr = (void*)DO_SYSCALL(mmap, ptr, PAGE_SIZE, PROT_NONE,
                            MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (IS_PTR_ERR(ptr)) {
        ret = PTR_TO_ERR(ptr);
        log_error("failed to map a stack guard page: %s", unix_strerror(ret));
        return unix_to_pal_error(ret);
    }
    ret = pal_add_initial_range((uintptr_t)ptr, PAGE_SIZE, /*prot=*/0, "stack guard");
    if (ret < 0) {
        return ret;
    }

    uintptr_t start_addr = MMAP_MIN_ADDR;
    uintptr_t end_addr = MIN(proc_maps_info.highest_addr, ARCH_HIGHEST_ADDR);

    /* Verify that the address is mappable. `MMAP_MIN_ADDR` is hardcoded in Gramine and actual min
     * mmap address could be different. */
    while (1) {
        if (start_addr >= end_addr) {
            return -PAL_ERROR_NOMEM;
        }

        ptr = (void*)DO_SYSCALL(mmap, start_addr, PAGE_SIZE, PROT_NONE,
                                MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (!IS_PTR_ERR(ptr)) {
            DO_SYSCALL(munmap, ptr, g_pal_public_state.alloc_align);
            /* Check returned pointer in case of older kernels, which do not support
             * `MAP_FIXED_NOREPLACE`. */
            if (ptr == (void*)start_addr) {
                break;
            }
        } else if (PTR_TO_ERR(ptr) == -EEXIST) {
            break;
        }

        if (start_addr >> (sizeof(start_addr) * 8 - 1)) {
            /* Address would overflow. */
            return -PAL_ERROR_NOMEM;
        }
        start_addr <<= 1;
    }

    g_pal_public_state.memory_address_start = (void*)start_addr;
    g_pal_public_state.memory_address_end = (void*)end_addr;

    g_vdso_start = proc_maps_info.vdso_start;
    g_vdso_end = proc_maps_info.vdso_end;
    return 0;
}

/* This fd is never closed (but it does not live through `execve`). */
static int g_reserved_ranges_fd = -1;

void pal_read_next_reserved_range(uintptr_t last_range_start, uintptr_t* out_next_range_start,
                                  uintptr_t* out_next_range_end) {
    __UNUSED(last_range_start);
    uintptr_t new_range[2];

    int ret = -EBADF;
    if (g_reserved_ranges_fd >= 0) {
        ret = read_all(g_reserved_ranges_fd, new_range, sizeof(new_range));
    }
    if (ret < 0) {
        *out_next_range_start = 0;
        *out_next_range_end = 0;
        return;
    }

    assert(new_range[0] <= new_range[1] && new_range[1] <= last_range_start);
    *out_next_range_start = new_range[0];
    *out_next_range_end = new_range[1];
}

int init_reserved_ranges(int fd) {
    int ret = DO_SYSCALL(fcntl, fd, F_SETFD, FD_CLOEXEC);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }
    g_reserved_ranges_fd = fd;
    return 0;
}
