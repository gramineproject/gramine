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
    int fd = DO_SYSCALL(open, "/proc/meminfo", O_RDONLY, 0);

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

unsigned long _PalMemoryAvailableQuota(void) {
    unsigned long quota = 0;
    if (read_proc_meminfo("MemFree", &quota) < 0)
        return 0;
    return quota * 1024;
}

struct parsed_ranges {
    uintptr_t vdso_start;
    uintptr_t vdso_end;
    uintptr_t highest_addr;
};

static int parsed_ranges_callback(struct proc_maps_range* r, void* arg) {
    struct parsed_ranges* ranges = arg;

    if (r->name) {
        if (!strcmp(r->name, "[vdso]")) {
            ranges->vdso_start = r->start;
            ranges->vdso_end = r->end;
        }
    }

    if (ranges->highest_addr < r->end) {
        ranges->highest_addr = r->end;
    }

    return pal_add_initial_range(r->start, r->end - r->start, r->prot, r->name ?: "");
}

int init_initial_memory_ranges(uintptr_t* vdso_start, uintptr_t* vdso_end) {
    struct parsed_ranges ranges = { 0 };
    int ret = parse_proc_maps("/proc/self/maps", &parsed_ranges_callback, &ranges);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }

    uintptr_t start_addr = MMAP_MIN_ADDR;
    uintptr_t end_addr = MIN(ranges.highest_addr, ARCH_HIGHEST_ADDR);

    /* Verify that the address is mappable. */
    while (1) {
        if (start_addr >= end_addr) {
            return -PAL_ERROR_NOMEM;
        }

        void* ptr = (void*)DO_SYSCALL(mmap, start_addr, g_pal_public_state.alloc_align, PROT_NONE,
                                      MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        if (!IS_PTR_ERR(ptr)) {
            DO_SYSCALL(munmap, ptr, g_pal_public_state.alloc_align);
            break;
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

    *vdso_start = ranges.vdso_start;
    *vdso_end = ranges.vdso_end;
    return 0;
}

/* This fd is never closed (but it does not live through `execve`). */
static int g_reserved_ranges_fd = -1;

void pal_read_one_reserved_range(uintptr_t* last_range_start, uintptr_t* last_range_end) {
    uintptr_t last_range[2];

    int ret = -EBADF;
    if (g_reserved_ranges_fd >= 0) {
        ret = read_all(g_reserved_ranges_fd, last_range, sizeof(last_range));
    }
    if (ret < 0) {
        *last_range_start = 0;
        *last_range_end = 0;
        return;
    }

    assert(last_range[0] <= last_range[1] && last_range[1] <= *last_range_start);
    *last_range_start = last_range[0];
    *last_range_end = last_range[1];
}

int init_reserved_ranges(int fd) {
    int ret = DO_SYSCALL(fcntl, fd, F_SETFD, FD_CLOEXEC);
    if (ret < 0) {
        return unix_to_pal_error(ret);
    }
    g_reserved_ranges_fd = fd;
    return 0;
}
