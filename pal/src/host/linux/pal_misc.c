/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs for miscellaneous use.
 */

#include <asm/fcntl.h>
#include <linux/time.h>

#include "api.h"
#include "pal.h"
#include "linux_utils.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"

static int g_rand_fd = -1;

int init_random(void) {
    int fd = DO_SYSCALL(open, "/dev/urandom", O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0)
        return unix_to_pal_error(fd);
    g_rand_fd = fd;
    return 0;
}

int _PalSystemTimeQuery(uint64_t* out_usec) {
    struct timespec time;
    int ret;

    if (g_pal_linux_state.vdso_clock_gettime) {
        ret = g_pal_linux_state.vdso_clock_gettime(CLOCK_REALTIME, &time);
    } else {
        ret = DO_SYSCALL(clock_gettime, CLOCK_REALTIME, &time);
    }

    if (ret < 0)
        return unix_to_pal_error(ret);

    /* in microseconds */
    *out_usec = 1000000 * (uint64_t)time.tv_sec + time.tv_nsec / 1000;
    return 0;
}

int _PalRandomBitsRead(void* buffer, size_t size) {
    assert(g_rand_fd != -1);
    int ret = read_all(g_rand_fd, buffer, size);
    if (ret < 0)
        return unix_to_pal_error(ret);

    return 0;
}

int _PalAttestationReport(const void* user_report_data, size_t* user_report_data_size,
                          void* target_info, size_t* target_info_size, void* report,
                          size_t* report_size) {
    __UNUSED(user_report_data);
    __UNUSED(user_report_data_size);
    __UNUSED(target_info);
    __UNUSED(target_info_size);
    __UNUSED(report);
    __UNUSED(report_size);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _PalAttestationQuote(const void* user_report_data, size_t user_report_data_size, void* quote,
                         size_t* quote_size) {
    __UNUSED(user_report_data);
    __UNUSED(user_report_data_size);
    __UNUSED(quote);
    __UNUSED(quote_size);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

int _PalGetSpecialKey(const char* name, void* key, size_t* key_size) {
    __UNUSED(name);
    __UNUSED(key);
    __UNUSED(key_size);
    return -PAL_ERROR_NOTIMPLEMENTED;
}

/* Get the to-be-lazily committed pages of a given memory area; return all-zeros on Linux PAL. */
int _PalGetLazyCommitPages(uintptr_t addr, size_t size, uint8_t* bitvector,
                           size_t* bitvector_size) {
    __UNUSED(addr);
    assert(size && IS_ALIGNED(size, PAGE_SIZE));
    assert(bitvector);
    assert(bitvector_size);

    size_t num_pages = size / g_page_size;
    size_t num_bytes = UDIV_ROUND_UP(num_pages, 8);
    if (num_bytes > *bitvector_size) {
        return -PAL_ERROR_NOMEM;
    }
    *bitvector_size = num_bytes;

    memset(bitvector, 0, num_bytes);

    size_t leftover_pages = num_pages % 8;
    if (leftover_pages)
        bitvector[num_bytes - 1] &= ~((1 << leftover_pages) - 1);

    return 0;
}

int _PalFreeThenLazyReallocCommittedPages(void* addr, size_t size) {
    /* We simiply `memset()` to have zero-filled pages on subsequent accesses. */
    memset(addr, 0, size);
    return 0;
}
