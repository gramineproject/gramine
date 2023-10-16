/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains implementation of PAL's internal memory allocator.
 */

#include "api.h"
#include "asan.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "spinlock.h"

static spinlock_t g_slab_mgr_lock = INIT_SPINLOCK_UNLOCKED;

#define SYSTEM_LOCK()   spinlock_lock(&g_slab_mgr_lock)
#define SYSTEM_UNLOCK() spinlock_unlock(&g_slab_mgr_lock)
#define SYSTEM_LOCKED() spinlock_is_locked(&g_slab_mgr_lock)

static inline void* system_mem_alloc(size_t size);
static inline void system_mem_free(void* addr, size_t size);
#define system_malloc(size) system_mem_alloc(size)
#define system_free(addr, size) system_mem_free(addr, size)

#include "slabmgr.h"

static inline void* system_mem_alloc(size_t size) {
    void* addr = NULL;

    size = ALLOC_ALIGN_UP(size);

    int ret = pal_internal_memory_alloc(size, &addr);
    if (ret < 0) {
        return NULL;
    }

#ifdef ASAN
    asan_poison_region((uintptr_t)addr, size, ASAN_POISON_HEAP_LEFT_REDZONE);
#endif

    return addr;
}

static inline void system_mem_free(void* addr, size_t size) {
    if (!addr)
        return;

    size = ALLOC_ALIGN_UP(size);

#ifdef ASAN
    /* Unpoison the memory before unmapping it */
    asan_unpoison_region((uintptr_t)addr, size);
#endif

    int ret = pal_internal_memory_free(addr, size);
    if (ret < 0) {
        log_error("freeing memory failed: %s", pal_strerror(ret));
        _PalProcessExit(1);
    }
}

static SLAB_MGR g_slab_mgr = NULL;

void init_slab_mgr(void) {
    assert(!g_slab_mgr);

    g_slab_mgr = create_slab_mgr();
    if (!g_slab_mgr)
        INIT_FAIL("cannot initialize slab manager");
}

void* malloc(size_t size) {
    void* ptr = slab_alloc(g_slab_mgr, size);

#ifdef DEBUG
    /* In debug builds, try to break code that uses uninitialized heap
     * memory by explicitly initializing to a non-zero value. */
    if (ptr)
        memset(ptr, 0xa5, size);
#endif

    return ptr;
}

void* calloc(size_t num, size_t size) {
    size_t total;
    if (__builtin_mul_overflow(num, size, &total))
        return NULL;

    void* ptr = malloc(total);
    if (ptr)
        memset(ptr, 0, total);
    return ptr;
}

void free(void* ptr) {
    if (!ptr)
        return;
    slab_free(g_slab_mgr, ptr);
}
