/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Invisible Things Lab
 */

#include <stddef.h> /* needed by <linux/signal.h> for size_t */

#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>

#include "api.h"
#include "assert.h"
#include "avl_tree.h"
#include "libos_checkpoint.h"
#include "libos_defs.h"
#include "libos_flags_conv.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_rwlock.h"
#include "libos_tcb.h"
#include "libos_utils.h"
#include "libos_vma.h"
#include "linux_abi/memory.h"

/* The amount of total memory usage, all accesses must be protected by `vma_tree_lock`. */
static size_t g_total_memory_size = 0;
/* The peak amount of total memory usage, all accesses must use atomics, writes must also hold
 * `vma_tree_lock`. */
static size_t g_peak_total_memory_size = 0;

/* Filter flags that will be saved in `struct libos_vma`. For example there is no need for saving
 * MAP_FIXED or unsupported flags. */
static int filter_saved_flags(int flags) {
    return flags & (MAP_SHARED | MAP_SHARED_VALIDATE | MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN
                    | MAP_HUGETLB | MAP_HUGE_2MB | MAP_HUGE_1GB | MAP_STACK
                    | VMA_UNMAPPED | VMA_INTERNAL | VMA_TAINTED);
}

/* TODO: split flags into internal (Gramine) and Linux; also to consider: completely remove Linux
 * flags - we only need MAP_SHARED/MAP_PRIVATE and possibly MAP_STACK/MAP_GROWSDOWN */
struct libos_vma {
    uintptr_t begin;
    uintptr_t end;
    uintptr_t valid_end; // memory accesses beyond valid_end result in SIGBUS/EFAULT
    int prot;
    int flags;
    struct libos_handle* file;
    uint64_t offset; // offset inside `file`, where `begin` starts
    union {
        /* If this `vma` is used, it is included in `vma_tree` using this node. */
        struct avl_tree_node tree_node;
        /* Otherwise it might be cached in per thread vma cache, or might be on a temporary list
         * of to-be-freed vmas (used by _vma_bkeep_remove). Such lists use the field below. */
        struct libos_vma* next_free;
    };
    char comment[VMA_COMMENT_LEN];
};

static void copy_comment(struct libos_vma* vma, const char* comment) {
    size_t size = MIN(sizeof(vma->comment), strlen(comment) + 1);
    memcpy(vma->comment, comment, size);
    vma->comment[sizeof(vma->comment) - 1] = '\0';
}

static void copy_vma(struct libos_vma* old_vma, struct libos_vma* new_vma) {
    new_vma->begin     = old_vma->begin;
    new_vma->end       = old_vma->end;
    new_vma->valid_end = old_vma->valid_end;
    new_vma->prot      = old_vma->prot;
    new_vma->flags     = old_vma->flags;

    new_vma->file = old_vma->file;
    if (new_vma->file) {
        if (new_vma->file->inode)
            (void)__atomic_add_fetch(&new_vma->file->inode->num_mmapped, 1, __ATOMIC_RELAXED);
        get_handle(new_vma->file);
    }
    new_vma->offset = old_vma->offset;
    copy_comment(new_vma, old_vma->comment);
}

static bool vma_tree_cmp(struct avl_tree_node* node_a, struct avl_tree_node* node_b) {
    struct libos_vma* a = container_of(node_a, struct libos_vma, tree_node);
    struct libos_vma* b = container_of(node_b, struct libos_vma, tree_node);

    return a->end <= b->end;
}

static bool is_addr_in_vma(uintptr_t addr, struct libos_vma* vma) {
    return vma->begin <= addr && addr < vma->end;
}

/* Returns whether `addr` is smaller or inside a vma (`node`). */
static bool cmp_addr_to_vma(void* addr, struct avl_tree_node* node) {
    struct libos_vma* vma = container_of(node, struct libos_vma, tree_node);

    return (uintptr_t)addr < vma->end;
}

/*
 * "vma_tree" holds all vmas with the assumption that no 2 overlap (though they could be adjacent).
 * Currently we do not merge similar adjacent vmas - if we ever start doing it, this code needs
 * to be revisited as there might be some optimizations that would break due to it.
 */
static struct avl_tree vma_tree = {.cmp = vma_tree_cmp};
static struct libos_rwlock vma_tree_lock;
static bool vma_tree_lock_created = false;

/*
 * It is important to use the below wrappers instead of raw `rwlock_*_lock()` functions. This is
 * because at LibOS startup, the lock `vma_tree_lock` is not yet created. Fortunately, at LibOS
 * startup there is only one thread, so the lock would be redundant anyway.
 *
 * We cannot create `vma_tree_lock` at the very beginning of LibOS startup, because creating this
 * lock itself requires the memory subsystem (VMA) to be fully initialized. So we start with VMA
 * locking disabled first, then init the VMA subsystem, and only then create the lock. At this point
 * the VMA subsystem can be used in thread-safe manner.
 */
static inline void vma_rwlock_read_lock(void) {
    if (!vma_tree_lock_created)
        return;
    rwlock_read_lock(&vma_tree_lock);
}

static inline void vma_rwlock_read_unlock(void) {
    if (!vma_tree_lock_created)
        return;
    rwlock_read_unlock(&vma_tree_lock);
}

static inline void vma_rwlock_write_lock(void) {
    if (!vma_tree_lock_created)
        return;
    rwlock_write_lock(&vma_tree_lock);
}

static inline void vma_rwlock_write_unlock(void) {
    if (!vma_tree_lock_created)
        return;
    rwlock_write_unlock(&vma_tree_lock);
}

#ifdef DEBUG
static inline bool vma_rwlock_is_read_or_write_locked(void) {
    if (!vma_tree_lock_created)
        return true;
    return rwlock_is_read_locked(&vma_tree_lock) || rwlock_is_write_locked(&vma_tree_lock);
}

static inline bool vma_rwlock_is_write_locked(void) {
    if (!vma_tree_lock_created)
        return true;
    return rwlock_is_write_locked(&vma_tree_lock);
}
#endif

/* VMA code is supposed to use the vma_* wrappers of RW lock; hide the actual RW lock funcs */
#define rwlock_is_write_locked(x) false
#define rwlock_is_read_locked(x) false
#define rwlock_read_lock(x) static_assert(false, "hidden func")
#define rwlock_read_unlock(x) static_assert(false, "hidden func")
#define rwlock_write_lock(x) static_assert(false, "hidden func")
#define rwlock_write_unlock(x) static_assert(false, "hidden func")

static void total_memory_size_add(size_t length) {
    assert(vma_rwlock_is_write_locked());

    g_total_memory_size += length;

    /* We can read `g_peak_total_memory_size` non atomically, because writes are protected by
     * `vma_tree_lock`, which we hold. Store needs to be atomic to synchronize with readers. */
    if (g_peak_total_memory_size < g_total_memory_size) {
        __atomic_store_n(&g_peak_total_memory_size, g_total_memory_size, __ATOMIC_RELAXED);
    }
}

static void total_memory_size_sub(size_t length) {
    assert(vma_rwlock_is_write_locked());
    assert(g_total_memory_size >= length);

    g_total_memory_size -= length;
}

static struct libos_vma* node2vma(struct avl_tree_node* node) {
    if (!node) {
        return NULL;
    }
    return container_of(node, struct libos_vma, tree_node);
}

static struct libos_vma* _get_next_vma(struct libos_vma* vma) {
    assert(vma_rwlock_is_read_or_write_locked());
    return node2vma(avl_tree_next(&vma->tree_node));
}

static struct libos_vma* _get_prev_vma(struct libos_vma* vma) {
    assert(vma_rwlock_is_read_or_write_locked());
    return node2vma(avl_tree_prev(&vma->tree_node));
}

static struct libos_vma* _get_last_vma(void) {
    assert(vma_rwlock_is_read_or_write_locked());
    return node2vma(avl_tree_last(&vma_tree));
}

static struct libos_vma* _get_first_vma(void) {
    assert(vma_rwlock_is_read_or_write_locked());
    return node2vma(avl_tree_first(&vma_tree));
}

/* Returns the vma that contains `addr`. If there is no such vma, returns the closest vma with
 * higher address. */
static struct libos_vma* _lookup_vma(uintptr_t addr) {
    assert(vma_rwlock_is_read_or_write_locked());

    struct avl_tree_node* node = avl_tree_lower_bound_fn(&vma_tree, (void*)addr, cmp_addr_to_vma);
    if (!node) {
        return NULL;
    }
    return container_of(node, struct libos_vma, tree_node);
}

typedef bool (*traverse_visitor)(struct libos_vma* vma, void* visitor_arg);

/*
 * Walks through all VMAs which contain at least one byte from the [begin, end) range.
 *
 * `visitor` returns whether to continue iteration. It must be as simple as possible, because
 * it's called with the VMA lock held.
 *
 * Returns whether the traversed range was continuously covered by VMAs (takes into account
 * `vma->valid_end` if asked by the caller). This is useful:
 *
 *   - For emulating errors in memory management syscalls. To avoid memory faults during deep copy
 *     of user-supplied buffers in syscalls (e.g., in case of SGX OCALLs), callers must set
 *     `use_only_valid_part = true`. This deviates slightly from Linux behavior: e.g., on
 *     `write(partially-valid-vma)` Linux does not return -EFAULT but instead uses the buffer until
 *     the first invalid address. This behavior is too cumbersome to implement in Gramine + SGX,
 *     thus on `write(partially-valid-vma)` Gramine immediately returns -EFAULT.
 *
 *   - For deciding whether to return ENOMEM in madvise(MADV_DONTNEED). E.g., on
 *     `madvise(partially-valid-vma, MADV_DONTNEED)` Linux returns success (even though there is a
 *     part that is invalid). Callers must set `use_only_valid_part = false` to comply with this
 *     Linux behavior.
 */
// TODO: Probably other VMA functions could make use of this helper.
static bool _traverse_vmas_in_range(uintptr_t begin, uintptr_t end, bool use_only_valid_part,
                                    traverse_visitor visitor, void* visitor_arg) {
    assert(vma_rwlock_is_read_or_write_locked());
    assert(begin <= end);

    if (begin == end)
        return true;

    struct libos_vma* vma = _lookup_vma(begin);
    if (!vma || end <= vma->begin)
        return false;

    struct libos_vma* prev = NULL;
    bool is_continuous = vma->begin <= begin;

    while (1) {
        if (!visitor(vma, visitor_arg))
            break;

        prev = vma;
        vma = _get_next_vma(vma);
        if (!vma || end <= vma->begin) {
            uintptr_t prev_end = use_only_valid_part ? prev->valid_end : prev->end;
            is_continuous &= end <= prev_end;
            break;
        }

        uintptr_t prev_end = use_only_valid_part ? prev->valid_end : prev->end;
        is_continuous &= prev_end == vma->begin;
    }

    return is_continuous;
}

static void split_vma(struct libos_vma* old_vma, struct libos_vma* new_vma, uintptr_t addr) {
    assert(old_vma->begin < addr && addr < old_vma->end);

    copy_vma(old_vma, new_vma);
    new_vma->begin = addr;
    if (new_vma->file) {
        new_vma->offset += new_vma->begin - old_vma->begin;
        if (new_vma->valid_end < new_vma->begin) {
            new_vma->valid_end = new_vma->begin;
        }
    }

    old_vma->end = addr;
    if (old_vma->valid_end > old_vma->end) {
        old_vma->valid_end = old_vma->end;
    }

    assert(old_vma->begin <= old_vma->valid_end && old_vma->valid_end <= old_vma->end);
    assert(new_vma->begin <= new_vma->valid_end && new_vma->valid_end <= new_vma->end);
}

/*
 * This function might need a preallocated vma in `new_vma_ptr`, because it might need to split
 * an existing vma into two parts. If the vma is provided and this function happens to use it,
 * `*new_vma_ptr` will be set to NULL.
 * It returns a list of vmas that need to be freed in `vmas_to_free`.
 * Range [begin, end) can consist of multiple vmas even with holes in between, but they all must be
 * either internal or non-internal.
 */
static int _vma_bkeep_remove(uintptr_t begin, uintptr_t end, bool is_internal,
                             struct libos_vma** new_vma_ptr, struct libos_vma** vmas_to_free) {
    assert(vma_rwlock_is_write_locked());
    assert(!new_vma_ptr || *new_vma_ptr);
    assert(IS_ALLOC_ALIGNED_PTR(begin) && IS_ALLOC_ALIGNED_PTR(end));

    struct libos_vma* vma = _lookup_vma(begin);
    if (!vma) {
        return 0;
    }

    struct libos_vma* first_vma = vma;

    while (vma && vma->begin < end) {
        if (!!(vma->flags & VMA_INTERNAL) != is_internal) {
            if (is_internal) {
                log_warning("LibOS tried to free a user vma!");
            } else {
                log_warning("user app tried to free an internal vma!");
            }
            return -EACCES;
        }

        vma = _get_next_vma(vma);
    }

    vma = first_vma;

    if (vma->begin < begin) {
        if (end < vma->end) {
            if (!new_vma_ptr) {
                log_warning("need an additional vma to free this range!");
                return -ENOMEM;
            }
            struct libos_vma* new_vma = *new_vma_ptr;
            *new_vma_ptr = NULL;

            split_vma(vma, new_vma, end);
            vma->end = begin;
            if (vma->valid_end > vma->end) {
                vma->valid_end = vma->end;
            }

            avl_tree_insert(&vma_tree, &new_vma->tree_node);
            total_memory_size_sub(end - begin);

            return 0;
        }

        total_memory_size_sub(vma->end - begin);
        vma->end = begin;
        if (vma->valid_end > vma->end) {
            vma->valid_end = vma->end;
        }

        vma = _get_next_vma(vma);
        if (!vma) {
            return 0;
        }
    }

    while (vma->end <= end) {
        /* We need to search for the next node before deletion. */
        struct libos_vma* next = _get_next_vma(vma);

        avl_tree_delete(&vma_tree, &vma->tree_node);
        total_memory_size_sub(vma->end - vma->begin);

        vma->next_free = NULL;
        *vmas_to_free = vma;
        vmas_to_free = &vma->next_free;

        if (!next) {
            return 0;
        }
        vma = next;
    }

    if (vma->begin < end) {
        if (vma->file) {
            vma->offset += end - vma->begin;
        }
        total_memory_size_sub(end - vma->begin);
        vma->begin = end;
        if (vma->valid_end < vma->begin) {
            vma->valid_end = vma->begin;
        }
    }

    return 0;
}

static void free_vmas_freelist(struct libos_vma* vma);

/* This function uses at most 1 vma (in `bkeep_mmap_any`). `alloc_vma` depends on this behavior. */
static void* _vma_malloc(size_t size) {
    void* addr = NULL;
    size = ALLOC_ALIGN_UP(size);

    if (bkeep_mmap_any(size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | VMA_INTERNAL,
                       NULL, 0, "vma", &addr) < 0) {
        return NULL;
    }

    int ret = PalVirtualMemoryAlloc(addr, size, PAL_PROT_WRITE | PAL_PROT_READ);
    if (ret < 0) {
        struct libos_vma* vmas_to_free = NULL;

        vma_rwlock_write_lock();
        /* Since we are freeing a range we just created, additional vma is not needed. */
        ret = _vma_bkeep_remove((uintptr_t)addr, (uintptr_t)addr + size, /*is_internal=*/true, NULL,
                                &vmas_to_free);
        vma_rwlock_write_unlock();
        if (ret < 0) {
            log_error("Removing a vma we just created failed: %s", unix_strerror(ret));
            BUG();
        }

        free_vmas_freelist(vmas_to_free);
        return NULL;
    }

    return addr;
}

/* We never free `vma_mgr`. */
static void _vma_free(void* ptr, size_t size) {
    __UNUSED(ptr);
    __UNUSED(size);
    BUG();
}

#undef system_malloc
#undef system_free
#define system_malloc _vma_malloc
#define system_free   _vma_free
#define OBJ_TYPE      struct libos_vma
#include "memmgr.h"

static struct libos_lock vma_mgr_lock;
static MEM_MGR vma_mgr = NULL;

/*
 * We use a following per-thread caching mechanism of VMAs:
 * Each thread has a singly linked list of free VMAs, with maximal length of 3.
 * Allocation first checks if there is a cached VMA, deallocation adds it to cache, unless it is
 * full (3 entries already present).
 * Note that 3 is configurable number as long as it is a power of 2 minus 1 and `struct libos_vma`
 * alignment is not less that it. This is needed for storing the list length in lower bits of
 * the pointer (small optimization not to add more fields to TCB - can be removed if the max list
 * size needs to be increased or any supported architecture does not allow for it).
 */
#ifndef __x86_64__
/* If this optimization will work on the architecture you port Gramine to, add it to the check
 * above. */
#error "This optimization requires specific representation of pointers."
#endif

#define VMA_CACHE_SIZE 3ull
static_assert((VMA_CACHE_SIZE & (VMA_CACHE_SIZE + 1)) == 0,
              "VMA_CACHE_SIZE must be a power of 2 minus 1!");

static struct libos_vma* cache2ptr(void* vma) {
    static_assert(
        alignof(struct libos_vma) >= VMA_CACHE_SIZE + 1,
        "We need some lower bits of pointers to `struct libos_vma` for this optimization!");
    return (struct libos_vma*)((uintptr_t)vma & ~VMA_CACHE_SIZE);
}

static void* create_cache_ptr(struct libos_vma* vma, size_t size) {
    assert(size <= VMA_CACHE_SIZE);
    return (void*)((uintptr_t)vma | size);
}

static size_t cache2size(void* vma) {
    return (size_t)((uintptr_t)vma & VMA_CACHE_SIZE);
}

static struct libos_vma* get_from_thread_vma_cache(void) {
    struct libos_vma* vma = cache2ptr(LIBOS_TCB_GET(vma_cache));
    if (!vma) {
        return NULL;
    }
    LIBOS_TCB_SET(vma_cache, vma->next_free);
    return vma;
}

static bool add_to_thread_vma_cache(struct libos_vma* vma) {
    assert(cache2size(vma) == 0);
    void* ptr = LIBOS_TCB_GET(vma_cache);
    size_t size = cache2size(ptr);

    if (size >= VMA_CACHE_SIZE) {
        return false;
    }

    vma->next_free = ptr;
    LIBOS_TCB_SET(vma_cache, create_cache_ptr(vma, size + 1));
    return true;
}

static void remove_from_thread_vma_cache(struct libos_vma* to_remove) {
    assert(to_remove);

    struct libos_vma* first_vma = cache2ptr(LIBOS_TCB_GET(vma_cache));

    if (first_vma == to_remove) {
        LIBOS_TCB_SET(vma_cache, first_vma->next_free);
        return;
    }

    struct libos_vma* vma = first_vma;
    bool found = false;
    while (vma) {
        struct libos_vma* next = cache2ptr(vma->next_free);
        if (next == to_remove) {
            found = true;
            break;
        }
        vma = next;
    }
    if (!found) {
        return;
    }

    LIBOS_TCB_SET(vma_cache, create_cache_ptr(first_vma, cache2size(first_vma) - 1));
    vma = first_vma;
    while (vma) {
        struct libos_vma* next = cache2ptr(vma->next_free);
        if (next == to_remove) {
            vma->next_free = next->next_free;
            return;
        }
        vma->next_free = create_cache_ptr(next, cache2size(vma->next_free) - 1);
        vma = next;
    }
}

static struct libos_vma* alloc_vma(void) {
    struct libos_vma* vma = get_from_thread_vma_cache();
    if (vma) {
        goto out;
    }

    lock(&vma_mgr_lock);
    vma = get_mem_obj_from_mgr(vma_mgr);
    if (!vma) {
        /* `enlarge_mem_mgr` below will call _vma_malloc, which uses at most 1 vma - so we
         * temporarily provide it. */
        struct libos_vma tmp_vma = {0};
        /* vma cache is empty, as we checked it before. */
        if (!add_to_thread_vma_cache(&tmp_vma)) {
            log_error("Failed to add tmp vma to cache!");
            BUG();
        }
        if (!enlarge_mem_mgr(vma_mgr, size_align_up(DEFAULT_VMA_COUNT))) {
            remove_from_thread_vma_cache(&tmp_vma);
            goto out_unlock;
        }

        struct libos_vma* vma_migrate = get_mem_obj_from_mgr(vma_mgr);
        if (!vma_migrate) {
            log_error("Failed to allocate a vma right after enlarge_mem_mgr!");
            BUG();
        }

        vma_rwlock_write_lock();
        /* Currently `tmp_vma` is always used (added to `vma_tree`), but this assumption could
         * easily be changed (e.g. if we implement VMAs merging).*/
        struct avl_tree_node* node = &tmp_vma.tree_node;
        if (node->parent || vma_tree.root == node) {
            /* `tmp_vma` is in `vma_tree`, we need to migrate it. */
            copy_vma(&tmp_vma, vma_migrate);
            avl_tree_swap_node(&vma_tree, node, &vma_migrate->tree_node);
            vma_migrate = NULL;
        }
        vma_rwlock_write_unlock();

        if (vma_migrate) {
            free_mem_obj_to_mgr(vma_mgr, vma_migrate);
        }
        remove_from_thread_vma_cache(&tmp_vma);

        vma = get_mem_obj_from_mgr(vma_mgr);
    }

out_unlock:
    unlock(&vma_mgr_lock);
out:
    if (vma) {
        memset(vma, 0, sizeof(*vma));
    }
    return vma;
}

static void free_vma(struct libos_vma* vma) {
    if (vma->file) {
        if (vma->file->inode) {
            uint64_t old_num_mmapped = __atomic_fetch_sub(&vma->file->inode->num_mmapped, 1,
                                                          __ATOMIC_RELAXED);
            assert(old_num_mmapped > 0);
            (void)old_num_mmapped;
        }
        put_handle(vma->file);
    }

    if (add_to_thread_vma_cache(vma)) {
        return;
    }

    lock(&vma_mgr_lock);
    free_mem_obj_to_mgr(vma_mgr, vma);
    unlock(&vma_mgr_lock);
}

static void free_vmas_freelist(struct libos_vma* vma) {
    while (vma) {
        struct libos_vma* next = vma->next_free;
        free_vma(vma);
        vma = next;
    }
}

static int _bkeep_initial_vma(struct libos_vma* new_vma) {
    assert(vma_rwlock_is_write_locked());

    struct libos_vma* tmp_vma = _lookup_vma(new_vma->begin);
    if (tmp_vma && tmp_vma->begin < new_vma->end) {
        return -EEXIST;
    } else {
        avl_tree_insert(&vma_tree, &new_vma->tree_node);
        total_memory_size_add(new_vma->end - new_vma->begin);

        return 0;
    }
}

static int pal_mem_bkeep_alloc(size_t size, uintptr_t* out_addr);
static int pal_mem_bkeep_free(uintptr_t addr, size_t size);

#define ASLR_BITS 12
/* This variable is written to only once, during initialization, so it does not need to
 * be atomic. */
static void* g_aslr_addr_top = NULL;

int init_vma(void) {
    PalSetMemoryBookkeepingUpcalls(pal_mem_bkeep_alloc, pal_mem_bkeep_free);

    size_t initial_ranges_count = 0;
    for (size_t i = 0; i < g_pal_public_state->initial_mem_ranges_len; i++) {
        if (!g_pal_public_state->initial_mem_ranges[i].is_free) {
            initial_ranges_count++;
        }
    }

    struct libos_vma init_vmas[1 + initial_ranges_count];

    init_vmas[0].begin = 0; // vma for creation of memory manager

    size_t idx = 0;
    for (size_t i = 0; i < g_pal_public_state->initial_mem_ranges_len; i++) {
        if (g_pal_public_state->initial_mem_ranges[i].is_free) {
            continue;
        }

        init_vmas[1 + idx].begin     = g_pal_public_state->initial_mem_ranges[i].start;
        init_vmas[1 + idx].end       = g_pal_public_state->initial_mem_ranges[i].end;
        init_vmas[1 + idx].valid_end = g_pal_public_state->initial_mem_ranges[i].end;

        init_vmas[1 + idx].prot   = PAL_PROT_TO_LINUX(g_pal_public_state->initial_mem_ranges[i].prot);
        init_vmas[1 + idx].flags  = MAP_PRIVATE | MAP_ANONYMOUS | VMA_INTERNAL;
        init_vmas[1 + idx].file   = NULL;
        init_vmas[1 + idx].offset = 0;
        copy_comment(&init_vmas[1 + idx], g_pal_public_state->initial_mem_ranges[i].comment);

        assert(IS_ALLOC_ALIGNED(init_vmas[1 + idx].begin)
               && IS_ALLOC_ALIGNED(init_vmas[1 + idx].end));
        idx++;
    }
    assert(1 + idx == ARRAY_SIZE(init_vmas));

    vma_rwlock_write_lock();
    int ret = 0;
    /* First of init_vmas is reserved for later usage. */
    for (size_t i = 1; i < ARRAY_SIZE(init_vmas); i++) {
        assert(init_vmas[i].begin <= init_vmas[i].end);
        /* Skip empty areas. */
        if (init_vmas[i].begin == init_vmas[i].end) {
            log_debug("Skipping bookkeeping of empty region at 0x%lx (comment: \"%s\")",
                      init_vmas[i].begin, init_vmas[i].comment);
            continue;
        }
        if (!IS_ALLOC_ALIGNED(init_vmas[i].begin) || !IS_ALLOC_ALIGNED(init_vmas[i].end)) {
            log_error("Unaligned VMA region: 0x%lx-0x%lx (%s)", init_vmas[i].begin,
                      init_vmas[i].end, init_vmas[i].comment);
            ret = -EINVAL;
            break;
        }
        ret = _bkeep_initial_vma(&init_vmas[i]);
        if (ret < 0) {
            log_error("Failed to bookkeep initial VMA region 0x%lx-0x%lx (%s)",
                      init_vmas[i].begin, init_vmas[i].end, init_vmas[i].comment);
            break;
        }
        log_debug("Initial VMA region 0x%lx-0x%lx (%s) bookkeeped", init_vmas[i].begin,
                  init_vmas[i].end, init_vmas[i].comment);
    }
    vma_rwlock_write_unlock();
    /* From now on if we return with an error we might leave a structure local to this function in
     * vma_tree. We do not bother with removing them - this is initialization of VMA subsystem, if
     * it fails the whole application startup fails and we should never call any of functions in
     * this file. */
    if (ret < 0) {
        return ret;
    }

    g_aslr_addr_top = g_pal_public_state->memory_address_end;

    if (!g_pal_public_state->disable_aslr) {
        /* Inspired by: https://elixir.bootlin.com/linux/v5.6.3/source/arch/x86/mm/mmap.c#L80 */
        size_t gap_max_size = (g_pal_public_state->memory_address_end
                               - g_pal_public_state->memory_address_start) / 6 * 5;
        /* We do address space randomization only if we have at least ASLR_BITS to randomize. */
        if (gap_max_size / ALLOC_ALIGNMENT >= (1ul << ASLR_BITS)) {
            size_t gap = 0;

            int ret = PalRandomBitsRead(&gap, sizeof(gap));
            if (ret < 0) {
                return pal_to_unix_errno(ret);
            }

            /* Resulting distribution is not ideal, but it should not be an issue here. */
            gap = ALLOC_ALIGN_DOWN(gap % gap_max_size);
            g_aslr_addr_top = (char*)g_aslr_addr_top - gap;

            log_debug("ASLR top address adjusted to %p", g_aslr_addr_top);
        } else {
            log_warning("Not enough space to make meaningful address space randomization.");
        }
    }

    /* We need 1 vma to create the memmgr. */
    if (!add_to_thread_vma_cache(&init_vmas[0])) {
        log_error("Failed to add tmp vma to cache!");
        BUG();
    }
    vma_mgr = create_mem_mgr(DEFAULT_VMA_COUNT);
    if (!vma_mgr) {
        log_error("Failed to create VMA memory manager!");
        return -ENOMEM;
    }

    if (!create_lock(&vma_mgr_lock)) {
        return -ENOMEM;
    }

    if (!rwlock_create(&vma_tree_lock)) {
        return -ENOMEM;
    }
    vma_tree_lock_created = true;

    /* Now we need to migrate temporary initial vmas. */
    struct libos_vma* vmas_to_migrate_to[ARRAY_SIZE(init_vmas)];
    for (size_t i = 0; i < ARRAY_SIZE(vmas_to_migrate_to); i++) {
        vmas_to_migrate_to[i] = alloc_vma();
        if (!vmas_to_migrate_to[i]) {
            return -ENOMEM;
        }
    }

    vma_rwlock_write_lock();
    for (size_t i = 0; i < ARRAY_SIZE(init_vmas); i++) {
        /* Skip empty areas. */
        if (init_vmas[i].begin == init_vmas[i].end) {
            continue;
        }
        copy_vma(&init_vmas[i], vmas_to_migrate_to[i]);
        avl_tree_swap_node(&vma_tree, &init_vmas[i].tree_node, &vmas_to_migrate_to[i]->tree_node);
        vmas_to_migrate_to[i] = NULL;
    }
    vma_rwlock_write_unlock();

    for (size_t i = 0; i < ARRAY_SIZE(vmas_to_migrate_to); i++) {
        if (vmas_to_migrate_to[i]) {
            free_vma(vmas_to_migrate_to[i]);
        }
    }

    return 0;
}

static void _add_unmapped_vma(uintptr_t begin, uintptr_t end, struct libos_vma* vma) {
    assert(vma_rwlock_is_write_locked());

    vma->begin     = begin;
    vma->end       = end;
    vma->valid_end = end;

    vma->prot   = PROT_NONE;
    vma->flags  = VMA_INTERNAL | VMA_UNMAPPED;
    vma->file   = NULL;
    vma->offset = 0;
    copy_comment(vma, "");

    avl_tree_insert(&vma_tree, &vma->tree_node);
    total_memory_size_add(vma->end - vma->begin);
}

// TODO change so that vma1 is provided by caller
int bkeep_munmap(void* addr, size_t length, bool is_internal, void** tmp_vma_ptr) {
    assert(tmp_vma_ptr);

    if (!length || !IS_ALLOC_ALIGNED(length) || !IS_ALLOC_ALIGNED_PTR(addr)) {
        return -EINVAL;
    }

    struct libos_vma* vma1 = alloc_vma();
    if (!vma1) {
        return -ENOMEM;
    }
    /* Unmapping may succeed even without this vma, so if this allocation fails we move on. */
    struct libos_vma* vma2 = alloc_vma();

    struct libos_vma* vmas_to_free = NULL;

    vma_rwlock_write_lock();
    int ret = _vma_bkeep_remove((uintptr_t)addr, (uintptr_t)addr + length, is_internal,
                                vma2 ? &vma2 : NULL, &vmas_to_free);
    if (ret >= 0) {
        _add_unmapped_vma((uintptr_t)addr, (uintptr_t)addr + length, vma1);
        *tmp_vma_ptr = (void*)vma1;
        vma1 = NULL;
    }
    vma_rwlock_write_unlock();

    free_vmas_freelist(vmas_to_free);
    if (vma1) {
        free_vma(vma1);
    }
    if (vma2) {
        free_vma(vma2);
    }

    /*
     * TODO: We call `remove_r_debug()` on the assumption that `addr` might be the beginning of a
     * loaded ELF object. However, `remove_r_debug()` assumes that `addr` is the load base, while
     * the first mapping of an ELF object might begin later than its load base.
     */
    remove_r_debug(addr);
    return ret;
}

void bkeep_remove_tmp_vma(void* _vma) {
    struct libos_vma* vma = (struct libos_vma*)_vma;

    assert(vma->flags == (VMA_INTERNAL | VMA_UNMAPPED));

    vma_rwlock_write_lock();
    avl_tree_delete(&vma_tree, &vma->tree_node);
    total_memory_size_sub(vma->end - vma->begin);
    vma_rwlock_write_unlock();

    free_vma(vma);
}

void bkeep_convert_tmp_vma_to_user(void* _vma) {
    struct libos_vma* vma = (struct libos_vma*)_vma;

    vma_rwlock_write_lock();
    assert(vma->flags == (VMA_INTERNAL | VMA_UNMAPPED));
    vma->flags &= ~VMA_INTERNAL;
    vma_rwlock_write_unlock();
}

static bool is_file_prot_matching(struct libos_handle* file_hdl, int prot) {
    return !(prot & PROT_WRITE) || (file_hdl->flags & O_RDWR);
}

int bkeep_mmap_fixed(void* addr, size_t length, int prot, int flags, struct libos_handle* file,
                     uint64_t offset, const char* comment) {
    assert(flags & (MAP_FIXED | MAP_FIXED_NOREPLACE));

    if (!length || !IS_ALLOC_ALIGNED(length) || !IS_ALLOC_ALIGNED_PTR(addr)) {
        return -EINVAL;
    }

    struct libos_vma* new_vma = alloc_vma();
    if (!new_vma) {
        return -ENOMEM;
    }
    /* Unmapping may succeed even without this vma, so if this allocation fails we move on. */
    struct libos_vma* vma1 = alloc_vma();

    new_vma->begin = (uintptr_t)addr;
    new_vma->end   = new_vma->begin + length;

    /* valid_end is potentially incorrect now (if there is a file-backed mapping with a part that
     * exceeds the file); it should be updated in the mmap syscall (for file-backed mappings) */
    new_vma->valid_end = new_vma->begin + length;

    new_vma->prot  = prot;
    new_vma->flags = filter_saved_flags(flags) | ((file && (prot & PROT_WRITE)) ? VMA_TAINTED : 0);
    new_vma->file  = file;
    if (new_vma->file) {
        get_handle(new_vma->file);
        if (new_vma->file->inode)
            (void)__atomic_add_fetch(&new_vma->file->inode->num_mmapped, 1, __ATOMIC_RELAXED);
    }
    new_vma->offset = file ? offset : 0;
    copy_comment(new_vma, comment ?: "");

    struct libos_vma* vmas_to_free = NULL;

    vma_rwlock_write_lock();
    int ret = 0;
    if (flags & MAP_FIXED_NOREPLACE) {
        struct libos_vma* tmp_vma = _lookup_vma(new_vma->begin);
        if (tmp_vma && tmp_vma->begin < new_vma->end) {
            ret = -EEXIST;
        }
    } else {
        ret = _vma_bkeep_remove(new_vma->begin, new_vma->end, !!(flags & VMA_INTERNAL),
                                vma1 ? &vma1 : NULL, &vmas_to_free);
    }
    if (ret >= 0) {
        avl_tree_insert(&vma_tree, &new_vma->tree_node);
        total_memory_size_add(new_vma->end - new_vma->begin);
    }
    vma_rwlock_write_unlock();

    free_vmas_freelist(vmas_to_free);
    if (vma1) {
        free_vma(vma1);
    }

    if (ret < 0) {
        free_vma(new_vma);
    }
    return ret;
}

static void vma_update_prot(struct libos_vma* vma, int prot) {
    vma->prot = prot & (PROT_NONE | PROT_READ | PROT_WRITE | PROT_EXEC);
    if (vma->file && (prot & PROT_WRITE)) {
        vma->flags |= VMA_TAINTED;
    }
}

static int _vma_bkeep_change(uintptr_t begin, uintptr_t end, int prot, bool is_internal,
                             struct libos_vma** new_vma_ptr1, struct libos_vma** new_vma_ptr2) {
    assert(vma_rwlock_is_write_locked());
    assert(IS_ALLOC_ALIGNED_PTR(begin) && IS_ALLOC_ALIGNED_PTR(end));
    assert(begin < end);

    struct libos_vma* vma = _lookup_vma(begin);
    if (!vma) {
        return -ENOMEM;
    }

    struct libos_vma* prev = NULL;
    struct libos_vma* first_vma = vma;

    if (begin < vma->begin) {
        return -ENOMEM;
    }

    bool is_continuous = true;

    while (1) {
        if (!!(vma->flags & VMA_INTERNAL) != is_internal) {
            return -EACCES;
        }
        if (prot & PROT_GROWSDOWN) {
            if (!(vma->flags & MAP_GROWSDOWN)) {
                return -EINVAL;
            }
        }
        if (vma->file && (vma->flags & MAP_SHARED)) {
            if (!is_file_prot_matching(vma->file, prot)) {
                return -EACCES;
            }
        }

        if (end <= vma->end) {
            break;
        }

        prev = vma;

        vma = _get_next_vma(vma);
        if (!vma) {
            is_continuous = false;
            break;
        }

        is_continuous &= prev->end == vma->begin;
    }

    if (!is_continuous) {
        /* When Linux fails with such an error, it still changes permissions of the first
         * continuous fragment, but we just return an error. */
        return -ENOMEM;
    }

    vma = first_vma;

    /* For PROT_GROWSDOWN we just pretend that `vma->begin == begin`. */
    if (vma->begin < begin && !(prot & PROT_GROWSDOWN)) {
        struct libos_vma* new_vma1 = *new_vma_ptr1;
        *new_vma_ptr1 = NULL;

        split_vma(vma, new_vma1, begin);
        vma_update_prot(new_vma1, prot);

        struct libos_vma* next = _get_next_vma(vma);

        avl_tree_insert(&vma_tree, &new_vma1->tree_node);

        if (end < new_vma1->end) {
            struct libos_vma* new_vma2 = *new_vma_ptr2;
            *new_vma_ptr2 = NULL;

            split_vma(new_vma1, new_vma2, end);
            vma_update_prot(new_vma2, vma->prot);

            avl_tree_insert(&vma_tree, &new_vma2->tree_node);

            return 0;
        }

        /* Error checking at the begining ensures we always have the next node. */
        assert(next);
        vma = next;
    }

    while (vma->end <= end) {
        vma_update_prot(vma, prot);

#ifdef DEBUG
        struct libos_vma* prev = vma;
#endif
        vma = _get_next_vma(vma);
        if (!vma) {
            /* We've reached the very last vma. */
            assert(prev->end == end);
            return 0;
        }
    }

    if (end <= vma->begin) {
        return 0;
    }

    struct libos_vma* new_vma2 = *new_vma_ptr2;
    *new_vma_ptr2 = NULL;

    split_vma(vma, new_vma2, end);
    vma_update_prot(vma, prot);

    avl_tree_insert(&vma_tree, &new_vma2->tree_node);

    return 0;
}

int bkeep_mprotect(void* addr, size_t length, int prot, bool is_internal) {
    if (!length || !IS_ALLOC_ALIGNED(length) || !IS_ALLOC_ALIGNED_PTR(addr)) {
        return -EINVAL;
    }

    struct libos_vma* vma1 = alloc_vma();
    if (!vma1) {
        return -ENOMEM;
    }
    struct libos_vma* vma2 = alloc_vma();
    if (!vma2) {
        free_vma(vma1);
        return -ENOMEM;
    }

    vma_rwlock_write_lock();
    int ret = _vma_bkeep_change((uintptr_t)addr, (uintptr_t)addr + length, prot, is_internal, &vma1,
                                &vma2);
    vma_rwlock_write_unlock();

    if (vma1) {
        free_vma(vma1);
    }
    if (vma2) {
        free_vma(vma2);
    }

    return ret;
}

/* TODO consider:
 * maybe it's worth to keep another tree, complementary to `vma_tree`, that would hold free areas.
 * It would give O(logn) unmapped lookup, which now is O(n) in the worst case, but it would also
 * double the memory usage of this subsystem and add some complexity.
 * Another idea is to merge adjacent vmas, that are not backed by any file and have the same prot
 * and flags (the question is whether that happens often). */
/* This function allocates at most 1 vma. If in the future it uses more, `_vma_malloc` should be
 * updated as well. */
int bkeep_mmap_any_in_range(void* _bottom_addr, void* _top_addr, size_t length, int prot, int flags,
                            struct libos_handle* file, uint64_t offset, const char* comment,
                            void** ret_val_ptr) {
    assert(_bottom_addr < _top_addr);
    assert((g_pal_public_state->memory_address_start <= _bottom_addr
               && _top_addr <= g_pal_public_state->memory_address_end)
           || (g_pal_public_state->shared_address_start <= _bottom_addr
               && _top_addr <= g_pal_public_state->shared_address_end));

    if (!length || !IS_ALLOC_ALIGNED(length)) {
        return -EINVAL;
    }
    if (!IS_ALLOC_ALIGNED_PTR(_bottom_addr) || !IS_ALLOC_ALIGNED_PTR(_top_addr)) {
        return -EINVAL;
    }

    uintptr_t top_addr    = (uintptr_t)_top_addr;
    uintptr_t bottom_addr = (uintptr_t)_bottom_addr;
    int ret = 0;
    uintptr_t ret_val = 0;

    if (!g_received_user_memory && flags & VMA_INTERNAL) {
        /* Early LibOS init code must allocate memory only in
         * `[early_libos_mem_range_start; early_libos_mem_range_end)` range, not to overlap memory
         * that will be restored during checkpointing. */
        if (top_addr <= g_pal_public_state->early_libos_mem_range_start
                || g_pal_public_state->early_libos_mem_range_end <= bottom_addr) {
            /* Ranges do not overlap. */
            return -ENOMEM;
        }
        bottom_addr = MAX(bottom_addr, g_pal_public_state->early_libos_mem_range_start);
        top_addr = MIN(top_addr, g_pal_public_state->early_libos_mem_range_end);
        assert(bottom_addr < top_addr);
    }

#ifdef MAP_32BIT /* x86_64-specific */
    if (flags & MAP_32BIT) {
        /* Only consider first 2 gigabytes. */
        top_addr = MIN(top_addr, 1ul << 31);
        if (bottom_addr >= top_addr) {
            return -ENOMEM;
        }
    }
#endif

    struct libos_vma* new_vma = alloc_vma();
    if (!new_vma) {
        return -ENOMEM;
    }
    new_vma->prot  = prot;
    new_vma->flags = filter_saved_flags(flags) | ((file && (prot & PROT_WRITE)) ? VMA_TAINTED : 0);
    new_vma->file  = file;
    if (new_vma->file) {
        get_handle(new_vma->file);
        if (new_vma->file->inode)
            (void)__atomic_add_fetch(&new_vma->file->inode->num_mmapped, 1, __ATOMIC_RELAXED);
    }
    new_vma->offset = file ? offset : 0;
    copy_comment(new_vma, comment ?: "");

    vma_rwlock_write_lock();

    struct libos_vma* vma = _lookup_vma(top_addr);
    uintptr_t max_addr;
    if (!vma) {
        vma = _get_last_vma();
        max_addr = top_addr;
    } else {
        max_addr = MIN(top_addr, vma->begin);
        vma = _get_prev_vma(vma);
    }
    assert(!vma || vma->end <= max_addr);

    while (vma && bottom_addr <= vma->end) {
        assert(vma->end <= max_addr);
        if (max_addr - vma->end >= length) {
            goto out_found;
        }

        max_addr = vma->begin;
        vma = _get_prev_vma(vma);
    }

    if (!(bottom_addr <= max_addr && max_addr - bottom_addr >= length)) {
        ret = -ENOMEM;
        goto out;
    }

out_found:
    new_vma->end   = max_addr;
    new_vma->begin = new_vma->end - length;

    /* valid_end is potentially incorrect now (if there is a file-backed mapping with a part that
     * exceeds the file); it should be updated in the mmap syscall (for file-backed mappings) */
    new_vma->valid_end = max_addr;

    avl_tree_insert(&vma_tree, &new_vma->tree_node);
    total_memory_size_add(new_vma->end - new_vma->begin);

    ret_val = new_vma->begin;
    new_vma = NULL;

out:
    vma_rwlock_write_unlock();
    if (new_vma) {
        free_vma(new_vma);
    }
    if (ret >= 0) {
        *ret_val_ptr = (void*)ret_val;
    }
    return ret;
}

int bkeep_mmap_any(size_t length, int prot, int flags, struct libos_handle* file, uint64_t offset,
                   const char* comment, void** ret_val_ptr) {
    return bkeep_mmap_any_in_range(g_pal_public_state->memory_address_start,
                                   g_pal_public_state->memory_address_end,
                                   length, prot, flags, file, offset, comment, ret_val_ptr);
}

int bkeep_mmap_any_aslr(size_t length, int prot, int flags, struct libos_handle* file,
                        uint64_t offset, const char* comment, void** ret_val_ptr) {
    int ret;
    ret = bkeep_mmap_any_in_range(g_pal_public_state->memory_address_start, g_aslr_addr_top, length,
                                  prot, flags, file, offset, comment, ret_val_ptr);
    if (ret >= 0) {
        return ret;
    }

    return bkeep_mmap_any(length, prot, flags, file, offset, comment, ret_val_ptr);
}

int bkeep_vma_update_valid_length(void* begin_addr, size_t valid_length) {
    int ret;

    vma_rwlock_write_lock();
    struct libos_vma* vma = _lookup_vma((uintptr_t)begin_addr);
    if (!vma || !is_addr_in_vma((uintptr_t)begin_addr, vma)) {
        ret = -ENOENT;
        goto out;
    }

    if (vma->begin != (uintptr_t)begin_addr || valid_length > vma->end - vma->begin) {
        ret = -EINVAL;
        goto out;
    }

    vma->valid_end = vma->begin + valid_length;
    ret = 0;
out:
    vma_rwlock_write_unlock();
    return ret;
}

static int pal_mem_bkeep_alloc(size_t size, uintptr_t* out_addr) {
    void* addr;
    int ret = bkeep_mmap_any(size, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | VMA_INTERNAL, /*file=*/NULL,
                             /*offset=*/0, "pal internal memory", &addr);
    if (ret < 0) {
        return ret;
    }
    *out_addr = (uintptr_t)addr;
    return 0;
}

static int pal_mem_bkeep_free(uintptr_t addr, size_t size) {
    void* tmp_vma;
    int ret = bkeep_munmap((void*)addr, size, /*is_internal=*/true, &tmp_vma);
    if (ret < 0) {
        return ret;
    }
    /* Remove the temporary VMA immediately - PAL already freed the memory. */
    bkeep_remove_tmp_vma(tmp_vma);
    return 0;
}

static void dump_vma(struct libos_vma_info* vma_info, struct libos_vma* vma) {
    vma_info->addr         = (void*)vma->begin;
    vma_info->length       = vma->end - vma->begin;
    vma_info->valid_length = vma->valid_end - vma->begin;
    vma_info->prot         = vma->prot;
    vma_info->flags        = vma->flags;
    vma_info->file_offset  = vma->offset;
    vma_info->file         = vma->file;
    if (vma_info->file) {
        get_handle(vma_info->file);
    }
    static_assert(sizeof(vma_info->comment) == sizeof(vma->comment), "Comments sizes do not match");
    memcpy(vma_info->comment, vma->comment, sizeof(vma_info->comment));
}

int lookup_vma(void* addr, struct libos_vma_info* vma_info) {
    assert(vma_info);
    int ret = 0;

    vma_rwlock_read_lock();
    struct libos_vma* vma = _lookup_vma((uintptr_t)addr);
    if (!vma || !is_addr_in_vma((uintptr_t)addr, vma)) {
        ret = -ENOENT;
        goto out;
    }

    dump_vma(vma_info, vma);

out:
    vma_rwlock_read_unlock();
    return ret;
}

struct adj_visitor_ctx {
    int prot;
    bool is_ok;
};

static bool adj_visitor(struct libos_vma* vma, void* visitor_arg) {
    struct adj_visitor_ctx* ctx = visitor_arg;
    bool is_ok = !(vma->flags & (VMA_INTERNAL | VMA_UNMAPPED));
    is_ok &= (vma->prot & ctx->prot) == ctx->prot;
    ctx->is_ok &= is_ok;
    return is_ok;
}

bool is_in_adjacent_user_vmas(const void* addr, size_t length, int prot) {
    uintptr_t begin = (uintptr_t)addr;
    uintptr_t end = begin + length;
    assert(begin <= end);

    struct adj_visitor_ctx ctx = {
        .prot = prot,
        .is_ok = true,
    };

    vma_rwlock_read_lock();
    bool is_continuous = _traverse_vmas_in_range(begin, end, /*use_only_valid_part=*/true,
                                                 adj_visitor, &ctx);
    vma_rwlock_read_unlock();

    return is_continuous && ctx.is_ok;
}

static size_t dump_vmas_with_buf(struct libos_vma_info* infos, size_t max_count,
                                 uintptr_t begin, uintptr_t end,
                                 bool (*vma_filter)(struct libos_vma* vma, void* arg), void* arg) {
    size_t size = 0;
    struct libos_vma_info* vma_info = infos;

    vma_rwlock_read_lock();
    struct libos_vma* vma;

    for (vma = _lookup_vma(begin); vma && vma->begin < end; vma = _get_next_vma(vma)) {
        if (!vma_filter(vma, arg))
            continue;
        if (size < max_count) {
            dump_vma(vma_info, vma);
            vma_info++;
        }
        size++;
    }

    vma_rwlock_read_unlock();

    return size;
}

static int dump_vmas(struct libos_vma_info** out_infos, size_t* out_count,
                     uintptr_t begin, uintptr_t end,
                     bool (*vma_filter)(struct libos_vma* vma, void* arg), void* arg) {
    size_t count = DEFAULT_VMA_COUNT;

    while (true) {
        struct libos_vma_info* vmas = calloc(count, sizeof(*vmas));
        if (!vmas) {
            return -ENOMEM;
        }

        size_t needed_count = dump_vmas_with_buf(vmas, count, begin, end, vma_filter, arg);
        if (needed_count <= count) {
            *out_infos = vmas;
            *out_count = needed_count;
            return 0;
        }

        free_vma_info_array(vmas, count);
        count = needed_count;
    }
}

static bool vma_filter_all(struct libos_vma* vma, void* arg) {
    assert(vma_rwlock_is_read_or_write_locked());
    __UNUSED(arg);

    return !(vma->flags & VMA_INTERNAL);
}

static bool vma_filter_exclude_unmapped(struct libos_vma* vma, void* arg) {
    assert(vma_rwlock_is_read_or_write_locked());
    __UNUSED(arg);

    return !(vma->flags & (VMA_INTERNAL | VMA_UNMAPPED));
}

int dump_vmas_in_range(uintptr_t begin, uintptr_t end, bool include_unmapped,
                       struct libos_vma_info** out_infos, size_t* out_count) {
    return dump_vmas(out_infos, out_count, begin, end,
                     include_unmapped ? vma_filter_all : vma_filter_exclude_unmapped,
                     /*arg=*/NULL);
}

int dump_all_vmas(bool include_unmapped, struct libos_vma_info** out_infos, size_t* out_count) {
    return dump_vmas_in_range(/*begin=*/0, /*end=*/UINTPTR_MAX, include_unmapped, out_infos,
                              out_count);
}

void free_vma_info_array(struct libos_vma_info* vma_infos, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (vma_infos[i].file) {
            put_handle(vma_infos[i].file);
        }
    }

    free(vma_infos);
}

struct madvise_dontneed_ctx {
    uintptr_t begin;
    uintptr_t end;
    int error;
};

static bool madvise_dontneed_visitor(struct libos_vma* vma, void* visitor_arg) {
    struct madvise_dontneed_ctx* ctx = (struct madvise_dontneed_ctx*)visitor_arg;

    if (vma->flags & (VMA_UNMAPPED | VMA_INTERNAL)) {
        ctx->error = -EINVAL;
        return false;
    }

    if (vma->file) {
        if (vma->flags & VMA_TAINTED) {
            /* Resetting writable file-backed mappings is not yet implemented. */
            ctx->error = -ENOSYS;
            return false;
        }
        /* MADV_DONTNEED resets file-based mappings to the original state, which is a no-op for
         * non-tainted mappings. */
        return true;
    }

    uintptr_t zero_start = MAX(ctx->begin, vma->begin);
    uintptr_t zero_end = MIN(ctx->end, vma->valid_end);

    pal_prot_flags_t pal_prot = LINUX_PROT_TO_PAL(vma->prot, vma->flags);
    pal_prot_flags_t pal_prot_writable = pal_prot | PAL_PROT_WRITE;

    if (pal_prot != pal_prot_writable) {
        /* make the area writable so that it can be memset-to-zero */
        int ret = PalVirtualMemoryProtect((void*)zero_start, zero_end - zero_start,
                                          pal_prot_writable);
        if (ret < 0) {
            ctx->error = pal_to_unix_errno(ret);
            return false;
        }
    }

    memset((void*)zero_start, 0, zero_end - zero_start);

    if (pal_prot != pal_prot_writable) {
        /* the area was made writable above; restore the original permissions */
        int ret = PalVirtualMemoryProtect((void*)zero_start, zero_end - zero_start, pal_prot);
        if (ret < 0) {
            log_error("restoring original permissions failed: %s", pal_strerror(ret));
            BUG();
        }
    }
    return true;
}

int madvise_dontneed_range(uintptr_t begin, uintptr_t end) {
    struct madvise_dontneed_ctx ctx = {
        .begin = begin,
        .end = end,
        .error = 0,
    };

    vma_rwlock_read_lock();
    bool is_continuous = _traverse_vmas_in_range(begin, end, /*use_only_valid_part=*/false,
                                                 madvise_dontneed_visitor, &ctx);
    vma_rwlock_read_unlock();

    if (!is_continuous)
        return -ENOMEM;
    return ctx.error;
}

static bool vma_filter_needs_reload(struct libos_vma* vma, void* arg) {
    assert(vma_rwlock_is_read_or_write_locked());

    struct libos_handle* hdl = arg;
    assert(hdl && hdl->inode); /* guaranteed to have inode because invoked from `write` callback */

    if (vma->flags & (VMA_UNMAPPED | VMA_INTERNAL | MAP_ANONYMOUS | MAP_PRIVATE))
        return false;

    assert(vma->file); /* check above filtered out non-file-backed mappings */

    if (!vma->file->inode || vma->file->inode != hdl->inode)
        return false;

    if (!vma->file->fs || !vma->file->fs->fs_ops || !vma->file->fs->fs_ops->read)
        return false;

    if (!(vma->file->acc_mode & MAY_READ))
        return false;

    return true;
}

static int reload_vma(struct libos_vma_info* vma_info) {
    int ret;
    struct libos_handle* file = vma_info->file;
    assert(file && file->fs && file->fs->fs_ops && file->fs->fs_ops->read);

    /* NOTE: Unfortunately there's a data race here: the memory can be unmapped, or remapped, by
     * another thread by the time we get to `read`. */
    uintptr_t read_begin = (uintptr_t)vma_info->addr;
    uintptr_t read_end = (uintptr_t)vma_info->addr + vma_info->valid_length;
    assert(IS_ALLOC_ALIGNED(read_begin));
    assert(IS_ALLOC_ALIGNED(read_end));

    size_t size = read_end - read_begin;
    size_t read = 0;
    file_off_t pos = (file_off_t)vma_info->file_offset;
    pal_prot_flags_t pal_prot = LINUX_PROT_TO_PAL(vma_info->prot, vma_info->flags);
    pal_prot_flags_t pal_prot_writable = pal_prot | PAL_PROT_WRITE;

    if (pal_prot != pal_prot_writable) {
        /* make the area writable so that it can be reloaded */
        ret = PalVirtualMemoryProtect((void*)read_begin, size, pal_prot_writable);
        if (ret < 0)
            return pal_to_unix_errno(ret);
    }

    while (read < size) {
        size_t to_read = size - read;
        ssize_t count = file->fs->fs_ops->read(file, (void*)(read_begin + read), to_read, &pos);
        if (count < 0) {
            if (count == -EINTR || count == -EAGAIN) {
                continue;
            }
            ret = count;
            goto out;
        } else if (count == 0) {
            /* it's possible that the underlying file contents do not cover the whole VMA region */
            break;
        }
        assert((size_t)count <= to_read);
        read += count;
    }

    ret = 0;
out:
    if (pal_prot != pal_prot_writable) {
        /* the area was made writable above; restore the original permissions */
        int protect_ret = PalVirtualMemoryProtect((void*)read_begin, size, pal_prot);
        if (protect_ret < 0) {
            log_error("restore original permissions failed: %s", pal_strerror(protect_ret));
            BUG();
        }
    }

    return ret;
}

/* This helper function is to reload the VMA contents of a given file handle on `write`.
 *
 * NOTE: the `write` callback can be invoked from multiple paths (syscalls like `munmap()`,
 * `mmap(MAP_FIXED_NOREPLACE)` and `msync()`) via the `msync` callback, so blindly reloading the VMA
 * contents on e.g. `munmap()` can be inefficient (but unmapping file-backed memory regions
 * shouldn't be a frequent operation). */
int reload_mmaped_from_file_handle(struct libos_handle* hdl) {
    struct libos_vma_info* vma_infos;
    size_t count;

    int ret = dump_vmas(&vma_infos, &count, /*begin=*/0, /*end=*/UINTPTR_MAX,
                        vma_filter_needs_reload, hdl);
    if (ret < 0)
        return ret;

    for (size_t i = 0; i < count; i++) {
        ret = reload_vma(&vma_infos[i]);
        if (ret < 0)
            goto out;
    }

    ret = 0;
out:
    free_vma_info_array(vma_infos, count);
    return ret;
}

struct vma_update_valid_end_args {
    struct libos_handle* hdl;
    size_t file_size;
};

/* returns whether prot_refresh_vma() must be applied on a VMA */
static bool vma_update_valid_end(struct libos_vma* vma, void* _args) {
    assert(vma_rwlock_is_read_or_write_locked());

    struct vma_update_valid_end_args* args = _args;

    /* guaranteed to have inode because invoked from `write` or `truncate` callback */
    assert(args->hdl && args->hdl->inode);

    if (vma->flags & (VMA_UNMAPPED | VMA_INTERNAL | MAP_ANONYMOUS))
        return false;

    assert(vma->file); /* check above filtered out non-file-backed mappings */

    if (!vma->file->inode || vma->file->inode != args->hdl->inode)
        return false;

    size_t valid_length;
    if (args->file_size >= vma->offset) {
        size_t vma_length = vma->end - vma->begin;
        if (args->file_size - vma->offset > vma_length) {
            /* file size exceeds the mmapped part in VMA, the whole VMA is accessible */
            valid_length = vma_length;
        } else {
            /* file size is smaller than the mmapped part in VMA, only part of VMA is accessible */
            valid_length = args->file_size - vma->offset;
        }
    } else {
        /* file got smaller than the offset from which VMA is mapped, all VMA is inaccessible */
        valid_length = 0;
    }
    valid_length = ALLOC_ALIGN_UP(valid_length);

    vma->valid_end = vma->begin + valid_length;
    assert(vma->valid_end <= vma->end);

    return true;
}

static int prot_refresh_vma(struct libos_vma_info* vma_info) {
    int ret;

    /* NOTE: Unfortunately there's a data race here: the memory can be unmapped, or remapped, by
     * another thread by the time we get to `PalVirtualMemoryProtect`. */
    if (vma_info->valid_length) {
        ret = PalVirtualMemoryProtect(vma_info->addr, vma_info->valid_length,
                                      LINUX_PROT_TO_PAL(vma_info->prot, vma_info->flags));
        if (ret < 0)
            BUG();
    }
    if (vma_info->length - vma_info->valid_length) {
        ret = PalVirtualMemoryProtect(vma_info->addr + vma_info->valid_length,
                                      vma_info->length - vma_info->valid_length, /*prot=*/0);
        if (ret < 0)
            BUG();
    }

    return 0;
}

/* This helper function is to refresh access protections on the VMA pages of a given file handle on
 * file-extend operations (`write` and `ftruncate`). */
int prot_refresh_mmaped_from_file_handle(struct libos_handle* hdl, size_t file_size) {
    struct libos_vma_info* vma_infos;
    size_t count;

    struct vma_update_valid_end_args args = { .hdl = hdl, .file_size = file_size };

    int ret = dump_vmas(&vma_infos, &count, /*begin=*/0, /*end=*/UINTPTR_MAX,
                        vma_update_valid_end, &args);
    if (ret < 0)
        return ret;

    for (size_t i = 0; i < count; i++) {
        ret = prot_refresh_vma(&vma_infos[i]);
        if (ret < 0)
            goto out;
    }

    ret = 0;
out:
    free_vma_info_array(vma_infos, count);
    return ret;
}

static bool vma_filter_needs_msync(struct libos_vma* vma, void* arg) {
    assert(vma_rwlock_is_read_or_write_locked());

    struct libos_handle* hdl = arg;

    if (vma->flags & (VMA_UNMAPPED | VMA_INTERNAL | MAP_ANONYMOUS | MAP_PRIVATE))
        return false;

    assert(vma->file);

    if (hdl && vma->file != hdl)
        return false;

    if (!vma->file->fs || !vma->file->fs->fs_ops || !vma->file->fs->fs_ops->msync)
        return false;

    if (!(vma->file->acc_mode & MAY_WRITE))
        return false;

    return true;
}

static int msync_all(uintptr_t begin, uintptr_t end, struct libos_handle* hdl) {
    assert(IS_ALLOC_ALIGNED(begin));
    assert(end == UINTPTR_MAX || IS_ALLOC_ALIGNED(end));

    struct libos_vma_info* vma_infos;
    size_t count;

    int ret = dump_vmas(&vma_infos, &count, begin, end, vma_filter_needs_msync, hdl);
    if (ret < 0)
        return ret;

    for (size_t i = 0; i < count; i++) {
        struct libos_vma_info* vma_info = &vma_infos[i];

        struct libos_handle* file = vma_info->file;
        assert(file && file->fs && file->fs->fs_ops && file->fs->fs_ops->msync);

        /* NOTE: Unfortunately there's a data race here: the memory can be unmapped, or remapped, by
         * another thread by the time we get to `msync`. */
        if (!vma_info->valid_length)
            continue;

        uintptr_t msync_begin = MAX(begin, (uintptr_t)vma_info->addr);
        uintptr_t msync_end = MIN(end, (uintptr_t)vma_info->addr + vma_info->valid_length);
        assert(IS_ALLOC_ALIGNED(msync_begin));
        assert(IS_ALLOC_ALIGNED(msync_end));

        ret = file->fs->fs_ops->msync(file, (void*)msync_begin, msync_end - msync_begin,
                                      vma_info->prot, vma_info->flags, vma_info->file_offset);
        if (ret < 0)
            goto out;
    }

    ret = 0;
out:
    free_vma_info_array(vma_infos, count);
    return ret;
}

int msync_range(uintptr_t begin, uintptr_t end) {
    return msync_all(begin, end, /*hdl=*/NULL);
}

int msync_handle(struct libos_handle* hdl) {
    return msync_all(/*begin=*/0, /*end=*/UINTPTR_MAX, hdl);
}

BEGIN_CP_FUNC(vma) {
    __UNUSED(size);
    assert(size == sizeof(struct libos_vma_info));

    struct libos_vma_info* vma = (struct libos_vma_info*)obj;
    struct libos_vma_info* new_vma = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(*vma));
        ADD_TO_CP_MAP(obj, off);

        new_vma = (struct libos_vma_info*)(base + off);
        *new_vma = *vma;

        if (vma->file)
            DO_CP(handle, vma->file, &new_vma->file);

        /* by default, file-backed memory (if shared and/or untainted) is re-mapped in child */
        bool remap_from_file = !(vma->flags & VMA_UNMAPPED) && vma->file;

        /*
         * Check whether we need to checkpoint memory this vma bookkeeps: it should be mapped and it
         * should be either anonymous memory or tainted private file-backed memory. In other cases,
         * we re-map this vma during checkpoint restore in child (see function below).
         *
         * FIXME: In case of anonymous memory, we always checkpoint memory and ignore MAP_SHARED
         *        flag. VMA content in parent and child may diverge.
         */
        if (!(vma->flags & VMA_UNMAPPED) && (!vma->file ||
                    (vma->flags & (VMA_TAINTED | MAP_PRIVATE)) == (VMA_TAINTED | MAP_PRIVATE))) {
            remap_from_file = false;

            if (!vma->file) {
                /* Send anonymous memory region. */
                struct libos_mem_entry* mem;
                assert(vma->valid_length == vma->length);
                DO_CP_SIZE(memory, vma->addr, vma->valid_length, &mem);
                mem->prot = LINUX_PROT_TO_PAL(vma->prot, /*map_flags=*/0);
            } else {
                /*
                 * Send file-backed memory region.
                 *
                 * Access beyond the last file-backed page (reflected via vma->valid_length) should
                 * cause SIGBUS. So we send only those memory contents of VMA that are backed by the
                 * file, round up to pages. Rest of VMA memory region will be inaccessible in the
                 * child process.
                 *
                 * It may happen that the whole file-backed memory is beyond the file size (e.g.,
                 * the file was truncated after the memory was allocated). In this case we consider
                 * the whole memory region to be inaccessible in the child process.
                 */
                assert(vma->valid_length <= vma->length);
                if (vma->valid_length > 0) {
                    struct libos_mem_entry* mem;
                    DO_CP_SIZE(memory, vma->addr, vma->valid_length, &mem);
                    mem->prot = LINUX_PROT_TO_PAL(vma->prot, /*map_flags=*/0);
                }
            }
        }

        /*
         * Add a dummy memory region to the checkpoint. The content of this memory won't be
         * actually sent, just this metadata. See `receive_memory_on_stream` for more info.
         * This must come after all other `DO_CP_SIZE(memory, ...)` in this function, to maintain
         * proper ordering (memory entries are prepended to the beginning of a list in
         * the checkpoint).
         *
         * XXX: we could go with an alternative (less hacky?) approach - instead of dummy memory
         * regions we could add a dedicated list of VMAs to restore before rest of the checkpoint.
         */
        struct libos_mem_entry* mem;
        DO_CP_SIZE(memory, vma->addr, vma->length, &mem);
        mem->dummy = true;

        ADD_CP_FUNC_ENTRY(off);
        ADD_CP_ENTRY(ADDR, (uintptr_t)remap_from_file);
    } else {
        new_vma = (struct libos_vma_info*)(base + off);
    }

    if (objp)
        *objp = (void*)new_vma;
}
END_CP_FUNC(vma)

BEGIN_RS_FUNC(vma) {
    struct libos_vma_info* vma = (void*)(base + GET_CP_FUNC_ENTRY());
    bool remap_from_file = (bool)GET_CP_ENTRY(ADDR);
    CP_REBASE(vma->file);

    int ret = bkeep_mmap_fixed(vma->addr, vma->length, vma->prot, vma->flags | MAP_FIXED, vma->file,
                               vma->file_offset, vma->comment);
    if (ret < 0)
        return ret;

    size_t valid_length = vma->valid_length;

    if (!(vma->flags & VMA_UNMAPPED) && vma->file) {
        struct libos_fs* fs = vma->file->fs;
        get_handle(vma->file);

        if (remap_from_file) {
            /* Parent did not send file-backed memory region, need to mmap file contents. */
            if (!fs || !fs->fs_ops || !fs->fs_ops->mmap)
                return -EINVAL;

            ret = fs->fs_ops->mmap(vma->file, vma->addr, vma->length, vma->prot,
                                   vma->flags | MAP_FIXED, vma->file_offset, &valid_length);
            if (ret < 0)
                return ret;
        }
    }

    assert(valid_length <= vma->length);
    ret = bkeep_vma_update_valid_length(vma->addr, vma->valid_length);
    if (ret < 0)
        return ret;
}
END_RS_FUNC(vma)

BEGIN_CP_FUNC(all_vmas) {
    __UNUSED(obj);
    __UNUSED(size);
    __UNUSED(objp);
    size_t count;
    struct libos_vma_info* vmas;
    int ret = dump_all_vmas(/*include_unmapped=*/true, &vmas, &count);
    if (ret < 0) {
        return ret;
    }
    if (count == 0) {
        free_vma_info_array(vmas, count);
        return -ENOMEM;
    }

    /* Checkpoint VMAs in descending order - checkpointing code requires it. See
     * `create_mem_ranges_array` for details. */
    for (struct libos_vma_info* vma = &vmas[count - 1]; true; vma--) {
        DO_CP(vma, vma, NULL);
        if (vma == vmas)
            break;
    }

    free_vma_info_array(vmas, count);
}
END_CP_FUNC_NO_RS(all_vmas)


static void debug_print_vma(struct libos_vma* vma) {
    log_always(
        "[all=0x%lx-0x%lx; valid=0x%lx-0x%lx] prot=0x%x flags=0x%x%s%s file=%p (offset=%ld)%s%s",
        vma->begin, vma->end, vma->begin, vma->valid_end,
        vma->prot,
        vma->flags & ~(VMA_INTERNAL | VMA_UNMAPPED),
        vma->flags & VMA_INTERNAL ? "(INTERNAL " : "(",
        vma->flags & VMA_UNMAPPED ? "UNMAPPED)" : ")",
        vma->file,
        vma->offset,
        vma->comment[0] ? " comment=" : "",
        vma->comment[0] ? vma->comment : "");
}

void debug_print_all_vmas(void) {
    vma_rwlock_read_lock();

    struct libos_vma* vma = _get_first_vma();
    while (vma) {
        debug_print_vma(vma);
        vma = _get_next_vma(vma);
    }

    vma_rwlock_read_unlock();
}

size_t get_peak_memory_usage(void) {
    return __atomic_load_n(&g_peak_total_memory_size, __ATOMIC_RELAXED);
}

size_t get_total_memory_usage(void) {
    vma_rwlock_read_lock();
    size_t total_memory_size = g_total_memory_size;
    vma_rwlock_read_unlock();
    /* This memory accounting is just a simple heuristic, which does not account swap, reserved
     * memory, unmapped VMAs etc. */
    return MIN(total_memory_size, g_pal_public_state->mem_total);
}
