/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include <asm/errno.h>
#include <asm/mman.h>

#include "debug_map.h"
#include "linux_utils.h"
#include "spinlock.h"

struct debug_map* _Atomic g_debug_map = NULL;

/* Lock for modifying g_debug_map on our end. Even though the list can be read by GDB at any time,
 * we need to prevent concurrent modification. */
static spinlock_t g_debug_map_lock = INIT_SPINLOCK_UNLOCKED;

static struct debug_map* debug_map_new(const char* name, void* addr) {
    struct debug_map* map;

    if (!(map = malloc(sizeof(*map))))
        return NULL;

    if (!(map->name = strdup(name))) {
        free(map);
        return NULL;
    }

    map->addr = addr;
    map->next = NULL;
    return map;
}

/* This function is hooked by our gdb integration script and should be left as is. */
__attribute__((__noinline__)) void debug_map_update_debugger(void) {
    __asm__ volatile(""); // Required in addition to __noinline__ to prevent deleting this function.
                          // See GCC docs.
}

int debug_map_add(const char* name, void* addr) {
    spinlock_lock(&g_debug_map_lock);

    struct debug_map* map = g_debug_map;
    while (map) {
        if (map->addr == addr) {
            bool name_matches = !strcmp(name, map->name);
            spinlock_unlock(&g_debug_map_lock);
            /* If the exact same map is already there, skip adding it and report success: this can
             * happen when we encounter two executable ranges for the same file. */
            return name_matches ? 0 : -EEXIST;
        }
        map = map->next;
    }

    map = debug_map_new(name, addr);
    if (!map) {
        spinlock_unlock(&g_debug_map_lock);
        return -ENOMEM;
    }

    map->next = g_debug_map;
    g_debug_map = map;

    spinlock_unlock(&g_debug_map_lock);

    debug_map_update_debugger();

    return 0;
}

int debug_map_remove(void* addr) {
    spinlock_lock(&g_debug_map_lock);

    struct debug_map* prev = NULL;
    struct debug_map* map = g_debug_map;
    while (map) {
        if (map->addr == addr)
            break;
        prev = map;
        map = map->next;
    }
    if (!map) {
        spinlock_unlock(&g_debug_map_lock);
        return -EINVAL;
    }
    if (prev) {
        prev->next = map->next;
    } else {
        g_debug_map = map->next;
    }

    spinlock_unlock(&g_debug_map_lock);

    debug_map_update_debugger();

    free(map->name);
    free(map);

    return 0;
}

/* Find a range that (likely) corresponds to a mapped executable file, and add it to debug maps. */
static int debug_map_init_callback(struct proc_maps_range* r, void* arg) {
    __UNUSED(arg);

    /* not executable */
    if (!(r->prot & PROT_EXEC))
        return 0;

    /* no name */
    if (!r->name)
        return 0;

    /* [vvar], [vdso] etc. */
    if (r->name[0] != '/')
        return 0;

    /* /dev/sgx etc. */
    if (strstartswith(r->name, "/dev/"))
        return 0;

    void* addr = (void*)(r->start - r->offset);
    return debug_map_add(r->name, addr);
}

int debug_map_init_from_proc_maps(void) {
    return parse_proc_maps("/proc/self/maps", debug_map_init_callback, /*arg=*/NULL);
}
