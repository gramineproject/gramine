/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <asm/errno.h>
#include <limits.h>
#include <linux/futex.h>
#include <stdbool.h>

#include "asan.h"
#include "assert.h"
#include "enclave_api.h"
#include "enclave_ocalls.h"
#include "pal.h"
#include "pal_internal.h"
#include "pal_linux_error.h"
#include "spinlock.h"

static uintptr_t g_untrusted_page_next_entry = 0;
static spinlock_t g_untrusted_page_lock = INIT_SPINLOCK_UNLOCKED;

/* Allocate 8-byte ints instead of classic 4-byte ints for the futex word. This is to mitigate
 * CVE-2022-21166 (INTEL-SA-00615) which requires all writes to untrusted memory from within the
 * enclave to be done in 8-byte chunks aligned to 8-bytes boundary. Since the 8-byte ints returned
 * are guaranteed to be 8-byte aligned, we don't need to care about the alignment later. */
static int alloc_untrusted_futex_word(uint64_t** out_addr) {
    spinlock_lock(&g_untrusted_page_lock);
    static_assert(PAGE_SIZE % sizeof(uint64_t) == 0, "required by the check below");
    if (g_untrusted_page_next_entry % PAGE_SIZE == 0) {
        void* untrusted_page;
        int ret = ocall_mmap_untrusted(&untrusted_page, PAGE_SIZE, PROT_READ | PROT_WRITE,
                                       MAP_ANONYMOUS | MAP_PRIVATE, /*fd=*/-1, /*offset=*/0);
        if (ret < 0) {
            spinlock_unlock(&g_untrusted_page_lock);
            return unix_to_pal_error(ret);
        }
#ifdef ASAN
        asan_poison_region((uintptr_t)untrusted_page, PAGE_SIZE, ASAN_POISON_HEAP_LEFT_REDZONE);
#endif

        g_untrusted_page_next_entry = (uintptr_t)untrusted_page;
        /* Reserve space for users counter. */
        g_untrusted_page_next_entry += sizeof(uint64_t);
#ifdef ASAN
        asan_unpoison_region((uintptr_t)untrusted_page, sizeof(uint64_t));
#endif
    }

    uintptr_t addr = g_untrusted_page_next_entry;
    g_untrusted_page_next_entry += sizeof(uint64_t);
#ifdef ASAN
    /* TODO: uncomment the following code once the painful mitigation for CVE-2022-21166
     * (INTEL-SA-00615) can be removed in the future. This is a reminder that ASAN requires 8-byte
     * aligned addresses, so we need to pad it using classic 4-byte ints for the futex word. */
    /* g_untrusted_page_next_entry += sizeof(uint32_t); */
    asan_unpoison_region(addr, sizeof(uint64_t));
#endif

    /* This counter is only used to decide when to free the page - untrusted host can do this anyway
     * at any point, so we can keep the counter in untrusted memory. */
    uint64_t* untrusted_users_counter_ptr = (uint64_t*)ALIGN_DOWN(addr, PAGE_SIZE);
    uint64_t users_counter = COPY_UNTRUSTED_VALUE(untrusted_users_counter_ptr);
    COPY_VALUE_TO_UNTRUSTED(untrusted_users_counter_ptr, users_counter + 1);
    spinlock_unlock(&g_untrusted_page_lock);

    *out_addr = (uint64_t*)addr;
    return 0;
}

static void free_untrusted_futex_word(uint64_t* addr) {
    uint64_t* untrusted_users_counter_ptr = (uint64_t*)ALIGN_DOWN((uintptr_t)addr, PAGE_SIZE);

    void* addr_to_munmap = NULL;
    spinlock_lock(&g_untrusted_page_lock);
    uint64_t users_counter = COPY_UNTRUSTED_VALUE(untrusted_users_counter_ptr);
    if (users_counter == 1) {
        /* Counter is at the begining of the page. */
        addr_to_munmap = untrusted_users_counter_ptr;
        if (ALIGN_DOWN(g_untrusted_page_next_entry, PAGE_SIZE) == (uintptr_t)addr_to_munmap) {
            g_untrusted_page_next_entry = 0;
        }
    } else {
        assert(users_counter);
        COPY_VALUE_TO_UNTRUSTED(untrusted_users_counter_ptr, users_counter - 1);
    }
#ifdef ASAN
    asan_poison_region((uintptr_t)addr, sizeof(uint64_t), ASAN_POISON_HEAP_LEFT_REDZONE);
#endif
    spinlock_unlock(&g_untrusted_page_lock);

    if (addr_to_munmap) {
#ifdef ASAN
        /* First 64 bits are for users counter - already not poisoned. */
        asan_unpoison_region((uintptr_t)addr_to_munmap + sizeof(uint64_t),
                             PAGE_SIZE - sizeof(uint64_t));
#endif
        int ret = ocall_munmap_untrusted(addr_to_munmap, PAGE_SIZE);
        if (ret < 0) {
            log_error("Failed to free untrusted page at %p: %s", addr_to_munmap,
                      unix_strerror(ret));
        }
    }
}

int _PalEventCreate(PAL_HANDLE* handle_ptr, bool init_signaled, bool auto_clear) {
    PAL_HANDLE handle = calloc(1, HANDLE_SIZE(event));
    if (!handle) {
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(handle, PAL_TYPE_EVENT);

    int ret = alloc_untrusted_futex_word(&handle->event.signaled_untrusted);
    if (ret < 0) {
        free(handle);
        return ret;
    }

    spinlock_init(&handle->event.lock);
    handle->event.waiters_cnt = 0;
    handle->event.signaled = init_signaled;
    handle->event.auto_clear = auto_clear;
    __atomic_store_n(handle->event.signaled_untrusted, init_signaled ? 1 : 0, __ATOMIC_RELEASE);

    *handle_ptr = handle;
    return 0;
}

void _PalEventSet(PAL_HANDLE handle) {
    spinlock_lock(&handle->event.lock);
    handle->event.signaled = true;
    __atomic_store_n(handle->event.signaled_untrusted, 1, __ATOMIC_RELEASE);
    bool need_wake = handle->event.waiters_cnt > 0;
    spinlock_unlock(&handle->event.lock);

    if (need_wake) {
        int ret = 0;
        do {
            /* We use 8-byte ints instead of classic 4-byte ints for futexes. This is to mitigate
             * CVE-2022-21166 (INTEL-SA-00615) which requires all writes to untrusted memory from
             * within the enclave to be done in 8-byte chunks aligned to 8-bytes boundary. We hence
             * cast this 8-byte int of the futex word to a 4-byte int here to be compatible with
             * futex() syscall signature. */
            ret = ocall_futex((uint32_t*)handle->event.signaled_untrusted, FUTEX_WAKE,
                              handle->event.auto_clear ? 1 : INT_MAX, /*timeout=*/NULL);
        } while (ret == -EINTR);
        /* This `FUTEX_WAKE` cannot really fail. Negative return value would mean malicious host,
         * but it could also report `0` here and not perform the wakeup, so the worst case scenario
         * is just a DoS, which we don't really care about. */
        assert(ret >= 0);
    }
}

void _PalEventClear(PAL_HANDLE handle) {
    spinlock_lock(&handle->event.lock);
    handle->event.signaled = false;
    __atomic_store_n(handle->event.signaled_untrusted, 0, __ATOMIC_RELEASE);
    spinlock_unlock(&handle->event.lock);
}

/* We use `handle->event.signaled` as the source of truth whether the event was signaled.
 * `handle->event.signaled_untrusted` acts only as a futex sleeping word. */
int _PalEventWait(PAL_HANDLE handle, uint64_t* timeout_us) {
    bool added_to_count = false;
    while (1) {
        spinlock_lock(&handle->event.lock);
        if (handle->event.signaled) {
            if (handle->event.auto_clear) {
                handle->event.signaled = false;
                __atomic_store_n(handle->event.signaled_untrusted, 0, __ATOMIC_RELEASE);
            }
            if (added_to_count) {
                handle->event.waiters_cnt--;
            }
            spinlock_unlock(&handle->event.lock);
            return 0;
        }

        if (!added_to_count) {
            handle->event.waiters_cnt++;
            added_to_count = true;
        }
        spinlock_unlock(&handle->event.lock);

        /* We use 8-byte ints instead of classic 4-byte ints for futexes. This is to mitigate
         * CVE-2022-21166 (INTEL-SA-00615) which requires all writes to untrusted memory from within
         * the enclave to be done in 8-byte chunks aligned to 8-bytes boundary. We hence cast this
         * 8-byte int of the futex word to a 4-byte int here to be compatible with futex() syscall
         * signature. */
        int ret = ocall_futex((uint32_t*)handle->event.signaled_untrusted, FUTEX_WAIT, 0,
                              timeout_us);
        if (ret < 0 && ret != -EAGAIN) {
            if (added_to_count) {
                spinlock_lock(&handle->event.lock);
                handle->event.waiters_cnt--;
                spinlock_unlock(&handle->event.lock);
            }
            return unix_to_pal_error(ret);
        }
    }
}

static void event_destroy(PAL_HANDLE handle) {
    assert(handle->hdr.type == PAL_TYPE_EVENT);

    free_untrusted_futex_word(handle->event.signaled_untrusted);
    free(handle);
}

struct handle_ops g_event_ops = {
    .destroy = event_destroy,
};
