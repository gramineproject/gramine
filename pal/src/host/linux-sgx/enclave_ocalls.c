/*
 * This is for enclave to make ocalls to untrusted runtime.
 *
 * Most ocall implementations retry the host-level operations on -EINTR, except for a few ocalls
 * that are expected to be able to return -EINTR (read, write, recv, send, accept, connect, sleep,
 * futex). The -EINTR error happens when an async signal arrives from the host OS, with two
 * sub-cases: (a) signal arrives during a slow host-level syscall or (b) signal arrives during other
 * untrusted-PAL code execution. In both cases, the untrusted-PAL signal handler injects -EINTR and
 * forces an ocall return. To prevent ocalls from returning -EINTR to unsuspecting LibOS/user app,
 * here we retry a host-level syscall. In some cases, this may lead to FD leaks or incorrect
 * semantics (e.g., a retried open() syscall may have succeeded the first time, but a signal arrived
 * right-after this syscall and forced -EINTR, thus leaving an FD from the first try open and
 * leaking). See also `man 7 signal` and `sgx_exception.c: handle_async_signal()`.
 *
 * FIXME: Ideally, the untrusted-PAL signal handler must inspect the interrupted RIP and unwind/fix
 *        the untrusted state and decide whether to inject -EINTR or report success (e.g., if a
 *        signal arrives right-after an open() syscall, the signal handler must update ocall return
 *        values and report success instead of injecting -EINTR).
 */

#include <asm/errno.h>
#include <linux/futex.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>

#include "api.h"
#include "asan.h"
#include "cpu.h"
#include "enclave_ocalls.h"
#include "pal_internal.h"
#include "pal_ocall_types.h"
#include "pal_rpc_queue.h"
#include "sgx_attest.h"
#include "spinlock.h"

/* Check against this limit if the buffer to be allocated fits on the untrusted stack; if not,
 * buffer will be allocated on untrusted heap. Conservatively set this limit to 1/4 of the
 * actual stack size. Currently THREAD_STACK_SIZE = 2MB, so this limit is 512KB.
 * Note that the main thread is special in that it is handled by Linux, with the typical stack
 * size of 8MB. Thus, 512KB limit also works well for the main thread. */
#define MAX_UNTRUSTED_STACK_BUF (THREAD_STACK_SIZE / 4)

/* global pointer to a single untrusted queue, all accesses must be protected by g_rpc_queue->lock
 */
rpc_queue_t* g_rpc_queue = NULL;

static long sgx_exitless_ocall(uint64_t code, void* ocall_args) {
    /* perform OCALL with enclave exit if no RPC queue (i.e., no exitless); no need for atomics
     * because this pointer is set only once at enclave initialization */
    if (!g_rpc_queue)
        return sgx_ocall(code, ocall_args);

    /* allocate request in a new stack frame on OCALL stack; note that request's lock is used in
     * futex() and must be aligned to at least 4B */
    void* old_ustack = sgx_prepare_ustack();
    rpc_request_t* req = sgx_alloc_on_ustack_aligned(sizeof(*req), alignof(*req));
    if (!req) {
        sgx_reset_ustack(old_ustack);
        return -ENOMEM;
    }

    COPY_VALUE_TO_UNTRUSTED(&req->ocall_index, code);
    COPY_VALUE_TO_UNTRUSTED(&req->buffer, ocall_args);
    spinlock_init(&req->lock);

    /* grab the lock on this request (it is the responsibility of RPC thread to unlock it when
     * done); this always succeeds immediately since enclave thread is currently the only owner
     * of the lock */
    spinlock_lock(&req->lock);

    /* enqueue OCALL request into RPC queue; some RPC thread will dequeue it, issue a syscall
     * and, after syscall is finished, release the request's spinlock */
    bool enqueued = rpc_enqueue(g_rpc_queue, req);
    if (!enqueued) {
        /* no space in queue: all RPC threads are busy with outstanding ocalls; fallback to normal
         * syscall path with enclave exit */
        sgx_reset_ustack(old_ustack);
        return sgx_ocall(code, ocall_args);
    }

    /* wait till request processing is finished; try spinlock first */
    bool locked = spinlock_lock_timeout(&req->lock, RPC_SPINLOCK_TIMEOUT);

    /* at this point:
     * - either RPC thread is done with OCALL and released the request's spinlock,
     *   and our enclave thread grabbed lock but it doesn't matter at this point
     *   (OCALL is done, locked == true, no need to wait on futex)
     * - or OCALL is still pending and the request is still blocked on spinlock
     *   (OCALL is not done, locked == false, let's wait on futex) */

    if (!locked) {
        /* OCALL takes a lot of time, so fallback to waiting on a futex; at this point we exit
         * enclave to perform syscall; this code is based on Mutex 2 from Futexes are Tricky */
        uint32_t c = SPINLOCK_UNLOCKED;

        /* at this point can be a subtle data race: RPC thread is only now done with OCALL and
         * moved lock in UNLOCKED state; in this racey case, lock = UNLOCKED = 0 and we do not
         * wait on futex (note that enclave thread grabbed lock but it doesn't matter) */
        if (!spinlock_cmpxchg(&req->lock, &c, SPINLOCK_LOCKED_NO_WAITERS)) {
            /* allocate futex args on OCALL stack */
            struct ocall_futex* ocall_futex_args;

            ocall_futex_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_futex_args),
                                                           alignof(*ocall_futex_args));
            if (!ocall_futex_args) {
                sgx_reset_ustack(old_ustack);
                return -ENOMEM;
            }

            COPY_VALUE_TO_UNTRUSTED(&ocall_futex_args->futex, &req->lock.lock);
            COPY_VALUE_TO_UNTRUSTED(&ocall_futex_args->op, FUTEX_WAIT_PRIVATE);
            COPY_VALUE_TO_UNTRUSTED(&ocall_futex_args->timeout_us, (uint64_t)-1); /* never time out */

            do {
                /* at this point lock = LOCKED_*; before waiting on futex, need to move lock to
                 * LOCKED_WITH_WAITERS; note that check on cmpxchg of lock = UNLOCKED = 0 is for
                 * the same data race as above */
                if (c == SPINLOCK_LOCKED_WITH_WAITERS || /* shortcut: don't need to move lock state */
                    spinlock_cmpxchg(&req->lock, &c, SPINLOCK_LOCKED_WITH_WAITERS)) {
                    /* at this point, futex(wait) syscall expects lock to be in LOCKED_WITH_WAITERS
                     * set by enclave thread above; if RPC thread moved it back to UNLOCKED, futex()
                     * immediately returns */
                    COPY_VALUE_TO_UNTRUSTED(&ocall_futex_args->val, SPINLOCK_LOCKED_WITH_WAITERS);
                    int ret = sgx_ocall(OCALL_FUTEX, ocall_futex_args);
                    if (ret < 0 && ret != -EAGAIN) {
                        sgx_reset_ustack(old_ustack);
                        return -EPERM;
                    }
                }
                c = SPINLOCK_UNLOCKED;
            } while (!spinlock_cmpxchg(&req->lock, &c, SPINLOCK_LOCKED_WITH_WAITERS));
            /* while-loop is required for spurious futex wake-ups: our enclave thread must wait
             * until lock moves to UNLOCKED (note that enclave thread grabs lock but it doesn't
             * matter at this point) */
        }
    }

    sgx_reset_ustack(old_ustack);
    return COPY_UNTRUSTED_VALUE(&req->result);
}

__attribute_no_sanitize_address
noreturn void ocall_exit(int exitcode, int is_exitgroup) {
    struct ocall_exit* ocall_exit_args;

    sgx_prepare_ustack();
    ocall_exit_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_exit_args),
                                                  alignof(*ocall_exit_args));
    if (!ocall_exit_args) {
        /* We can't really recover from here. Should be unreachable without the host doing malicious
         * things. */
        die_or_inf_loop();
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_exit_args->exitcode, exitcode);
    COPY_VALUE_TO_UNTRUSTED(&ocall_exit_args->is_exitgroup, is_exitgroup);

#ifdef ASAN
    /* Unpoison the stacks allocated for this thread. They can be later used for a new thread. */
    uintptr_t initial_stack_addr = GET_ENCLAVE_TCB(initial_stack_addr);
    asan_unpoison_region(initial_stack_addr - ENCLAVE_STACK_SIZE, ENCLAVE_STACK_SIZE);

    uintptr_t sig_stack_low = GET_ENCLAVE_TCB(sig_stack_low);
    uintptr_t sig_stack_high = GET_ENCLAVE_TCB(sig_stack_high);
    asan_unpoison_region(sig_stack_low, sig_stack_high - sig_stack_low);
#endif

    // There are two reasons for this loop:
    //  1. Ocalls can be interuppted.
    //  2. We can't trust the outside to actually exit, so we need to ensure
    //     that we never return even when the outside tries to trick us (this
    //     case should be already catched by enclave_entry.S).
    while (true) {
        sgx_ocall(OCALL_EXIT, ocall_exit_args);
    }
}

int ocall_mmap_untrusted(void** addrptr, size_t size, int prot, int flags, int fd, off_t offset) {
    int retval = 0;
    struct ocall_mmap_untrusted* ocall_mmap_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_mmap_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_mmap_args),
                                                  alignof(*ocall_mmap_args));
    if (!ocall_mmap_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    if (!addrptr) {
        sgx_reset_ustack(old_ustack);
        return -EINVAL;
    }

    void* requested_addr = *addrptr;

    if (flags & MAP_FIXED || flags & MAP_FIXED_NOREPLACE) {
        if (!sgx_is_valid_untrusted_ptr(requested_addr, size, PAGE_SIZE)) {
            sgx_reset_ustack(old_ustack);
            return -EINVAL;
        }
    } else {
        requested_addr = NULL; /* for sanity */
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_mmap_args->addr, requested_addr);
    COPY_VALUE_TO_UNTRUSTED(&ocall_mmap_args->size, size);
    COPY_VALUE_TO_UNTRUSTED(&ocall_mmap_args->prot, prot);
    COPY_VALUE_TO_UNTRUSTED(&ocall_mmap_args->flags, flags);
    COPY_VALUE_TO_UNTRUSTED(&ocall_mmap_args->fd, fd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_mmap_args->offset, offset);

    do {
        retval = sgx_exitless_ocall(OCALL_MMAP_UNTRUSTED, ocall_mmap_args);
    } while (retval == -EINTR);

    if (retval < 0) {
        if (retval != -EACCES && retval != -EAGAIN && retval != -EBADF && retval != -EINVAL &&
                retval != -ENFILE && retval != -ENODEV && retval != -ENOMEM && retval != -EEXIST &&
                retval != -EPERM) {
            retval = -EPERM;
        }
        sgx_reset_ustack(old_ustack);
        return retval;
    }

    void* returned_addr = COPY_UNTRUSTED_VALUE(&ocall_mmap_args->addr);
    if (flags & MAP_FIXED || flags & MAP_FIXED_NOREPLACE) {
        /* addrptr already contains the mmap'ed address, no need to update it */
        if (returned_addr != requested_addr) {
            sgx_reset_ustack(old_ustack);
            return -EPERM;
        }
    } else {
        /* update addrptr with the mmap'ed address */
        if (!sgx_is_valid_untrusted_ptr(returned_addr, size, PAGE_SIZE)) {
            sgx_reset_ustack(old_ustack);
            return -EPERM;
        }
        *addrptr = returned_addr;
    }

    sgx_reset_ustack(old_ustack);
    return 0;
}

int ocall_munmap_untrusted(const void* addr, size_t size) {
    int retval = 0;
    struct ocall_munmap_untrusted* ocall_munmap_args;

    if (!sgx_is_valid_untrusted_ptr(addr, size, PAGE_SIZE))
        return -EINVAL;

    void* old_ustack = sgx_prepare_ustack();
    ocall_munmap_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_munmap_args),
                                                    alignof(*ocall_munmap_args));
    if (!ocall_munmap_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_munmap_args->addr, addr);
    COPY_VALUE_TO_UNTRUSTED(&ocall_munmap_args->size, size);

    do {
        retval = sgx_exitless_ocall(OCALL_MUNMAP_UNTRUSTED, ocall_munmap_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EINVAL) {
        retval = -EPERM;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

/*
 * Memorize untrusted memory area to avoid mmap/munmap per each read/write IO. Because this cache
 * is per-thread, we don't worry about concurrency. The cache will be carried over thread
 * exit/creation. On fork/exec emulation, untrusted code does vfork/exec, so the mmapped cache
 * will be released by exec host syscall.
 *
 * In case of AEX and consequent signal handling, current thread may be interrupted in the middle
 * of using the cache. If there are OCALLs during signal handling, they could interfere with the
 * normal-execution use of the cache, so 'in_use' atomic protects against it. OCALLs during signal
 * handling do not use the cache and always explicitly mmap/munmap untrusted memory; 'need_munmap'
 * indicates whether explicit munmap is needed at the end of such OCALL.
 */
static int ocall_mmap_untrusted_cache(size_t size, void** addrptr, bool* need_munmap) {
    int ret;

    *addrptr = NULL;
    *need_munmap = false;

    struct untrusted_area* cache = &pal_get_enclave_tcb()->untrusted_area_cache;

    uint64_t in_use = 0;
    if (!__atomic_compare_exchange_n(&cache->in_use, &in_use, 1, /*weak=*/false, __ATOMIC_RELAXED,
                                     __ATOMIC_RELAXED)) {
        /* AEX signal handling case: cache is in use, so make explicit mmap/munmap */
        ret = ocall_mmap_untrusted(addrptr, size, PROT_READ | PROT_WRITE,
                                   MAP_ANONYMOUS | MAP_PRIVATE, /*fd=*/-1, /*offset=*/0);
        if (ret < 0) {
            return ret;
        }
        *need_munmap = true;
        return 0;
    }
    COMPILER_BARRIER();

    /* normal execution case: cache was not in use, so use it/allocate new one for reuse */
    if (cache->valid) {
        if (cache->size >= size) {
            *addrptr = cache->addr;
            return 0;
        }
        ret = ocall_munmap_untrusted(cache->addr, cache->size);
        if (ret < 0) {
            cache->valid = false;
            COMPILER_BARRIER();
            __atomic_store_n(&cache->in_use, 0, __ATOMIC_RELAXED);
            return ret;
        }
    }

    ret = ocall_mmap_untrusted(addrptr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE,
                               /*fd=*/-1, /*offset=*/0);
    if (ret < 0) {
        cache->valid = false;
        COMPILER_BARRIER();
        __atomic_store_n(&cache->in_use, 0, __ATOMIC_RELAXED);
    } else {
        cache->valid = true;
        cache->addr  = *addrptr;
        cache->size  = size;
    }
    return ret;
}

static void ocall_munmap_untrusted_cache(void* addr, size_t size, bool need_munmap) {
    if (need_munmap) {
        ocall_munmap_untrusted(addr, size);
        /* there is not much we can do in case of error */
    } else {
        struct untrusted_area* cache = &pal_get_enclave_tcb()->untrusted_area_cache;
        __atomic_store_n(&cache->in_use, 0, __ATOMIC_RELAXED);
    }
}

int ocall_cpuid(unsigned int leaf, unsigned int subleaf, unsigned int values[static 4]) {
    int retval = 0;
    struct ocall_cpuid* ocall_cpuid_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_cpuid_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_cpuid_args),
                                                   alignof(*ocall_cpuid_args));
    if (!ocall_cpuid_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_cpuid_args->leaf, leaf);
    COPY_VALUE_TO_UNTRUSTED(&ocall_cpuid_args->subleaf, subleaf);

    do {
        /* cpuid must be retrieved in the context of current logical core, cannot use exitless */
        retval = sgx_ocall(OCALL_CPUID, ocall_cpuid_args);
    } while (retval == -EINTR);

    if (retval < 0) {
        log_error("OCALL_CPUID returned an error (impossible on benign host)");
        _PalProcessExit(1);
    }

    if (!retval) {
        values[0] = COPY_UNTRUSTED_VALUE(&ocall_cpuid_args->values[0]);
        values[1] = COPY_UNTRUSTED_VALUE(&ocall_cpuid_args->values[1]);
        values[2] = COPY_UNTRUSTED_VALUE(&ocall_cpuid_args->values[2]);
        values[3] = COPY_UNTRUSTED_VALUE(&ocall_cpuid_args->values[3]);
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_open(const char* pathname, int flags, unsigned short mode) {
    int retval = 0;
    size_t path_size = pathname ? strlen(pathname) + 1 : 0;
    struct ocall_open* ocall_open_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_open_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_open_args),
                                                  alignof(*ocall_open_args));
    if (!ocall_open_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_open_args->flags, flags);
    COPY_VALUE_TO_UNTRUSTED(&ocall_open_args->mode, mode);
    void* untrusted_pathname = sgx_copy_to_ustack(pathname, path_size);
    if (!untrusted_pathname) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_open_args->pathname, untrusted_pathname);

    do {
        retval = sgx_exitless_ocall(OCALL_OPEN, ocall_open_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EACCES && retval != -EEXIST && retval != -EINVAL &&
            retval != -EISDIR && retval != -ELOOP && retval != -EMFILE &&
            retval != -ENAMETOOLONG && retval != -ENFILE && retval != -ENODEV &&
            retval != -ENOENT && retval != -ENOMEM && retval != -ENOTDIR && retval != -EROFS &&
            retval != -EWOULDBLOCK) {
        retval = -EPERM;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_close(int fd) {
    int retval = 0;
    struct ocall_close* ocall_close_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_close_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_close_args),
                                                   alignof(*ocall_close_args));
    if (!ocall_close_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_close_args->fd, fd);

    /* We should never restart host-level `close` syscall on errors (including `EINTR`), but
     * `sgx_ocall_close` does not forward any errors (always returns `0`), so this can only be
     * an injected `EINTR`. */
    do {
        retval = sgx_exitless_ocall(OCALL_CLOSE, ocall_close_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EBADF && retval != -EIO) {
        retval = -EPERM;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

ssize_t ocall_read(int fd, void* buf, size_t count) {
    ssize_t retval = 0;
    void* obuf = NULL;
    struct ocall_read* ocall_read_args;
    void* untrusted_buf;
    bool need_munmap = false;

    void* old_ustack = sgx_prepare_ustack();
    if (count > MAX_UNTRUSTED_STACK_BUF) {
        retval = ocall_mmap_untrusted_cache(ALLOC_ALIGN_UP(count), &obuf, &need_munmap);
        if (retval < 0) {
            sgx_reset_ustack(old_ustack);
            return retval;
        }
        untrusted_buf = obuf;
    } else {
        untrusted_buf = sgx_alloc_on_ustack(count);
        if (!untrusted_buf) {
            retval = -EPERM;
            goto out;
        }
    }

    ocall_read_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_read_args),
                                                  alignof(*ocall_read_args));
    if (!ocall_read_args) {
        retval = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_read_args->fd, fd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_read_args->count, count);
    COPY_VALUE_TO_UNTRUSTED(&ocall_read_args->buf, untrusted_buf);

    retval = sgx_exitless_ocall(OCALL_READ, ocall_read_args);

    if (retval < 0 && retval != -EAGAIN && retval != -EWOULDBLOCK && retval != -EBADF &&
            retval != -EINTR && retval != -EINVAL && retval != -EIO && retval != -EISDIR) {
        retval = -EPERM;
    }

    if (retval > 0) {
        if ((size_t)retval > count) {
            retval = -EPERM;
            goto out;
        }
        if (!sgx_copy_to_enclave(buf, count, untrusted_buf, retval)) {
            retval = -EPERM;
            goto out;
        }
    }

out:
    sgx_reset_ustack(old_ustack);
    if (obuf)
        ocall_munmap_untrusted_cache(obuf, ALLOC_ALIGN_UP(count), need_munmap);
    return retval;
}

ssize_t ocall_write(int fd, const void* buf, size_t count) {
    ssize_t retval = 0;
    void* obuf = NULL;
    struct ocall_write* ocall_write_args;
    const void* untrusted_buf;
    bool need_munmap = false;

    void* old_ustack = sgx_prepare_ustack();

    if (sgx_is_valid_untrusted_ptr(buf, count, /*alignment=*/1)) {
        /* buf is in untrusted memory (e.g., allowed file mmaped in untrusted memory) */
        untrusted_buf = buf;
    } else if (sgx_is_completely_within_enclave(buf, count)) {
        /* typical case of buf inside of enclave memory */
        if (count > MAX_UNTRUSTED_STACK_BUF) {
            /* buf is too big and may overflow untrusted stack, so use untrusted heap */
            retval = ocall_mmap_untrusted_cache(ALLOC_ALIGN_UP(count), &obuf, &need_munmap);
            if (retval < 0) {
                goto out;
            }
            memcpy(obuf, buf, count);
            untrusted_buf = obuf;
        } else {
            untrusted_buf = sgx_copy_to_ustack(buf, count);
            if (!untrusted_buf) {
                retval = -EPERM;
                goto out;
            }
        }
    } else {
        /* buf is partially in/out of enclave memory */
        retval = -EPERM;
        goto out;
    }

    ocall_write_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_write_args),
                                                   alignof(*ocall_write_args));
    if (!ocall_write_args) {
        retval = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_write_args->fd, fd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_write_args->count, count);
    COPY_VALUE_TO_UNTRUSTED(&ocall_write_args->buf, untrusted_buf);

    retval = sgx_exitless_ocall(OCALL_WRITE, ocall_write_args);

    if (retval < 0 && retval != -EAGAIN && retval != -EWOULDBLOCK && retval != -EBADF &&
            retval != -EFBIG && retval != -EINTR && retval != -EINVAL && retval != -EIO &&
            retval != -ENOSPC && retval != -EPIPE) {
        retval = -EPERM;
    }

    if (retval > 0 && (size_t)retval > count) {
        retval = -EPERM;
        goto out;
    }

out:
    sgx_reset_ustack(old_ustack);
    if (obuf)
        ocall_munmap_untrusted_cache(obuf, ALLOC_ALIGN_UP(count), need_munmap);
    return retval;
}

ssize_t ocall_pread(int fd, void* buf, size_t count, off_t offset) {
    long retval = 0;
    void* obuf = NULL;
    struct ocall_pread* ocall_pread_args;
    void* untrusted_buf;
    bool need_munmap = false;

    void* old_ustack = sgx_prepare_ustack();
    if (count > MAX_UNTRUSTED_STACK_BUF) {
        retval = ocall_mmap_untrusted_cache(ALLOC_ALIGN_UP(count), &obuf, &need_munmap);
        if (retval < 0) {
            sgx_reset_ustack(old_ustack);
            return retval;
        }
        untrusted_buf = obuf;
    } else {
        untrusted_buf = sgx_alloc_on_ustack(count);
        if (!untrusted_buf) {
            retval = -EPERM;
            goto out;
        }
    }

    ocall_pread_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_pread_args),
                                                   alignof(*ocall_pread_args));
    if (!ocall_pread_args) {
        retval = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_pread_args->fd, fd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_pread_args->count, count);
    COPY_VALUE_TO_UNTRUSTED(&ocall_pread_args->offset, offset);
    COPY_VALUE_TO_UNTRUSTED(&ocall_pread_args->buf, untrusted_buf);

    retval = sgx_exitless_ocall(OCALL_PREAD, ocall_pread_args);

    if (retval < 0 && retval != -EAGAIN && retval != -EWOULDBLOCK && retval != -EBADF &&
            retval != -EINTR && retval != -EINVAL && retval != -EIO && retval != -EISDIR &&
            retval != -ENXIO && retval != -EOVERFLOW && retval != -ESPIPE) {
        retval = -EPERM;
    }

    if (retval > 0) {
        if ((size_t)retval > count) {
            retval = -EPERM;
            goto out;
        }
        if (!sgx_copy_to_enclave(buf, count, untrusted_buf, retval)) {
            retval = -EPERM;
        }
    }

out:
    sgx_reset_ustack(old_ustack);
    if (obuf)
        ocall_munmap_untrusted_cache(obuf, ALLOC_ALIGN_UP(count), need_munmap);
    return retval;
}

ssize_t ocall_pwrite(int fd, const void* buf, size_t count, off_t offset) {
    long retval = 0;
    void* obuf = NULL;
    struct ocall_pwrite* ocall_pwrite_args;
    const void* untrusted_buf;
    bool need_munmap = false;

    void* old_ustack = sgx_prepare_ustack();

    if (sgx_is_valid_untrusted_ptr(buf, count, /*alignment=*/1)) {
        /* buf is in untrusted memory (e.g., allowed file mmaped in untrusted memory) */
        untrusted_buf = buf;
    } else if (sgx_is_completely_within_enclave(buf, count)) {
        /* typical case of buf inside of enclave memory */
        if (count > MAX_UNTRUSTED_STACK_BUF) {
            /* buf is too big and may overflow untrusted stack, so use untrusted heap */
            retval = ocall_mmap_untrusted_cache(ALLOC_ALIGN_UP(count), &obuf, &need_munmap);
            if (retval < 0) {
                goto out;
            }
            memcpy(obuf, buf, count);
            untrusted_buf = obuf;
        } else {
            untrusted_buf = sgx_copy_to_ustack(buf, count);
            if (!untrusted_buf) {
                retval = -EPERM;
                goto out;
            }
        }
    } else {
        /* buf is partially in/out of enclave memory */
        retval = -EPERM;
        goto out;
    }

    ocall_pwrite_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_pwrite_args),
                                                    alignof(*ocall_pwrite_args));
    if (!ocall_pwrite_args) {
        retval = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_pwrite_args->fd, fd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_pwrite_args->count, count);
    COPY_VALUE_TO_UNTRUSTED(&ocall_pwrite_args->offset, offset);
    COPY_VALUE_TO_UNTRUSTED(&ocall_pwrite_args->buf, untrusted_buf);

    retval = sgx_exitless_ocall(OCALL_PWRITE, ocall_pwrite_args);

    if (retval < 0 && retval != -EAGAIN && retval != -EWOULDBLOCK && retval != -EBADF &&
            retval != -EFBIG && retval != -EINTR && retval != -EINVAL && retval != -EIO &&
            retval != -ENOSPC && retval != -ENXIO && retval != -EOVERFLOW && retval != -EPIPE &&
            retval != -ESPIPE) {
        retval = -EPERM;
    }

    if (retval > 0 && (size_t)retval > count) {
        retval = -EPERM;
        goto out;
    }

out:
    sgx_reset_ustack(old_ustack);
    if (obuf)
        ocall_munmap_untrusted_cache(obuf, ALLOC_ALIGN_UP(count), need_munmap);
    return retval;
}

int ocall_fstat(int fd, struct stat* buf) {
    int retval = 0;
    struct ocall_fstat* ocall_fstat_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_fstat_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_fstat_args),
                                                   alignof(*ocall_fstat_args));
    if (!ocall_fstat_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_fstat_args->fd, fd);

    do {
        retval = sgx_exitless_ocall(OCALL_FSTAT, ocall_fstat_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EACCES && retval != -EBADF && retval != -ELOOP &&
            retval != -ENAMETOOLONG && retval != -ENOENT && retval != -ENOMEM &&
            retval != -ENOTDIR) {
        retval = -EPERM;
    }

    if (!retval) {
        if (!sgx_copy_to_enclave(buf, sizeof(*buf), &ocall_fstat_args->stat, sizeof(struct stat))) {
            retval = -EPERM;
        }
        /* TODO: sanitize `buf`, e.g. that `buf->st_size >= 0` */
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_fionread(int fd) {
    int retval = 0;
    struct ocall_fionread* ocall_fionread_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_fionread_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_fionread_args),
                                                      alignof(*ocall_fionread_args));
    if (!ocall_fionread_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_fionread_args->fd, fd);

    do {
        retval = sgx_exitless_ocall(OCALL_FIONREAD, ocall_fionread_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EBADF && retval != -EINVAL && retval != -ENOTTY) {
        retval = -EPERM;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_fsetnonblock(int fd, int nonblocking) {
    int retval = 0;
    struct ocall_fsetnonblock* ocall_fsetnonblock_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_fsetnonblock_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_fsetnonblock_args),
                                                          alignof(*ocall_fsetnonblock_args));
    if (!ocall_fsetnonblock_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_fsetnonblock_args->fd, fd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_fsetnonblock_args->nonblocking, nonblocking);

    do {
        retval = sgx_exitless_ocall(OCALL_FSETNONBLOCK, ocall_fsetnonblock_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EACCES && retval != -EAGAIN && retval != -EBADF &&
            retval != -EINVAL && retval != -EPERM) {
        retval = -EPERM;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

/* TODO: Unneeded OCALL? Gramine doesn't have a notion of permissions currently. */
int ocall_fchmod(int fd, unsigned short mode) {
    int retval = 0;
    struct ocall_fchmod* ocall_fchmod_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_fchmod_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_fchmod_args),
                                                    alignof(*ocall_fchmod_args));
    if (!ocall_fchmod_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_fchmod_args->fd, fd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_fchmod_args->mode, mode);

    do {
        retval = sgx_exitless_ocall(OCALL_FCHMOD, ocall_fchmod_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EACCES && retval != -EIO && retval != -ELOOP &&
            retval != -ENAMETOOLONG && retval != -ENOENT && retval != -ENOMEM &&
            retval != -ENOTDIR && retval != -EPERM && retval != -EROFS) {
        retval = -EPERM;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_fsync(int fd) {
    int retval = 0;
    struct ocall_fsync* ocall_fsync_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_fsync_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_fsync_args),
                                                   alignof(*ocall_fsync_args));
    if (!ocall_fsync_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_fsync_args->fd, fd);

    do {
        retval = sgx_exitless_ocall(OCALL_FSYNC, ocall_fsync_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EBADF && retval != -EIO && retval != -EINVAL && retval != -EROFS) {
        retval = -EPERM;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_ftruncate(int fd, uint64_t length) {
    int retval = 0;
    struct ocall_ftruncate* ocall_ftruncate_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_ftruncate_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_ftruncate_args),
                                                       alignof(*ocall_ftruncate_args));
    if (!ocall_ftruncate_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_ftruncate_args->fd, fd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_ftruncate_args->length, length);

    do {
        retval = sgx_exitless_ocall(OCALL_FTRUNCATE, ocall_ftruncate_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EBADF && retval != -EINVAL && retval != -EPERM &&
            retval != -EROFS) {
        retval = -EPERM;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_mkdir(const char* pathname, unsigned short mode) {
    int retval = 0;
    size_t path_size = pathname ? strlen(pathname) + 1 : 0;
    struct ocall_mkdir* ocall_mkdir_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_mkdir_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_mkdir_args),
                                                   alignof(*ocall_mkdir_args));
    if (!ocall_mkdir_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_mkdir_args->mode, mode);
    void* untrusted_pathname = sgx_copy_to_ustack(pathname, path_size);
    if (!untrusted_pathname) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_mkdir_args->pathname, untrusted_pathname);

    do {
        retval = sgx_exitless_ocall(OCALL_MKDIR, ocall_mkdir_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EACCES && retval != -EEXIST && retval != -EINVAL &&
            retval != -ELOOP && retval != -EMLINK && retval != -ENAMETOOLONG &&
            retval != -ENOENT && retval != -ENOMEM && retval != -ENOSPC && retval != -ENOTDIR &&
            retval != -EPERM && retval != -EROFS) {
        retval = -EPERM;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_getdents(int fd, struct linux_dirent64* dirp, size_t dirp_size) {
    int retval = 0;
    struct ocall_getdents* ocall_getdents_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_getdents_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_getdents_args),
                                                      alignof(*ocall_getdents_args));
    if (!ocall_getdents_args) {
        retval = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_getdents_args->fd, fd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_getdents_args->size, dirp_size);
    void* untrusted_dirp = sgx_alloc_on_ustack_aligned(dirp_size, alignof(*dirp));
    if (!untrusted_dirp) {
        retval = -EPERM;
        goto out;
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_getdents_args->dirp, untrusted_dirp);

    do {
        retval = sgx_exitless_ocall(OCALL_GETDENTS, ocall_getdents_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EBADF && retval != -EINVAL && retval != -ENOENT &&
            retval != -ENOTDIR) {
        retval = -EPERM;
    }

    if (retval > 0) {
        size_t size = (size_t)retval;
        if (size > dirp_size) {
            retval = -EPERM;
            goto out;
        }
        if (!sgx_copy_to_enclave(dirp, dirp_size, untrusted_dirp, size)) {
            retval = -EPERM;
            goto out;
        }

        size_t size_left = size;
        while (size_left > offsetof(struct linux_dirent64, d_name)) {
            /* `drip->d_off` is understandable only by the fs driver in kernel, we have no way of
             * validating it. */
            if (dirp->d_reclen > size_left) {
                retval = -EPERM;
                goto out;
            }
            size_left -= dirp->d_reclen;
            dirp = (struct linux_dirent64*)((char*)dirp + dirp->d_reclen);
        }
        if (size_left != 0) {
            retval = -EPERM;
            goto out;
        }
    }

out:
    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_resume_thread(void* tcs) {
    int retval = 0;
    do {
        retval = sgx_exitless_ocall(OCALL_RESUME_THREAD, tcs);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EINVAL && retval != -EPERM && retval != -ESRCH) {
        retval = -EPERM;
    }

    return retval;
}

int ocall_clone_thread(void* dynamic_tcs) {
    int retval = 0;
    /* FIXME: if there was an EINTR, there may be an untrusted thread left over */
    do {
        /* clone must happen in the context of current (enclave) thread, cannot use exitless;
         * in particular, the new (enclave) thread must have the same signal mask as the current
         * enclave thread (and NOT signal mask of the RPC thread) */
        retval = sgx_ocall(OCALL_CLONE_THREAD, dynamic_tcs);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -ENOMEM && retval != -EAGAIN && retval != -EINVAL &&
            retval != -EPERM) {
        retval = -EPERM;
    }

    return retval;
}

int ocall_create_process(size_t nargs, const char** args, uintptr_t (*reserved_mem_ranges)[2],
                         size_t reserved_mem_ranges_len, int* out_stream_fd) {
    int ret;
    void* urts_reserved_mem_ranges = NULL;
    size_t reserved_mem_ranges_size = reserved_mem_ranges_len * sizeof(*reserved_mem_ranges);
    bool need_munmap;
    void* old_ustack = sgx_prepare_ustack();
    struct ocall_create_process* ocall_cp_args;


    ocall_cp_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_cp_args) + nargs * sizeof(char*),
                                                alignof(*ocall_cp_args));
    if (!ocall_cp_args) {
        ret = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_cp_args->nargs, nargs);
    for (size_t i = 0; i < nargs; i++) {
        size_t size = args[i] ? strlen(args[i]) + 1 : 0;
        void* unstrusted_arg = args[i] ? sgx_copy_to_ustack(args[i], size) : NULL;

        if (args[i] && !unstrusted_arg) {
            ret = -EPERM;
            goto out;
        }
        COPY_VALUE_TO_UNTRUSTED(&ocall_cp_args->args[i], unstrusted_arg);
    }

    if (reserved_mem_ranges_size) {
        ret = ocall_mmap_untrusted_cache(reserved_mem_ranges_size, &urts_reserved_mem_ranges,
                                         &need_munmap);
        if (ret < 0) {
            goto out;
        }
        if (!sgx_copy_from_enclave(urts_reserved_mem_ranges, reserved_mem_ranges,
                                   reserved_mem_ranges_size)) {
            ret = -EPERM;
            goto out;
        }
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_cp_args->reserved_mem_ranges, urts_reserved_mem_ranges);
    COPY_VALUE_TO_UNTRUSTED(&ocall_cp_args->reserved_mem_ranges_size, reserved_mem_ranges_size);

    do {
        /* FIXME: if there was an EINTR, there may be an untrusted process left over */
        ret = sgx_exitless_ocall(OCALL_CREATE_PROCESS, ocall_cp_args);
    } while (ret == -EINTR);

    if (ret < 0) {
        if (ret != -EAGAIN && ret != -EWOULDBLOCK && ret != -EBADF && ret != -EFBIG
                && ret != -EINVAL && ret != -EIO && ret != -ENOSPC && ret != -EPIPE
                && ret != -ENOMEM && ret != -EACCES && ret != -EISDIR && ret != -ELOOP
                && ret != -EMFILE && ret != -ENAMETOOLONG && ret != -ENFILE && ret != -ENOENT
                && ret != -ENOEXEC && ret != -ENOTDIR && ret != -EPERM) {
            ret = -EPERM;
        }
        goto out;
    }

    if (out_stream_fd)
        *out_stream_fd = COPY_UNTRUSTED_VALUE(&ocall_cp_args->stream_fd);

out:
    if (urts_reserved_mem_ranges) {
        /* Cannot really handle errors here - but this is just host memory and this cannot fail on
         * non-malicious host. */
        ocall_munmap_untrusted_cache(urts_reserved_mem_ranges, reserved_mem_ranges_size,
                                     need_munmap);
    }
    sgx_reset_ustack(old_ustack);
    return ret;
}

int ocall_futex(uint32_t* futex, int op, int val, uint64_t* timeout_us) {
    int retval = 0;
    struct ocall_futex* ocall_futex_args;

    if (!sgx_is_valid_untrusted_ptr(futex, sizeof(*futex), alignof(__typeof__(*futex)))) {
        return -EINVAL;
    }

    if (op != FUTEX_WAIT && op != FUTEX_WAKE) {
        /* Other operations are not implemented currently. */
        return -EINVAL;
    }

    void* old_ustack = sgx_prepare_ustack();
    ocall_futex_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_futex_args),
                                                   alignof(*ocall_futex_args));
    if (!ocall_futex_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_futex_args->futex, futex);
    COPY_VALUE_TO_UNTRUSTED(&ocall_futex_args->op, op);
    COPY_VALUE_TO_UNTRUSTED(&ocall_futex_args->val, val);
    COPY_VALUE_TO_UNTRUSTED(&ocall_futex_args->timeout_us, timeout_us ? *timeout_us : (uint64_t)-1);

    if (op == FUTEX_WAIT) {
        /* With `FUTEX_WAIT` this thread is most likely going to sleep, so there is no point in
         * doing an exitless ocall. */
        retval = sgx_ocall(OCALL_FUTEX, ocall_futex_args);
    } else {
        assert(op == FUTEX_WAKE);
        retval = sgx_exitless_ocall(OCALL_FUTEX, ocall_futex_args);
    }

    if (retval < 0 && retval != -EACCES && retval != -EAGAIN && retval != -EDEADLK &&
            retval != -EINTR && retval != -EINVAL && retval != -ENFILE && retval != -ENOMEM &&
            retval != -ENOSYS && retval != -EPERM && retval != -ESRCH && retval != -ETIMEDOUT) {
        retval = -EPERM;
    }

    if (timeout_us) {
        uint64_t remaining_time_us;

        remaining_time_us = COPY_UNTRUSTED_VALUE(&ocall_futex_args->timeout_us);
        if (retval == -ETIMEDOUT) {
            remaining_time_us = 0;
        }
        if (remaining_time_us > *timeout_us) {
            retval = -EPERM;
        } else {
            *timeout_us = remaining_time_us;
        }
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_socket(int family, int type, int protocol) {
    int ret;
    void* old_ustack = sgx_prepare_ustack();
    struct ocall_socket* ocall_socket_args;

    ocall_socket_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_socket_args),
                                                    alignof(*ocall_socket_args));
    if (!ocall_socket_args) {
        ret = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_socket_args->family, family);
    COPY_VALUE_TO_UNTRUSTED(&ocall_socket_args->type, type);
    COPY_VALUE_TO_UNTRUSTED(&ocall_socket_args->protocol, protocol);

    do {
        ret = sgx_exitless_ocall(OCALL_SOCKET, ocall_socket_args);
    } while (ret == -EINTR);

    if (ret < 0 && ret != -EINVAL && ret != -EACCES && ret != -EMFILE && ret != -ENFILE
            && ret != -ENOMEM && ret != -EAFNOSUPPORT && ret != -EPROTONOSUPPORT) {
        ret = -EPERM;
    }

out:
    sgx_reset_ustack(old_ustack);
    return ret;
}

int ocall_bind(int fd, struct sockaddr_storage* addr, size_t addrlen, uint16_t* out_new_port) {
    int ret;
    void* old_ustack = sgx_prepare_ustack();
    struct ocall_bind* ocall_bind_args;

    ocall_bind_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_bind_args),
                                                  alignof(*ocall_bind_args));
    if (!ocall_bind_args) {
        ret = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_bind_args->fd, fd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_bind_args->addrlen, addrlen);

    void* untrusted_addr = sgx_copy_to_ustack(addr, addrlen);
    if (!untrusted_addr) {
        ret = -EPERM;
        goto out;
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_bind_args->addr, untrusted_addr);

    do {
        ret = sgx_exitless_ocall(OCALL_BIND, ocall_bind_args);
    } while (ret == -EINTR);

    if (ret < 0) {
        if (ret != -EACCES && ret != -EADDRINUSE && ret != -EBADF && ret != -EINVAL
                && ret != -ENOTSOCK) {
            ret = -EPERM;
        }
        goto out;
    }

    uint16_t new_port = COPY_UNTRUSTED_VALUE(&ocall_bind_args->new_port);
    if (new_port == 0) {
        ret = -EPERM;
        goto out;
    }

    *out_new_port = new_port;
    ret = 0;

out:
    sgx_reset_ustack(old_ustack);
    return ret;
}

int ocall_listen_simple(int fd, unsigned int backlog) {
    int ret;
    void* old_ustack = sgx_prepare_ustack();
    struct ocall_listen_simple* ocall_listen_args;
    ocall_listen_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_listen_args),
                                                    alignof(*ocall_listen_args));
    if (!ocall_listen_args) {
        ret = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_listen_args->fd, fd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_listen_args->backlog, backlog);

    do {
        ret = sgx_exitless_ocall(OCALL_LISTEN_SIMPLE, ocall_listen_args);
    } while (ret == -EINTR);

    if (ret < 0 && ret != -EADDRINUSE && ret != -EBADF && ret != -ENOTSOCK && ret != -EOPNOTSUPP) {
        ret = -EPERM;
    }

out:
    sgx_reset_ustack(old_ustack);
    return ret;
}

int ocall_listen(int domain, int type, int protocol, int ipv6_v6only, struct sockaddr* addr,
                 size_t* addrlen) {
    int retval = 0;
    size_t len = addrlen ? *addrlen : 0;
    struct ocall_listen* ocall_listen_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_listen_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_listen_args),
                                                    alignof(*ocall_listen_args));
    if (!ocall_listen_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_listen_args->domain, domain);
    COPY_VALUE_TO_UNTRUSTED(&ocall_listen_args->type, type);
    COPY_VALUE_TO_UNTRUSTED(&ocall_listen_args->protocol, protocol);
    COPY_VALUE_TO_UNTRUSTED(&ocall_listen_args->ipv6_v6only, ipv6_v6only);
    COPY_VALUE_TO_UNTRUSTED(&ocall_listen_args->addrlen, len);
    void* untrusted_addr = (addr && len) ? sgx_copy_to_ustack(addr, len) : NULL;
    if (addr && len && !untrusted_addr) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_listen_args->addr, untrusted_addr);

    do {
        retval = sgx_exitless_ocall(OCALL_LISTEN, ocall_listen_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EACCES && retval != -EINVAL && retval != -EMFILE &&
            retval != -ENFILE && retval != -ENOMEM && retval != -ENOBUFS && retval != -EBADF &&
            retval != -ENOPROTOOPT && retval != -ENOTSOCK && retval != -EADDRINUSE &&
            retval != -EADDRNOTAVAIL && retval != -ELOOP && retval != -ENAMETOOLONG &&
            retval != -ENOENT && retval != -ENOTDIR && retval != -EROFS && retval != -EOPNOTSUPP) {
        retval = -EPERM;
    }

    if (retval >= 0) {
        if (addr && len) {
            size_t untrusted_addrlen = COPY_UNTRUSTED_VALUE(&ocall_listen_args->addrlen);
            if (!sgx_copy_to_enclave(addr, len, untrusted_addr, untrusted_addrlen)) {
                sgx_reset_ustack(old_ustack);
                return -EPERM;
            }
            *addrlen = untrusted_addrlen;
        }
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_accept(int sockfd, struct sockaddr* addr, size_t* addrlen, struct sockaddr* local_addr,
                 size_t* local_addrlen, int options) {
    int retval = 0;
    size_t len = addrlen ? *addrlen : 0;
    size_t local_len = local_addrlen ? *local_addrlen : 0;
    struct ocall_accept* ocall_accept_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_accept_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_accept_args),
                                                    alignof(*ocall_accept_args));
    if (!ocall_accept_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_accept_args->sockfd, sockfd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_accept_args->addrlen, len);
    COPY_VALUE_TO_UNTRUSTED(&ocall_accept_args->local_addrlen, local_len);
    void* untrusted_addr = (addr && len) ? sgx_copy_to_ustack(addr, len) : NULL;
    if (addr && len && !untrusted_addr) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }
    void* untrusted_local_addr = (local_addr && local_len) ?
                                 sgx_copy_to_ustack(local_addr, local_len) : NULL;
    if (local_addr && local_len && !untrusted_local_addr) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_accept_args->addr, untrusted_addr);
    COPY_VALUE_TO_UNTRUSTED(&ocall_accept_args->local_addr, untrusted_local_addr);
    COPY_VALUE_TO_UNTRUSTED(&ocall_accept_args->options, options);

    retval = sgx_exitless_ocall(OCALL_ACCEPT, ocall_accept_args);

    if (retval < 0 && retval != -EAGAIN && retval != -EWOULDBLOCK && retval != -EBADF &&
            retval != -ECONNABORTED && retval != -EINTR && retval != -EINVAL && retval != -EMFILE &&
            retval != -ENFILE && retval != -ENOMEM && retval != -ENOBUFS && retval != -ENOTSOCK &&
            retval != -EPROTO && retval != -EPERM && retval != -ENOPROTOOPT) {
        retval = -EPERM;
    }

    if (retval >= 0) {
        if (addr && len) {
            size_t untrusted_addrlen;
            untrusted_addrlen = COPY_UNTRUSTED_VALUE(&ocall_accept_args->addrlen);
            if (!sgx_copy_to_enclave(addr, len, untrusted_addr, untrusted_addrlen)) {
                sgx_reset_ustack(old_ustack);
                return -EPERM;
            }
            *addrlen = untrusted_addrlen;
        }
        if (local_addr && local_len) {
            size_t untrusted_local_addrlen;
            untrusted_local_addrlen = COPY_UNTRUSTED_VALUE(&ocall_accept_args->local_addrlen);
            if (!sgx_copy_to_enclave(local_addr, local_len, untrusted_local_addr,
                                     untrusted_local_addrlen)) {
                sgx_reset_ustack(old_ustack);
                return -EPERM;
            }
            *local_addrlen = untrusted_local_addrlen;
        }
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_connect(int domain, int type, int protocol, int ipv6_v6only, const struct sockaddr* addr,
                  size_t addrlen, struct sockaddr* bind_addr, size_t* bind_addrlen) {
    int retval = 0;
    size_t bind_len = bind_addrlen ? *bind_addrlen : 0;
    struct ocall_connect* ocall_connect_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_connect_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_connect_args),
                                                     alignof(*ocall_connect_args));
    if (!ocall_connect_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_connect_args->domain, domain);
    COPY_VALUE_TO_UNTRUSTED(&ocall_connect_args->type, type);
    COPY_VALUE_TO_UNTRUSTED(&ocall_connect_args->protocol, protocol);
    COPY_VALUE_TO_UNTRUSTED(&ocall_connect_args->ipv6_v6only, ipv6_v6only);
    COPY_VALUE_TO_UNTRUSTED(&ocall_connect_args->addrlen, addrlen);
    COPY_VALUE_TO_UNTRUSTED(&ocall_connect_args->bind_addrlen, bind_len);
    void* untrusted_addr = addr ? sgx_copy_to_ustack(addr, addrlen) : NULL;
    void* untrusted_bind_addr = bind_addr ? sgx_copy_to_ustack(bind_addr, bind_len) : NULL;
    if ((addr && !untrusted_addr) || (bind_addr && !untrusted_bind_addr)) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_connect_args->addr, untrusted_addr);
    COPY_VALUE_TO_UNTRUSTED(&ocall_connect_args->bind_addr, untrusted_bind_addr);

    retval = sgx_exitless_ocall(OCALL_CONNECT, ocall_connect_args);

    if (retval < 0 && retval != -EACCES && retval != -EINVAL && retval != -EMFILE &&
            retval != -ENFILE && retval != -ENOMEM && retval != -ENOBUFS && retval != -EBADF &&
            retval != -ENOPROTOOPT && retval != -ENOTSOCK && retval != -EADDRINUSE &&
            retval != -EADDRNOTAVAIL && retval != -ELOOP && retval != -ENAMETOOLONG &&
            retval != -ENOENT && retval != -ENOTDIR && retval != -EROFS && retval != -EOPNOTSUPP &&
            retval != -EPERM && retval != -EAFNOSUPPORT && retval != -EAGAIN &&
            retval != -EALREADY && retval != -ECONNREFUSED && retval != -EINPROGRESS &&
            retval != -EINTR && retval != -EISCONN && retval != -ENETUNREACH &&
            retval != -EPROTOTYPE && retval != -ETIMEDOUT) {
        retval = -EPERM;
    }

    if (retval >= 0) {
        if (bind_addr && bind_len) {
            size_t untrusted_addrlen = COPY_UNTRUSTED_VALUE(&ocall_connect_args->bind_addrlen);
            bool copied = sgx_copy_to_enclave(bind_addr, bind_len, untrusted_bind_addr,
                                              untrusted_addrlen);
            if (!copied) {
                sgx_reset_ustack(old_ustack);
                return -EPERM;
            }
            *bind_addrlen = untrusted_addrlen;
        }
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_connect_simple(int fd, bool nonblocking, struct sockaddr_storage* addr, size_t* addrlen,
                         bool* out_inprogress) {
    int ret;
    void* old_ustack = sgx_prepare_ustack();
    struct ocall_connect_simple* ocall_connect_args;
    ocall_connect_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_connect_args),
                                                     alignof(*ocall_connect_args));
    if (!ocall_connect_args) {
        ret = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_connect_args->fd, fd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_connect_args->addrlen, *addrlen);

    assert(*addrlen <= sizeof(*addr));
    struct sockaddr_storage* untrusted_addr = sgx_alloc_on_ustack_aligned(sizeof(*untrusted_addr),
                                                                          alignof(*untrusted_addr));
    if (!untrusted_addr) {
        ret = -EPERM;
        goto out;
    }
    memcpy(untrusted_addr, addr, *addrlen);
    COPY_VALUE_TO_UNTRUSTED(&ocall_connect_args->addr, untrusted_addr);

    do {
        ret = sgx_exitless_ocall(OCALL_CONNECT_SIMPLE, ocall_connect_args);
    } while (ret == -EINTR);

    bool inprogress = false;
    if (ret == -EINPROGRESS) {
        if (!nonblocking) {
            /* EINPROGRESS can be returned only on non-blocking sockets */
            ret = -EPERM;
            goto out;
        }
        /* POSIX/Linux have an unusual semantics for EINPROGRESS: the connect operation is
         * considered successful, but the return value is -EINPROGRESS error code. We don't want to
         * replicate this oddness in Gramine, so we return `0` and set a special variable. */
        inprogress = true;
        ret = 0;
    }

    if (ret < 0) {
        if (ret != -EACCES && ret != -EPERM && ret != -EADDRINUSE && ret != -EADDRNOTAVAIL
                && ret != -EAFNOSUPPORT && ret != -EAGAIN && ret != -EALREADY && ret != -EBADF
                && ret != -ECONNREFUSED && ret != -EISCONN && ret != -ENETUNREACH
                && ret != -ENOTSOCK && ret != -EPROTOTYPE && ret != -ETIMEDOUT) {
            ret = -EPERM;
        }
        goto out;
    }

    size_t new_addrlen = COPY_UNTRUSTED_VALUE(&ocall_connect_args->addrlen);
    if (new_addrlen > sizeof(*addr)) {
        ret = -EPERM;
        goto out;
    }
    bool copied = sgx_copy_to_enclave(addr, sizeof(*addr), untrusted_addr, new_addrlen);
    if (!copied) {
        ret = -EPERM;
        goto out;
    }
    *addrlen = new_addrlen;
    *out_inprogress = inprogress;
    ret = 0;

out:
    sgx_reset_ustack(old_ustack);
    return ret;
}

ssize_t ocall_recv(int sockfd, struct iovec* iov, size_t iov_len, void* addr, size_t* addrlenptr,
                   void* control, size_t* controllenptr, unsigned int flags) {
    ssize_t retval;
    void* obuf = NULL;
    bool is_obuf_mapped = false;
    size_t addrlen = addrlenptr ? *addrlenptr : 0;
    size_t controllen = controllenptr ? *controllenptr : 0;
    struct ocall_recv* ocall_recv_args;
    bool need_munmap = false;

    void* old_ustack = sgx_prepare_ustack();

    size_t size = 0;
    for (size_t i = 0; i < iov_len; i++) {
        size += iov[i].iov_len;
    }

    if ((size + addrlen + controllen) > MAX_UNTRUSTED_STACK_BUF) {
        /* Buffer is too big for untrusted stack - use untrusted heap instead. */
        retval = ocall_mmap_untrusted_cache(ALLOC_ALIGN_UP(size), &obuf, &need_munmap);
        if (retval < 0) {
            goto out;
        }
        is_obuf_mapped = true;
    } else {
        obuf = sgx_alloc_on_ustack(size);
        if (!obuf) {
            retval = -EPERM;
            goto out;
        }
    }

    ocall_recv_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_recv_args),
                                                  alignof(*ocall_recv_args));
    if (!ocall_recv_args) {
        retval = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_recv_args->sockfd, sockfd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_recv_args->count, size);
    COPY_VALUE_TO_UNTRUSTED(&ocall_recv_args->addrlen, addrlen);
    void* untrusted_addr = addr ? sgx_alloc_on_ustack_aligned(addrlen, alignof(*addr)) : NULL;
    void* untrusted_control = control ? sgx_alloc_on_ustack(controllen) : NULL;
    if ((addr && !untrusted_addr) || (control && !untrusted_control)) {
        retval = -EPERM;
        goto out;
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_recv_args->buf, obuf);
    COPY_VALUE_TO_UNTRUSTED(&ocall_recv_args->addr, untrusted_addr);
    COPY_VALUE_TO_UNTRUSTED(&ocall_recv_args->control, untrusted_control);
    COPY_VALUE_TO_UNTRUSTED(&ocall_recv_args->controllen, controllen);
    COPY_VALUE_TO_UNTRUSTED(&ocall_recv_args->flags, flags);

    retval = sgx_exitless_ocall(OCALL_RECV, ocall_recv_args);

    if (retval < 0) {
        if (retval != -EAGAIN && retval != -EWOULDBLOCK && retval != -EBADF
                && retval != -ECONNREFUSED && retval != -ECONNRESET && retval != -EINTR
                && retval != -EINVAL && retval != -ENOMEM && retval != -ENOTCONN
                && retval != -ENOTSOCK) {
            retval = -EPERM;
        }
        goto out;
    }

    if (!(flags & MSG_TRUNC)) {
        if ((size_t)retval > size) {
            retval = -EPERM;
            goto out;
        }
    } else {
        /* Little sanity check - there are no such big packets. Can help user apps doing some
         * arithmetic on the return value without checking for overflows. */
        if ((size_t)retval >= (1ul << 48)) {
            retval = -EPERM;
            goto out;
        }
    }

    if (addr && addrlen) {
        size_t untrusted_addrlen = COPY_UNTRUSTED_VALUE(&ocall_recv_args->addrlen);
        if (!sgx_copy_to_enclave(addr, addrlen, untrusted_addr, untrusted_addrlen)) {
            retval = -EPERM;
            goto out;
        }
        *addrlenptr = untrusted_addrlen;
    }

    if (control && controllen) {
        size_t untrusted_controllen = COPY_UNTRUSTED_VALUE(&ocall_recv_args->controllen);
        bool copied = sgx_copy_to_enclave(control, controllen, untrusted_control,
                                          untrusted_controllen);
        if (!copied) {
            retval = -EPERM;
            goto out;
        }
        *controllenptr = untrusted_controllen;
    }

    size_t host_buf_idx = 0;
    size_t data_size = MIN(size, (size_t)retval);
    for (size_t i = 0; i < iov_len && host_buf_idx < data_size; i++) {
        size_t this_size = MIN(data_size - host_buf_idx, iov[i].iov_len);
        if (!sgx_copy_to_enclave(iov[i].iov_base, iov[i].iov_len,
                                 (char*)obuf + host_buf_idx, this_size)) {
            retval = -EPERM;
            goto out;
        }
        host_buf_idx += this_size;
    }

    /* `retval` already set. */

out:
    sgx_reset_ustack(old_ustack);
    if (is_obuf_mapped)
        ocall_munmap_untrusted_cache(obuf, ALLOC_ALIGN_UP(size), need_munmap);
    return retval;
}

ssize_t ocall_send(int sockfd, const struct iovec* iov, size_t iov_len, const void* addr,
                   size_t addrlen, void* control, size_t controllen, unsigned int flags) {
    ssize_t retval = 0;
    void* obuf = NULL;
    bool is_obuf_mapped = false;
    struct ocall_send* ocall_send_args;
    bool need_munmap;

    void* old_ustack = sgx_prepare_ustack();

    size_t size = 0;
    for (size_t i = 0; i < iov_len; i++) {
        size += iov[i].iov_len;
    }

    if ((size + addrlen + controllen) > MAX_UNTRUSTED_STACK_BUF) {
        /* Buffer is too big for untrusted stack - use untrusted heap instead. */
        retval = ocall_mmap_untrusted_cache(ALLOC_ALIGN_UP(size), &obuf, &need_munmap);
        if (retval < 0)
            goto out;
        is_obuf_mapped = true;
    } else {
        obuf = sgx_alloc_on_ustack(size);
    }
    if (!obuf) {
        retval = -EPERM;
        goto out;
    }

    size = 0;
    for (size_t i = 0; i < iov_len; i++) {
        memcpy((char*)obuf + size, iov[i].iov_base, iov[i].iov_len);
        size += iov[i].iov_len;
    }

    ocall_send_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_send_args),
                                                  alignof(*ocall_send_args));
    if (!ocall_send_args) {
        retval = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_send_args->sockfd, sockfd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_send_args->count, size);
    COPY_VALUE_TO_UNTRUSTED(&ocall_send_args->addrlen, addrlen);
    void* untrusted_addr = addr ? sgx_copy_to_ustack(addr, addrlen) : NULL;
    void* untrusted_control = control ? sgx_copy_to_ustack(control, controllen) : NULL;
    if ((addr && !untrusted_addr) || (control && !untrusted_control)) {
        retval = -EPERM;
        goto out;
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_send_args->buf, obuf);
    COPY_VALUE_TO_UNTRUSTED(&ocall_send_args->addr, untrusted_addr);
    COPY_VALUE_TO_UNTRUSTED(&ocall_send_args->control, untrusted_control);
    COPY_VALUE_TO_UNTRUSTED(&ocall_send_args->controllen, controllen);
    COPY_VALUE_TO_UNTRUSTED(&ocall_send_args->flags, flags);

    retval = sgx_exitless_ocall(OCALL_SEND, ocall_send_args);

    if (retval < 0 && retval != -EACCES && retval != -EAGAIN && retval != -EWOULDBLOCK &&
            retval != -EALREADY && retval != -EBADF && retval != -ECONNRESET &&
            retval != -EINTR && retval != -EINVAL && retval != -EISCONN && retval != -EMSGSIZE &&
            retval != -ENOMEM && retval != -ENOBUFS && retval != -ENOTCONN && retval != -ENOTSOCK &&
            retval != -EOPNOTSUPP && retval != -EPIPE) {
        retval = -EPERM;
    }

    if (retval > 0 && (size_t)retval > size) {
        retval = -EPERM;
        goto out;
    }

out:
    sgx_reset_ustack(old_ustack);
    if (is_obuf_mapped)
        ocall_munmap_untrusted_cache(obuf, ALLOC_ALIGN_UP(size), need_munmap);
    return retval;
}

int ocall_setsockopt(int sockfd, int level, int optname, const void* optval, size_t optlen) {
    int retval = 0;
    struct ocall_setsockopt* ocall_setsockopt_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_setsockopt_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_setsockopt_args),
                                                        alignof(*ocall_setsockopt_args));
    if (!ocall_setsockopt_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_setsockopt_args->sockfd, sockfd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_setsockopt_args->level, level);
    COPY_VALUE_TO_UNTRUSTED(&ocall_setsockopt_args->optname, optname);
    COPY_VALUE_TO_UNTRUSTED(&ocall_setsockopt_args->optlen, 0);
    COPY_VALUE_TO_UNTRUSTED(&ocall_setsockopt_args->optval, NULL);

    if (optval && optlen > 0) {
        COPY_VALUE_TO_UNTRUSTED(&ocall_setsockopt_args->optlen, optlen);
        void* untrusted_optval = sgx_copy_to_ustack(optval, optlen);
        if (!untrusted_optval) {
            sgx_reset_ustack(old_ustack);
            return -EPERM;
        }
        COPY_VALUE_TO_UNTRUSTED(&ocall_setsockopt_args->optval, untrusted_optval);
    }

    do {
        retval = sgx_exitless_ocall(OCALL_SETSOCKOPT, ocall_setsockopt_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EBADF && retval != -EINVAL && retval != -ENOPROTOOPT &&
            retval != -ENOTSOCK) {
        retval = -EPERM;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_shutdown(int sockfd, int how) {
    int retval = 0;
    struct ocall_shutdown* ocall_shutdown_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_shutdown_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_shutdown_args),
                                                      alignof(*ocall_shutdown_args));
    if (!ocall_shutdown_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_shutdown_args->sockfd, sockfd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_shutdown_args->how, how);

    do {
        retval = sgx_exitless_ocall(OCALL_SHUTDOWN, ocall_shutdown_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EBADF && retval != -EINVAL && retval != -ENOTCONN &&
            retval != -ENOTSOCK) {
        retval = -EPERM;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_gettime(uint64_t* microsec_ptr) {
    int retval = 0;
    struct ocall_gettime* ocall_gettime_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_gettime_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_gettime_args),
                                                     alignof(*ocall_gettime_args));
    if (!ocall_gettime_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    /* Last seen time value. This guards against time rewinding. */
    static uint64_t last_microsec = 0;
    uint64_t last_microsec_before_ocall = __atomic_load_n(&last_microsec, __ATOMIC_ACQUIRE);
    do {
        retval = sgx_exitless_ocall(OCALL_GETTIME, ocall_gettime_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EINVAL && retval != -EPERM) {
        retval = -EPERM;
    }

    if (!retval) {
        uint64_t microsec = COPY_UNTRUSTED_VALUE(&ocall_gettime_args->microsec);
        if (microsec < last_microsec_before_ocall) {
            /* Probably a malicious host. */
            log_error("OCALL_GETTIME returned time value smaller than in the previous call");
            _PalProcessExit(1);
        }
        /* Update `last_microsec`. */
        uint64_t expected_microsec = last_microsec_before_ocall;
        while (expected_microsec < microsec) {
            if (__atomic_compare_exchange_n(&last_microsec, &expected_microsec, microsec,
                                            /*weak=*/true, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) {
                break;
            }
        }
        *microsec_ptr = MAX(microsec, expected_microsec);
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

void ocall_sched_yield(void) {
    void* old_ustack = sgx_prepare_ustack();

    /* NOTE: no reason to use exitless for `sched_yield` and it always succeeds. */
    (void)sgx_ocall(OCALL_SCHED_YIELD, NULL);

    sgx_reset_ustack(old_ustack);
}

int ocall_poll(struct pollfd* fds, size_t nfds, uint64_t* timeout_us) {
    int retval = 0;
    size_t nfds_bytes = nfds * sizeof(struct pollfd);
    struct ocall_poll* ocall_poll_args;
    uint64_t remaining_time_us = timeout_us ? *timeout_us : (uint64_t)-1;

    void* old_ustack = sgx_prepare_ustack();
    ocall_poll_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_poll_args),
                                                  alignof(*ocall_poll_args));
    if (!ocall_poll_args) {
        retval = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_poll_args->nfds, nfds);
    COPY_VALUE_TO_UNTRUSTED(&ocall_poll_args->timeout_us, remaining_time_us);
    void* untrusted_fds = sgx_copy_to_ustack(fds, nfds_bytes);
    if (!untrusted_fds) {
        retval = -EPERM;
        goto out;
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_poll_args->fds, untrusted_fds);

    retval = sgx_exitless_ocall(OCALL_POLL, ocall_poll_args);

    if (timeout_us) {
        remaining_time_us = retval == 0 ? 0 : COPY_UNTRUSTED_VALUE(&ocall_poll_args->timeout_us);
        if (remaining_time_us > *timeout_us) {
            remaining_time_us = *timeout_us;
        }
    }

    if (retval < 0 && retval != -EINTR && retval != -EINVAL && retval != -ENOMEM) {
        retval = -EPERM;
    }

    if (retval >= 0) {
        if ((size_t)retval > nfds) {
            retval = -EPERM;
            goto out;
        }
        if (!sgx_copy_to_enclave(fds, nfds_bytes, untrusted_fds, nfds_bytes)) {
            retval = -EPERM;
            goto out;
        }
    }

out:
    if (timeout_us) {
        *timeout_us = remaining_time_us;
    }
    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_rename(const char* oldpath, const char* newpath) {
    int retval = 0;
    size_t old_size = oldpath ? strlen(oldpath) + 1 : 0;
    size_t new_size = newpath ? strlen(newpath) + 1 : 0;
    struct ocall_rename* ocall_rename_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_rename_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_rename_args),
                                                    alignof(*ocall_rename_args));
    if (!ocall_rename_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    void* untrusted_oldpath = sgx_copy_to_ustack(oldpath, old_size);
    void* untrusted_newpath = sgx_copy_to_ustack(newpath, new_size);
    if (!untrusted_oldpath || !untrusted_newpath) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_rename_args->oldpath, untrusted_oldpath);
    COPY_VALUE_TO_UNTRUSTED(&ocall_rename_args->newpath, untrusted_newpath);

    do {
        retval = sgx_exitless_ocall(OCALL_RENAME, ocall_rename_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EACCES && retval != -EBUSY && retval != -EINVAL &&
            retval != -EISDIR && retval != -ELOOP && retval != -EMLINK &&
            retval != -ENAMETOOLONG && retval != -ENOENT && retval != -ENOMEM &&
            retval != -ENOTDIR && retval != -ENOTEMPTY && retval != -EEXIST && retval != -EPERM &&
            retval != -EROFS) {
        retval = -EPERM;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_delete(const char* pathname) {
    int retval = 0;
    size_t path_size = pathname ? strlen(pathname) + 1 : 0;
    struct ocall_delete* ocall_delete_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_delete_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_delete_args),
                                                    alignof(*ocall_delete_args));
    if (!ocall_delete_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    void* untrusted_pathname = sgx_copy_to_ustack(pathname, path_size);
    if (!untrusted_pathname) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_delete_args->pathname, untrusted_pathname);

    do {
        retval = sgx_exitless_ocall(OCALL_DELETE, ocall_delete_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EACCES && retval != -EBUSY && retval != -EIO &&
            retval != -EISDIR && retval != -ELOOP && retval != -ENAMETOOLONG &&
            retval != -ENOENT && retval != -ENOMEM && retval != -ENOTDIR && retval != -EPERM &&
            retval != -EROFS && retval != -EINVAL && retval != -ENOTEMPTY) {
        retval = -EPERM;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_debug_map_add(const char* name, void* addr) {
    int retval = 0;

#ifdef DEBUG
    size_t size = strlen(name) + 1;
    struct ocall_debug_map_add* ocall_debug_map_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_debug_map_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_debug_map_args),
                                                       alignof(*ocall_debug_map_args));
    if (!ocall_debug_map_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    void* untrusted_name = sgx_copy_to_ustack(name, size);
    if (!untrusted_name) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_debug_map_args->name, untrusted_name);
    COPY_VALUE_TO_UNTRUSTED(&ocall_debug_map_args->addr, addr);

    do {
        retval = sgx_exitless_ocall(OCALL_DEBUG_MAP_ADD, ocall_debug_map_args);
    } while (retval == -EINTR);

    sgx_reset_ustack(old_ustack);
#else
    __UNUSED(name);
    __UNUSED(addr);
#endif

    return retval;
}

int ocall_debug_map_remove(void* addr) {
    int retval = 0;

#ifdef DEBUG
    struct ocall_debug_map_remove* ocall_debug_map_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_debug_map_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_debug_map_args),
                                                       alignof(*ocall_debug_map_args));
    if (!ocall_debug_map_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_debug_map_args->addr, addr);

    do {
        retval = sgx_exitless_ocall(OCALL_DEBUG_MAP_REMOVE, ocall_debug_map_args);
    } while (retval == -EINTR);

    sgx_reset_ustack(old_ustack);
#else
    __UNUSED(addr);
#endif

    return retval;
}

int ocall_debug_describe_location(uintptr_t addr, char* buf, size_t buf_size) {
#ifdef DEBUG
    int retval = 0;

    struct ocall_debug_describe_location* ocall_debug_describe_args;
    char* untrusted_buf;

    void* old_ustack = sgx_prepare_ustack();
    ocall_debug_describe_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_debug_describe_args),
                                                            alignof(*ocall_debug_describe_args));
    untrusted_buf = sgx_alloc_on_ustack(buf_size);
    if (!ocall_debug_describe_args || !untrusted_buf) {
        retval = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_debug_describe_args->addr, addr);
    COPY_VALUE_TO_UNTRUSTED(&ocall_debug_describe_args->buf, untrusted_buf);
    COPY_VALUE_TO_UNTRUSTED(&ocall_debug_describe_args->buf_size, buf_size);

    do {
        retval = sgx_exitless_ocall(OCALL_DEBUG_DESCRIBE_LOCATION, ocall_debug_describe_args);
    } while (retval == -EINTR);

    if (retval == 0) {
        if (!sgx_copy_to_enclave(buf, buf_size, untrusted_buf, buf_size)) {
            retval = -EPERM;
            goto out;
        }
    }
out:
    sgx_reset_ustack(old_ustack);
    return retval;
#else
    __UNUSED(addr);
    __UNUSED(buf);
    __UNUSED(buf_size);
    return -ENOSYS;
#endif
}

int ocall_eventfd(int flags) {
    int retval = 0;
    struct ocall_eventfd* ocall_eventfd_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_eventfd_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_eventfd_args),
                                                     alignof(*ocall_eventfd_args));
    if (!ocall_eventfd_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_eventfd_args->flags, flags);

    do {
        retval = sgx_exitless_ocall(OCALL_EVENTFD, ocall_eventfd_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EINVAL && retval != -EMFILE && retval != -ENFILE &&
            retval != -ENODEV && retval != -ENOMEM) {
        retval = -EPERM;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_ioctl(int fd, unsigned int cmd, unsigned long arg) {
    int retval;
    struct ocall_ioctl* ocall_ioctl_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_ioctl_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_ioctl_args),
                                                   alignof(*ocall_ioctl_args));
    if (!ocall_ioctl_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_ioctl_args->fd, fd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_ioctl_args->cmd, cmd);
    COPY_VALUE_TO_UNTRUSTED(&ocall_ioctl_args->arg, arg);

    retval = sgx_exitless_ocall(OCALL_IOCTL, ocall_ioctl_args);
    /* in general case, IOCTL may return any error code (the list of possible error codes is not
     * standardized and is up to the Linux driver/kernel module), so no check of `retval` here */

    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_get_quote(const sgx_spid_t* spid, bool linkable, const sgx_report_t* report,
                    const sgx_quote_nonce_t* nonce, char** quote, size_t* quote_len) {
    int retval;
    struct ocall_get_quote* ocall_quote_args;
    char* buf = NULL;

    void* old_ustack = sgx_prepare_ustack();
    ocall_quote_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_quote_args),
                                                   alignof(*ocall_quote_args));
    if (!ocall_quote_args) {
        retval = -ENOMEM;
        goto out;
    }

    if (spid) {
        COPY_VALUE_TO_UNTRUSTED(&ocall_quote_args->is_epid, true);
        memcpy(&ocall_quote_args->spid, spid, sizeof(*spid));
    } else {
        COPY_VALUE_TO_UNTRUSTED(&ocall_quote_args->is_epid, false);
        memset(&ocall_quote_args->spid, 0, sizeof(ocall_quote_args->spid)); /* for sanity */
    }

    memcpy(&ocall_quote_args->report, report, sizeof(*report));
    memcpy(&ocall_quote_args->nonce, nonce, sizeof(*nonce));
    COPY_VALUE_TO_UNTRUSTED(&ocall_quote_args->linkable, linkable);

    do {
        retval = sgx_exitless_ocall(OCALL_GET_QUOTE, ocall_quote_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EACCES && retval != -EINVAL && retval != -ENOMEM &&
            retval != -EPERM && retval != -EAGAIN && retval != -ECONNREFUSED) {
        /* GET_QUOTE OCALL may return many error codes, but we sanitize all error codes except the
         * above (most important ones) because PAL/LibOS logic doesn't care about specific errors */
        retval = -EPERM;
    }

    if (retval >= 0) {
        struct ocall_get_quote quote_copied;
        if (!sgx_copy_to_enclave(&quote_copied, sizeof(quote_copied), ocall_quote_args,
                                 sizeof(*ocall_quote_args))) {
            retval = -EACCES;
            goto out;
        }

        /* copy each field inside and free the out-of-enclave buffers */
        if (quote_copied.quote) {
            size_t len = quote_copied.quote_len;
            if (len > SGX_QUOTE_MAX_SIZE) {
                retval = -EACCES;
                goto out;
            }

            buf = malloc(len);
            if (!buf) {
                retval = -ENOMEM;
                goto out;
            }

            if (!sgx_copy_to_enclave(buf, len, quote_copied.quote, len)) {
                retval = -EACCES;
                goto out;
            }

            retval = ocall_munmap_untrusted(quote_copied.quote, ALLOC_ALIGN_UP(len));
            if (retval < 0) {
                goto out;
            }

            *quote     = buf;
            *quote_len = len;
        }
    }

out:
    if (retval < 0)
        free(buf);
    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_sched_setaffinity(void* tcs, unsigned long* cpu_mask, size_t cpu_mask_len) {
    int retval = 0;
    struct ocall_sched_setaffinity* ocall_sched_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_sched_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_sched_args),
                                                   alignof(*ocall_sched_args));
    if (!ocall_sched_args) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }

    size_t cpu_mask_size = cpu_mask_len * sizeof(*cpu_mask);
    COPY_VALUE_TO_UNTRUSTED(&ocall_sched_args->tcs, tcs);
    COPY_VALUE_TO_UNTRUSTED(&ocall_sched_args->cpumask_size, cpu_mask_size);
    void* untrusted_cpu_mask = sgx_copy_to_ustack(cpu_mask, cpu_mask_size);
    if (!untrusted_cpu_mask) {
        sgx_reset_ustack(old_ustack);
        return -EPERM;
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_sched_args->cpu_mask, untrusted_cpu_mask);

    do {
        retval = sgx_exitless_ocall(OCALL_SCHED_SETAFFINITY, ocall_sched_args);
    } while (retval == -EINTR);

    if (retval < 0 && retval != -EINVAL && retval != -EPERM && retval != -ESRCH) {
        retval = -EPERM;
    }

    sgx_reset_ustack(old_ustack);
    return retval;
}

static bool is_cpumask_valid(unsigned long* cpu_mask, size_t cpu_mask_len) {
    /* Linux seems to allow setting affinity to offline threads, so we only need to check against
     * the count of possible threads. */
    size_t max_bitmask_len = BITS_TO_LONGS(g_pal_public_state.topo_info.threads_cnt);
    if (cpu_mask_len < max_bitmask_len) {
        return true;
    }
    assert(max_bitmask_len > 0);

    size_t invalid_bits_count = max_bitmask_len * BITS_IN_TYPE(unsigned long)
                                - g_pal_public_state.topo_info.threads_cnt;
    if (cpu_mask[max_bitmask_len - 1] & SET_HIGHEST_N_BITS(unsigned long, invalid_bits_count)) {
        return false;
    }

    for (size_t i = max_bitmask_len; i < cpu_mask_len; i++) {
        if (cpu_mask[i]) {
            return false;
        }
    }

    return true;
}

int ocall_sched_getaffinity(void* tcs, unsigned long* cpu_mask, size_t cpu_mask_len) {
    int retval = 0;
    struct ocall_sched_getaffinity* ocall_sched_args;

    void* old_ustack = sgx_prepare_ustack();
    ocall_sched_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_sched_args),
                                                   alignof(*ocall_sched_args));
    if (!ocall_sched_args) {
        retval = -EPERM;
        goto out;
    }

    size_t cpu_mask_size = cpu_mask_len * sizeof(*cpu_mask);
    COPY_VALUE_TO_UNTRUSTED(&ocall_sched_args->tcs, tcs);
    COPY_VALUE_TO_UNTRUSTED(&ocall_sched_args->cpumask_size, cpu_mask_size);
    void* untrusted_cpu_mask = sgx_alloc_on_ustack_aligned(cpu_mask_size, alignof(*cpu_mask));
    if (!untrusted_cpu_mask) {
        retval = -EPERM;
        goto out;
    }
    COPY_VALUE_TO_UNTRUSTED(&ocall_sched_args->cpu_mask, untrusted_cpu_mask);

    do {
        retval = sgx_exitless_ocall(OCALL_SCHED_GETAFFINITY, ocall_sched_args);
    } while (retval == -EINTR);

    if (retval < 0) {
        if (retval != -EINVAL && retval != -EPERM && retval != -ESRCH) {
            retval = -EPERM;
        }
        goto out;
    }

    if (retval % sizeof(*cpu_mask)) {
        retval = -EPERM;
        goto out;
    }

    if (!sgx_copy_to_enclave(cpu_mask, cpu_mask_size, untrusted_cpu_mask, retval)) {
        retval = -EPERM;
        goto out;
    }

    assert((size_t)retval <= cpu_mask_size);
    if (!is_cpumask_valid(cpu_mask, retval / sizeof(*cpu_mask))) {
        retval = -EPERM;
        goto out;
    }

    retval = 0;

out:
    sgx_reset_ustack(old_ustack);
    return retval;
}

int ocall_edmm_restrict_pages_perm(uint64_t addr, size_t count, uint64_t prot) {
    int ret;
    void* old_ustack = sgx_prepare_ustack();

    struct ocall_edmm_restrict_pages_perm* ocall_args;
    ocall_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_args), alignof(*ocall_args));
    if (!ocall_args) {
        ret = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_args->addr, addr);
    COPY_VALUE_TO_UNTRUSTED(&ocall_args->count, count);
    COPY_VALUE_TO_UNTRUSTED(&ocall_args->prot, prot);

    do {
        ret = sgx_exitless_ocall(OCALL_EDMM_RESTRICT_PAGES_PERM, ocall_args);
    } while (ret == -EINTR);
    if (ret < 0) {
        if (ret != -EINVAL && ret != -EPERM && ret != -EFAULT) {
            ret = -EPERM;
        }
        goto out;
    }

    ret = 0;

out:
    sgx_reset_ustack(old_ustack);
    return ret;
}

int ocall_edmm_modify_pages_type(uint64_t addr, size_t count, uint64_t type) {
    int ret;
    void* old_ustack = sgx_prepare_ustack();

    struct ocall_edmm_modify_pages_type* ocall_args;
    ocall_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_args), alignof(*ocall_args));
    if (!ocall_args) {
        ret = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_args->addr, addr);
    COPY_VALUE_TO_UNTRUSTED(&ocall_args->count, count);
    COPY_VALUE_TO_UNTRUSTED(&ocall_args->type, type);

    do {
        ret = sgx_exitless_ocall(OCALL_EDMM_MODIFY_PAGES_TYPE, ocall_args);
    } while (ret == -EINTR);
    if (ret < 0) {
        if (ret != -EINVAL && ret != -EPERM && ret != -EFAULT) {
            ret = -EPERM;
        }
        goto out;
    }

    ret = 0;

out:
    sgx_reset_ustack(old_ustack);
    return ret;
}

int ocall_edmm_remove_pages(uint64_t addr, size_t count) {
    int ret;
    void* old_ustack = sgx_prepare_ustack();

    struct ocall_edmm_remove_pages* ocall_args;
    ocall_args = sgx_alloc_on_ustack_aligned(sizeof(*ocall_args), alignof(*ocall_args));
    if (!ocall_args) {
        ret = -EPERM;
        goto out;
    }

    COPY_VALUE_TO_UNTRUSTED(&ocall_args->addr, addr);
    COPY_VALUE_TO_UNTRUSTED(&ocall_args->count, count);

    do {
        ret = sgx_exitless_ocall(OCALL_EDMM_REMOVE_PAGES, ocall_args);
    } while (ret == -EINTR);
    if (ret < 0) {
        if (ret != -EINVAL && ret != -EPERM && ret != -EFAULT) {
            ret = -EPERM;
        }
        goto out;
    }

    ret = 0;

out:
    sgx_reset_ustack(old_ustack);
    return ret;
}
