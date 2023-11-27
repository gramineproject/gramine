/* SPDX-License-Identifier: LGPL-3.0-or-later */

#include <stddef.h> /* needed by <linux/signal.h> for size_t */
#include <asm/errno.h>
#include <asm/prctl.h>
#include <asm/signal.h>
#include <linux/signal.h>

#include "asan.h"
#include "assert.h"
#include "gdb_integration/sgx_gdb.h"
#include "host_ecalls.h"
#include "host_internal.h"
#include "spinlock.h"

struct enclave_thread_map {
    unsigned int    tid;
    sgx_arch_tcs_t* tcs;
};

static struct enclave_thread_map* g_enclave_thread_map = NULL;
static spinlock_t g_enclave_thread_map_lock = INIT_SPINLOCK_UNLOCKED;

/* total number of items in g_enclave_thread_map; protected by g_enclave_thread_map_lock */
static size_t g_enclave_thread_num = 0;

bool g_sgx_enable_stats = false;

/* this function is called only on thread/process exit (never in the middle of thread exec) */
void update_and_print_stats(bool process_wide) {
    static atomic_ulong g_eenter_cnt       = 0;
    static atomic_ulong g_eexit_cnt        = 0;
    static atomic_ulong g_aex_cnt          = 0;
    static atomic_ulong g_sync_signal_cnt  = 0;
    static atomic_ulong g_async_signal_cnt = 0;

    if (!g_sgx_enable_stats)
        return;

    PAL_HOST_TCB* tcb = pal_get_host_tcb();

    int tid = DO_SYSCALL(gettid);
    assert(tid > 0);
    log_always("----- SGX stats for thread %d -----\n"
               "  # of EENTERs:        %lu\n"
               "  # of EEXITs:         %lu\n"
               "  # of AEXs:           %lu\n"
               "  # of sync signals:   %lu\n"
               "  # of async signals:  %lu",
               tid, tcb->eenter_cnt, tcb->eexit_cnt, tcb->aex_cnt,
               tcb->sync_signal_cnt, tcb->async_signal_cnt);

    g_eenter_cnt       += tcb->eenter_cnt;
    g_eexit_cnt        += tcb->eexit_cnt;
    g_aex_cnt          += tcb->aex_cnt;
    g_sync_signal_cnt  += tcb->sync_signal_cnt;
    g_async_signal_cnt += tcb->async_signal_cnt;

    if (process_wide) {
        int pid = g_host_pid;
        assert(pid > 0);
        log_always("----- Total SGX stats for process %d -----\n"
                   "  # of EENTERs:        %lu\n"
                   "  # of EEXITs:         %lu\n"
                   "  # of AEXs:           %lu\n"
                   "  # of sync signals:   %lu\n"
                   "  # of async signals:  %lu",
                   pid, g_eenter_cnt, g_eexit_cnt, g_aex_cnt,
                   g_sync_signal_cnt, g_async_signal_cnt);
    }
}

void pal_host_tcb_init(PAL_HOST_TCB* tcb, void* stack, void* alt_stack) {
    tcb->self = tcb;
    tcb->tcs = NULL;    /* initialized by child thread */
    tcb->stack = stack;
    tcb->alt_stack = alt_stack;

    tcb->eenter_cnt       = 0;
    tcb->eexit_cnt        = 0;
    tcb->aex_cnt          = 0;
    tcb->sync_signal_cnt  = 0;
    tcb->async_signal_cnt = 0;

    tcb->profile_sample_time = 0;

    tcb->last_async_event = PAL_EVENT_NO_EVENT;
}

int create_tcs_mapper(void* tcs_base, unsigned int thread_num) {
    sgx_arch_tcs_t* enclave_tcs = tcs_base;

    g_enclave_thread_map = malloc(sizeof(struct enclave_thread_map) * thread_num);
    if (!g_enclave_thread_map) {
        return -ENOMEM;
    }

    for (uint32_t i = 0; i < thread_num; i++) {
        g_enclave_thread_map[i].tid = 0;
        g_enclave_thread_map[i].tcs = &enclave_tcs[i];
    }
    g_enclave_thread_num = thread_num;
    return 0;
}

static int add_dynamic_tcs(sgx_arch_tcs_t* tcs) {
    int ret;
    struct enclave_dbginfo* dbginfo = (struct enclave_dbginfo*)DBGINFO_ADDR;

    ret = set_tcs_debug_flag_if_debugging((void**)&tcs, /*count=*/1);
    if (ret < 0) {
        return ret;
    }

    size_t i = 0;
    spinlock_lock(&g_enclave_thread_map_lock);
    for (i = 0; i < g_enclave_thread_num; i++) {
        if (g_enclave_thread_map[i].tcs == tcs) {
            log_error("Dynamic TCS page %p was already added to the list of enclave threads", tcs);
            BUG();
        }
        if (!g_enclave_thread_map[i].tcs) {
            g_enclave_thread_map[i].tcs = tcs;
            dbginfo->tcs_addrs[i] = tcs;
            break;
        }
    }

    if (i == g_enclave_thread_num) {
        /* Current map is full. */
        if (g_enclave_thread_num >= MAX_DBG_THREADS) {
            log_error("Number of simultaneous enclave threads equals to or exceeds %u, "
                      "not supported", MAX_DBG_THREADS);
            ret = -EOVERFLOW;
            goto out;
        }

        size_t new_enclave_thread_num = MIN(g_enclave_thread_num * 2, (size_t)MAX_DBG_THREADS);
        struct enclave_thread_map* new_enclave_thread_map = realloc(
            g_enclave_thread_map, sizeof(struct enclave_thread_map) * new_enclave_thread_num);
        if (!new_enclave_thread_map) {
            ret = -ENOMEM;
            goto out;
        }

        memset(new_enclave_thread_map + g_enclave_thread_num, 0,
               sizeof(struct enclave_thread_map) * (new_enclave_thread_num - g_enclave_thread_num));

        g_enclave_thread_num = new_enclave_thread_num;
        g_enclave_thread_map = new_enclave_thread_map;

        g_enclave_thread_map[i].tcs = tcs;
        dbginfo->tcs_addrs[i] = tcs;
    }

    ret = 0;
out:
    spinlock_unlock(&g_enclave_thread_map_lock);
    return ret;
}

void map_tcs(unsigned int tid) {
    while (true) {
        spinlock_lock(&g_enclave_thread_map_lock);
        for (size_t i = 0; i < g_enclave_thread_num; i++) {
            if (!g_enclave_thread_map[i].tcs)
                continue;
            if (!g_enclave_thread_map[i].tid) {
                g_enclave_thread_map[i].tid = tid;
                pal_get_host_tcb()->tcs = g_enclave_thread_map[i].tcs;
                ((struct enclave_dbginfo*)DBGINFO_ADDR)->thread_tids[i] = tid;
                spinlock_unlock(&g_enclave_thread_map_lock);
                return;
            }
        }

        if (!g_pal_enclave.edmm_enabled) {
            /* no static or dynamic TCS pages available, bail out */
            spinlock_unlock(&g_enclave_thread_map_lock);
            return;
        }
        spinlock_unlock(&g_enclave_thread_map_lock);
        /*
         * At least one dynamic TCS is available in the in-enclave map of TCSs. However,
         * the host-enclave map of TCSs may be briefly out of sync with the in-enclave map
         * because the enclave decided to reuse some TCS that is being currently unmapped
         * by another thread -- in this case, the host-enclave map may still have all TCS slots
         * occupied, but only for a small window of time until the exiting thread calls
         * `unmap_my_tcs()`.
         */
        CPU_RELAX();
    }
}

void unmap_my_tcs(void) {
    size_t i = 0;
    spinlock_lock(&g_enclave_thread_map_lock);
    for (i = 0; i < g_enclave_thread_num; i++)
        if (g_enclave_thread_map[i].tcs == pal_get_host_tcb()->tcs) {
            g_enclave_thread_map[i].tid = 0;
            ((struct enclave_dbginfo*)DBGINFO_ADDR)->thread_tids[i] = 0;
            break;
        }
    assert(i < g_enclave_thread_num);
    pal_get_host_tcb()->tcs = NULL;
    spinlock_unlock(&g_enclave_thread_map_lock);
}

int current_enclave_thread_cnt(void) {
    int ret = 0;
    spinlock_lock(&g_enclave_thread_map_lock);
    for (size_t i = 0; i < g_enclave_thread_num; i++)
        if (g_enclave_thread_map[i].tid)
            ret++;
    spinlock_unlock(&g_enclave_thread_map_lock);
    return ret;
}

/*
 * pal_thread_init(): An initialization wrapper of a newly-created thread (including
 * the first thread). This function accepts a TCB pointer to be set to the GS register
 * of the thread. The rest of the TCB is used as the alternative stack for signal
 * handling. Notice that this sets up the untrusted thread -- an enclave thread is set
 * up by other means (e.g., the GS register is set by an SGX-enforced TCS.OGSBASGX).
 */
__attribute_no_sanitize_address
int pal_thread_init(void* tcbptr) {
    PAL_HOST_TCB* tcb = tcbptr;
    int ret;

    /* set GS reg of this thread to thread's TCB; after this point, can use pal_get_host_tcb() */
    ret = DO_SYSCALL(arch_prctl, ARCH_SET_GS, tcb);
    if (ret < 0) {
        ret = -EPERM;
        goto out;
    }

    if (tcb->alt_stack) {
        stack_t ss = {
            .ss_sp    = tcb->alt_stack,
            .ss_flags = 0,
            .ss_size  = ALT_STACK_SIZE - sizeof(*tcb)
        };
        ret = DO_SYSCALL(sigaltstack, &ss, NULL);
        if (ret < 0) {
            ret = -EPERM;
            goto out;
        }
    }

    int tid = DO_SYSCALL(gettid);
    map_tcs(tid); /* updates tcb->tcs */

    if (!tcb->tcs) {
        log_error("There are no available TCS pages left for a new thread. Please try to increase"
                  " sgx.max_threads in the manifest. The current value is %lu",
                  g_pal_enclave.thread_num);
        ret = -ENOMEM;
        goto out;
    }

    if (!tcb->stack) {
        /* only first thread doesn't have a stack (it uses the one provided by Linux); first
         * thread calls ecall_enclave_start() instead of ecall_thread_start() so just exit */
        return 0;
    }

    __atomic_store_n(tcb->start_status_ptr, 0, __ATOMIC_RELAXED);

    /* not-first (child) thread, start it */
    ecall_thread_start();

    unmap_my_tcs();
    ret = 0;
out:
    if (ret != 0)
        __atomic_store_n(tcb->start_status_ptr, ret, __ATOMIC_RELAXED);
    return ret;
}

__attribute_no_sanitize_address
noreturn void thread_exit(int status) {
    PAL_HOST_TCB* tcb = pal_get_host_tcb();

    /* technically, async signals were already blocked before calling this function
     * (by sgx_ocall_exit()) but we keep it here for future proof */
    block_async_signals(true);

    update_and_print_stats(/*process_wide=*/false);

    if (tcb->alt_stack) {
        stack_t ss;
        ss.ss_sp    = NULL;
        ss.ss_flags = SS_DISABLE;
        ss.ss_size  = 0;

        /* take precautions to unset the TCB and alternative stack first */
        DO_SYSCALL(arch_prctl, ARCH_SET_GS, 0);
        DO_SYSCALL(sigaltstack, &ss, NULL);
    }

#ifdef ASAN
    asan_unpoison_current_stack((uintptr_t)tcb->stack, THREAD_STACK_SIZE + ALT_STACK_SIZE);
#endif
    /* free the thread stack (via munmap) and exit; note that exit() needs a "status" arg
     * but it could be allocated on a stack, so we must put it in register and do asm */
    __asm__ volatile("cmpq $0, %%rdi \n"        /* check if tcb->stack != NULL */
                     "je 1f \n"
                     "syscall \n"               /* all args are already prepared, call munmap */
                     "1: \n"
                     "mov %[nr_exit], %%rax \n"
                     "mov %[exit_code], %%edi \n"
                     "syscall \n"               /* all args are prepared, call exit  */
                     "ud2 \n"
                     "jmp 1b \n"
                     :
                     : "a" (__NR_munmap), "D" (tcb->stack), "S" (THREAD_STACK_SIZE + ALT_STACK_SIZE),
                       [nr_exit] "i" (__NR_exit), [exit_code] "r" (status)
                     : "memory", "rcx", "r11"
    );
    __builtin_unreachable();
}

int clone_thread(void* dynamic_tcs) {
    int ret = 0;

    if (dynamic_tcs) {
        /* enclave decided to add a new TCS page (to accommodate more enclave threads) */
        ret = add_dynamic_tcs(dynamic_tcs);
        if (ret < 0) {
            return ret;
        }
    }

    void* stack = (void*)DO_SYSCALL(mmap, NULL, THREAD_STACK_SIZE + ALT_STACK_SIZE,
                                    PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (IS_PTR_ERR(stack))
        return -ENOMEM;

    /* Stack layout for the new thread looks like this (recall that stacks grow towards lower
     * addresses on Linux on x86-64):
     *
     *       stack +--> +-------------------+
     *                  |  child stack      | THREAD_STACK_SIZE
     * child_stack +--> +-------------------+
     *                  |  alternate stack  | ALT_STACK_SIZE - sizeof(PAL_HOST_TCB)
     *         tcb +--> +-------------------+
     *                  |  PAL TCB          | sizeof(PAL_HOST_TCB)
     *                  +-------------------+
     *
     * Note that this whole memory region is zeroed out because we use mmap(). */

    void* child_stack_top = stack + THREAD_STACK_SIZE;

    /* initialize TCB at the top of the alternative stack */
    PAL_HOST_TCB* tcb = child_stack_top + ALT_STACK_SIZE - sizeof(PAL_HOST_TCB);
    pal_host_tcb_init(tcb, stack, child_stack_top);

    /* align child_stack to 16 */
    child_stack_top = ALIGN_DOWN_PTR(child_stack_top, 16);

    int start_status = 1;
    tcb->start_status_ptr = &start_status;

    ret = clone(pal_thread_init, child_stack_top,
                CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SYSVSEM | CLONE_THREAD | CLONE_SIGHAND,
                tcb, /*parent_tid=*/NULL, /*tls=*/NULL, /*child_tid=*/NULL, thread_exit);

    if (ret < 0) {
        DO_SYSCALL(munmap, stack, THREAD_STACK_SIZE + ALT_STACK_SIZE);
        return ret;
    }

    while ((ret = __atomic_load_n(&start_status, __ATOMIC_RELAXED)) == 1)
        CPU_RELAX();

    return ret;
}

int get_tid_from_tcs(void* tcs) {
    int tid = 0;
    spinlock_lock(&g_enclave_thread_map_lock);
    for (size_t i = 0; i < g_enclave_thread_num; i++) {
        if (g_enclave_thread_map[i].tcs == tcs) {
            tid = g_enclave_thread_map[i].tid;
            break;
        }
    }
    spinlock_unlock(&g_enclave_thread_map_lock);
    return tid ? tid : -EINVAL;
}

int set_tcs_debug_flag_if_debugging(void* tcs_addrs[], size_t count) {
    if (!g_sgx_enable_stats && !g_vtune_profile_enabled)
        return 0;

    /* set TCS.FLAGS.DBGOPTIN in enclave threads to enable perf counters, Intel PT, etc */
    int ret = DO_SYSCALL(open, "/proc/self/mem", O_RDWR | O_LARGEFILE | O_CLOEXEC, 0);
    if (ret < 0) {
        log_error("Setting TCS.FLAGS.DBGOPTIN failed: %s", unix_strerror(ret));
        return ret;
    }
    int enclave_mem = ret;

    for (size_t i = 0; i < count; i++) {
        uint64_t tcs_flags;
        uint64_t* tcs_flags_ptr = tcs_addrs[i] + offsetof(sgx_arch_tcs_t, flags);

        ret = DO_SYSCALL(pread64, enclave_mem, &tcs_flags, sizeof(tcs_flags), (off_t)tcs_flags_ptr);
        if (ret < 0) {
            log_error("Reading TCS.FLAGS.DBGOPTIN failed: %s", unix_strerror(ret));
            goto out;
        }

        tcs_flags |= TCS_FLAGS_DBGOPTIN;

        ret = DO_SYSCALL(pwrite64, enclave_mem, &tcs_flags, sizeof(tcs_flags),
                         (off_t)tcs_flags_ptr);
        if (ret < 0) {
            log_error("Writing TCS.FLAGS.DBGOPTIN failed: %s", unix_strerror(ret));
            goto out;
        }
    }
    ret = 0;
out:
    DO_SYSCALL(close, enclave_mem);
    return ret;
}
