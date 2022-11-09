#include <stdalign.h>

#include "api.h"
#include "enclave_ecalls.h"
#include "pal_ecall_types.h"
#include "pal_linux.h"
#include "sgx_arch.h"

extern uintptr_t g_enclave_base;
extern uintptr_t g_enclave_top;

static int64_t g_enclave_start_called = 0;

/* This eats 1KB of a stack, so prevent inlining. */
__attribute__((noinline)) static void init_xsave_size_from_report(void) {
    __sgx_mem_aligned sgx_target_info_t target_info = { 0 };
    alignas(128) char report_data[64] = { 0 };
    __sgx_mem_aligned sgx_report_t report = { 0 };
    sgx_report(&target_info, &report_data, &report);
    init_xsave_size(report.body.attributes.xfrm);
}

/*
 * Called from enclave_entry.S to execute ecalls.
 *
 * During normal operation handle_ecall will not return. The exception is that
 * it will return if invalid parameters are passed. In this case
 * enclave_entry.S will go into an endless loop since a clean return to host is
 * not easy in all cases.
 *
 * Parameters:
 *
 *  ecall_index:
 *      Number of requested ecall. Untrusted.
 *
 *  ecall_args:
 *      Pointer to arguments for requested ecall. Untrusted.
 *
 *  exit_target:
 *      Address to return to after EEXIT. Untrusted.
 *
 *  enclave_base_addr:
 *      Base address of enclave. Calculated dynamically in enclave_entry.S.
 *      Trusted.
 */
void handle_ecall(long ecall_index, void* ecall_args, void* exit_target, void* enclave_base_addr) {
    if (ecall_index < 0 || ecall_index >= ECALL_NR)
        return;

    if (!g_enclave_top) {
        g_enclave_base = (uintptr_t)enclave_base_addr;
        g_enclave_top  = g_enclave_base + GET_ENCLAVE_TCB(enclave_size);
    }

    /* disallow malicious URSP (that points into the enclave) */
    uintptr_t ursp = GET_ENCLAVE_TCB(gpr)->ursp;
    if (g_enclave_base <= ursp && ursp <= g_enclave_top)
        return;

    /* Sanity check. */
    if (!((uintptr_t)exit_target < g_enclave_base || g_enclave_top <= (uintptr_t)exit_target)) {
        return;
    }

    SET_ENCLAVE_TCB(exit_target,     exit_target);
    SET_ENCLAVE_TCB(ustack,          (void*)ursp);
    SET_ENCLAVE_TCB(ustack_top,      (void*)ursp);
    SET_ENCLAVE_TCB(clear_child_tid, NULL);
    SET_ENCLAVE_TCB(untrusted_area_cache.in_use, 0UL);

    int64_t t = 0;
    if (__atomic_compare_exchange_n(&g_enclave_start_called, &t, 1, /*weak=*/false,
                                    __ATOMIC_SEQ_CST, __ATOMIC_RELAXED)) {
        // ENCLAVE_START not yet called, so only valid ecall is ENCLAVE_START.
        if (ecall_index != ECALL_ENCLAVE_START) {
            // To keep things simple, we treat an invalid ecall_index like an
            // unsuccessful call to ENCLAVE_START.
            return;
        }

        struct ecall_enclave_start* start_args;
        if (!sgx_is_valid_untrusted_ptr(ecall_args, sizeof(*start_args),
                                        alignof(__typeof__(*start_args)))) {
            return;
        }
        start_args = ecall_args;

        /* xsave size must be initialized early, from a trusted source (EREPORT result) */
        init_xsave_size_from_report();

        /* pal_linux_main is responsible for checking the passed arguments */
        pal_linux_main(COPY_UNTRUSTED_VALUE(&start_args->libpal_uri),
                       COPY_UNTRUSTED_VALUE(&start_args->libpal_uri_len),
                       COPY_UNTRUSTED_VALUE(&start_args->args),
                       COPY_UNTRUSTED_VALUE(&start_args->args_size),
                       COPY_UNTRUSTED_VALUE(&start_args->env),
                       COPY_UNTRUSTED_VALUE(&start_args->env_size),
                       COPY_UNTRUSTED_VALUE(&start_args->parent_stream_fd),
                       COPY_UNTRUSTED_VALUE(&start_args->qe_targetinfo),
                       COPY_UNTRUSTED_VALUE(&start_args->topo_info),
                       COPY_UNTRUSTED_VALUE(&start_args->rpc_queue),
                       COPY_UNTRUSTED_VALUE(&start_args->dns_host_conf),
                       COPY_UNTRUSTED_VALUE(&start_args->edmm_enabled),
                       COPY_UNTRUSTED_VALUE(&start_args->reserved_mem_ranges),
                       COPY_UNTRUSTED_VALUE(&start_args->reserved_mem_ranges_size));
    } else {
        // ENCLAVE_START already called (maybe successfully, maybe not), so
        // only valid ecall is THREAD_START.
        if (ecall_index != ECALL_THREAD_START) {
            return;
        }

        // Only allow THREAD_START after successful enclave initialization.
        if (!g_pal_linuxsgx_state.enclave_initialized) {
            return;
        }

        pal_start_thread();
    }
    // pal_linux_main and pal_start_thread should never return.
}
