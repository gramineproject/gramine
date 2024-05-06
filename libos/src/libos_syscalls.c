/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "asan.h"
#include "libos_defs.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_signal.h"
#include "libos_table.h"
#include "libos_tcb.h"
#include "libos_thread.h"
#include "libos_utils.h"
#include "linux_abi/errors.h"
#include "toml_utils.h"

typedef arch_syscall_arg_t (*six_args_syscall_t)(arch_syscall_arg_t, arch_syscall_arg_t,
                                                 arch_syscall_arg_t, arch_syscall_arg_t,
                                                 arch_syscall_arg_t, arch_syscall_arg_t);

/*
 * `context` is expected to be placed at the bottom of Gramine-internal stack.
 * If you change this function please also look at `libos_syscall_rt_sigsuspend`!
 */
noreturn void libos_emulate_syscall(PAL_CONTEXT* context) {
    LIBOS_TCB_SET(context.regs, context);

    unsigned long sysnr = pal_context_get_syscall(context);
    arch_syscall_arg_t ret = 0;

    if (sysnr == GRAMINE_CUSTOM_SYSCALL_NR) {
        unsigned long args[] = { ALL_SYSCALL_ARGS(context) };
        ret = handle_libos_call(args[0], args[1], args[2]);
    } else {
        if (sysnr >= LIBOS_SYSCALL_BOUND || !libos_syscall_table[sysnr]) {
            warn_unsupported_syscall(sysnr);
            ret = -ENOSYS;
            goto out;
        }

        LIBOS_TCB_SET(context.syscall_nr, sysnr);
        six_args_syscall_t syscall_func = (six_args_syscall_t)libos_syscall_table[sysnr];

        debug_print_syscall_before(sysnr, ALL_SYSCALL_ARGS(context));
        ret = syscall_func(ALL_SYSCALL_ARGS(context));
        debug_print_syscall_after(sysnr, ret, ALL_SYSCALL_ARGS(context));
    }
out:
    pal_context_set_retval(context, ret);

    /* Some syscalls e.g. `sigreturn` could have changed context and in reality we might be not
     * returning from a syscall. */
    if (!handle_signal(context) && LIBOS_TCB_GET(context.syscall_nr) >= 0) {
        switch (ret) {
            case -ERESTARTNOHAND:
            case -ERESTARTSYS:
            case -ERESTARTNOINTR:
                restart_syscall(context, sysnr);
                break;
            default:
                break;
        }
    }

    struct libos_thread* current = get_cur_thread();
    if (current->has_saved_sigmask) {
        lock(&current->lock);
        set_sig_mask(current, &current->saved_sigmask);
        unlock(&current->lock);
        current->has_saved_sigmask = false;
    }

    LIBOS_TCB_SET(context.syscall_nr, -1);
    LIBOS_TCB_SET(context.regs, NULL);

    return_from_syscall(context);
}

__attribute_no_sanitize_address
noreturn void return_from_syscall(PAL_CONTEXT* context) {
#ifdef ASAN
    uintptr_t libos_stack_bottom = (uintptr_t)LIBOS_TCB_GET(libos_stack_bottom);
    asan_unpoison_region(libos_stack_bottom - LIBOS_THREAD_LIBOS_STACK_SIZE,
                         LIBOS_THREAD_LIBOS_STACK_SIZE);
#endif
    _return_from_syscall(context);
}

int init_syscalls(void) {
    assert(g_manifest_root);
    int ret;

    toml_table_t* manifest_sys = toml_table_in(g_manifest_root, "sys");
    if (!manifest_sys)
        return 0;

    toml_array_t* toml_disallowed_syscalls = toml_array_in(manifest_sys, "disallowed_syscalls");
    if (!toml_disallowed_syscalls)
        return 0;

    ssize_t toml_disallowed_syscalls_cnt = toml_array_nelem(toml_disallowed_syscalls);
    if (toml_disallowed_syscalls_cnt < 0)
        return -EPERM;
    if (toml_disallowed_syscalls_cnt == 0)
        return 0;

    char* toml_disallowed_syscall_str = NULL;

    for (ssize_t i = 0; i < toml_disallowed_syscalls_cnt; i++) {
        toml_raw_t toml_disallowed_syscall_raw = toml_raw_at(toml_disallowed_syscalls, i);
        if (!toml_disallowed_syscall_raw) {
            log_error("Invalid disallowed syscall in manifest at index %ld", i);
            ret = -EINVAL;
            goto out;
        }

        ret = toml_rtos(toml_disallowed_syscall_raw, &toml_disallowed_syscall_str);
        if (ret < 0) {
            log_error("Invalid disallowed syscall in manifest at index %ld (not a string)", i);
            goto out;
        }

        uint64_t sysno = get_syscall_number(toml_disallowed_syscall_str);
        if (sysno >= LIBOS_SYSCALL_BOUND) {
            log_error("Unrecognized disallowed syscall `%s` in manifest at index %ld",
                      toml_disallowed_syscall_str, i);
            ret = -EINVAL;
            goto out;
        }

        /* force the syscall to be unrecognized by LibOS and thus return -ENOSYS */
        libos_syscall_table[sysno] = NULL;

        free(toml_disallowed_syscall_str);
        toml_disallowed_syscall_str = NULL;
    }

    ret = 0;
out:
    free(toml_disallowed_syscall_str);
    return ret;
}
