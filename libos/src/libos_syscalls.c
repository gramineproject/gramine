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
#ifdef UBSAN
/*
 * Variable syscall_func is of type six_args_syscall_t but points to item inside libos_syscall_table
 * array, which has a type libos_syscall_t, thus UBSan complains about "Indirect call of a function
 * through a function pointer of the wrong type". Silence this particular complaint.
 */
__attribute__((no_sanitize("function")))
#endif
noreturn void libos_emulate_syscall(PAL_CONTEXT* context) {
    LIBOS_TCB_SET(context.regs, context);

    unsigned long sysnr = pal_context_get_syscall(context);
    arch_syscall_arg_t ret = 0;

    if (sysnr == GRAMINE_CUSTOM_SYSCALL_NR) {
        unsigned long args[] = { ALL_SYSCALL_ARGS(context) };
        ret = handle_libos_call(args[0], args[1], args[2]);
    } else {
        if (sysnr >= LIBOS_SYSCALL_BOUND) {
            warn_unsupported_syscall(sysnr);
            ret = -ENOSYS;
            goto out;
        }

        if (libos_mock_syscall_table[sysnr].is_mocked) {
            trace_mock_syscall(sysnr);
            ret = libos_mock_syscall_table[sysnr].return_value;
            goto out;
        }

        if (!libos_syscall_table[sysnr]) {
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

    toml_array_t* toml_mock_syscalls = toml_array_in(manifest_sys, "debug__mock_syscalls");
    if (!toml_mock_syscalls)
        return 0;

    ssize_t toml_mock_syscalls_cnt = toml_array_nelem(toml_mock_syscalls);
    if (toml_mock_syscalls_cnt < 0)
        return -EPERM;
    if (toml_mock_syscalls_cnt == 0)
        return 0;

    char* syscall_name = NULL;

    for (ssize_t i = 0; i < toml_mock_syscalls_cnt; i++) {
        toml_table_t* toml_mock_syscall = toml_table_at(toml_mock_syscalls, i);
        if (!toml_mock_syscall) {
            log_error("Invalid mock syscall in manifest at index %ld (not a TOML table)", i);
            ret = -EINVAL;
            goto out;
        }

        ret = toml_string_in(toml_mock_syscall, "name", &syscall_name);
        if (ret < 0) {
            log_error("Invalid mock syscall in manifest at index %ld (can't parse `name`)", i);
            ret = -EINVAL;
            goto out;
        }

        int64_t syscall_return;
        ret = toml_int_in(toml_mock_syscall, "return", /*defaultval=*/0, &syscall_return);
        if (ret < 0) {
            log_error("Invalid mock syscall in manifest at index %ld (can't parse `return`)", i);
            ret = -EINVAL;
            goto out;
        }

        uint64_t sysno;
        ret = get_syscall_number(syscall_name, &sysno);
        if (ret < 0) {
            log_error("Unrecognized mock syscall `%s` in manifest at index %ld", syscall_name, i);
            goto out;
        }

        /* add syscall to the table of mocked syscalls */
        assert(sysno < LIBOS_SYSCALL_BOUND);
        libos_mock_syscall_table[sysno].is_mocked = true;
        libos_mock_syscall_table[sysno].return_value = syscall_return;

        free(syscall_name);
        syscall_name = NULL;
    }

    ret = 0;
out:
    free(syscall_name);
    return ret;
}
