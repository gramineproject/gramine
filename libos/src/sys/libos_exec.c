/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system call "execve".
 */

#include <errno.h>

#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_process.h"
#include "libos_table.h"
#include "libos_thread.h"
#include "libos_vma.h"
#include "pal.h"

/* new_argp: pointer to beginning of first stack frame (argc, argv[0], ...)
 * new_auxv: pointer inside first stack frame (auxv[0], auxv[1], ...) */
noreturn static void __libos_syscall_execve_rtld(void* new_argp, elf_auxv_t* new_auxv) {
    int ret = 0;

    set_default_tls();

    thread_sigaction_reset_on_execve();

    remove_loaded_elf_objects();
    clean_link_map_list();

    reset_brk();

    size_t count;
    struct libos_vma_info* vmas;
    ret = dump_all_vmas(&vmas, &count, /*include_unmapped=*/true);
    if (ret < 0) {
        goto error;
    }

    struct libos_thread* cur_thread = get_cur_thread();
    for (struct libos_vma_info* vma = vmas; vma < vmas + count; vma++) {
        /* Don't free the current stack */
        if (vma->addr == cur_thread->stack || vma->addr == cur_thread->stack_red)
            continue;

        void* tmp_vma = NULL;
        if (bkeep_munmap(vma->addr, vma->length, !!(vma->flags & VMA_INTERNAL), &tmp_vma) < 0) {
            BUG();
        }
        if (PalVirtualMemoryFree(vma->addr, vma->length) < 0) {
            BUG();
        }
        bkeep_remove_tmp_vma(tmp_vma);
    }

    free_vma_info_array(vmas, count);

    lock(&g_process.fs_lock);
    struct libos_handle* exec = g_process.exec;
    get_handle(exec);
    unlock(&g_process.fs_lock);

    struct link_map* exec_map;
    if ((ret = load_elf_object(exec, &exec_map)) < 0)
        goto error;

    if ((ret = init_brk_from_executable(exec_map)) < 0)
        goto error;

    if ((ret = load_elf_interp(exec_map)) < 0)
        goto error;

    cur_thread->robust_list = NULL;

    /* We are done with using this handle. */
    put_handle(exec);

    log_debug("execve: start execution");
    execute_elf_object(exec_map, new_argp, new_auxv);
    /* NOTREACHED */

error:
    log_error("execve failed with errno=%d", ret);
    process_exit(/*error_code=*/0, /*term_signal=*/SIGKILL);
}

/* `libos_syscall_execve()` passes ownership of `argv` to this function, so this function is
 * responsible for freeing it (both the array of pointers and the strings themselves) */
static int libos_syscall_execve_rtld(struct libos_handle* hdl, char** argv,
                                     const char* const* envp) {
    struct libos_thread* cur_thread = get_cur_thread();
    int ret;

    close_cloexec_handles(cur_thread->handle_map);

    lock(&g_process.fs_lock);
    put_handle(g_process.exec);
    get_handle(hdl);
    g_process.exec = hdl;
    unlock(&g_process.fs_lock);

    /* Update log prefix to include new executable name from `g_process.exec` */
    log_setprefix(libos_get_tcb());

    cur_thread->stack_top = NULL;
    cur_thread->stack     = NULL;
    cur_thread->stack_red = NULL;

    migrated_envp = NULL;

    char** new_argp;
    elf_auxv_t* new_auxv;

    ret = init_process_cmdline((const char* const*)argv);
    if (ret < 0)
        return ret;

    /* note the typecast of argv here: the C standard disallows implicit conversion of `char**` ->
     * `const char* const*`, but in reality it is safe to do */
    ret = init_stack((const char* const*)argv, envp, &new_argp, &new_auxv);
    if (ret < 0)
        return ret;

    /* We are done using this handle and we got the ownership from the caller. */
    put_handle(hdl);

    /* We copied the arguments on the stack and we got the ownership from the caller (note that
     * *argv was allocated as a single object -- concatenation of all argv strings). */
    free(*argv);
    free(argv);

    __libos_syscall_execve_rtld(new_argp, new_auxv);
    /* UNREACHABLE */
}

long libos_syscall_execve(const char* file, const char* const* argv, const char* const* envp) {
    int ret = 0, argc = 0;
    const char* const empty_argv[1] = {NULL};

    if (!is_user_string_readable(file))
        return -EFAULT;

    if (!argv) {
        argv = empty_argv;
    } else {
        for (const char* const* a = argv; /* no condition */; a++, argc++) {
            if (!is_user_memory_readable(a, sizeof(*a)))
                return -EFAULT;
            if (*a == NULL)
                break;
            if (!is_user_string_readable(*a))
                return -EFAULT;
        }
    }

    /* TODO: This should be removed, but: https://github.com/gramineproject/graphene/issues/2081 */
    if (!envp)
        envp = migrated_envp;

    for (const char* const* e = envp; /* no condition*/; e++) {
        if (!is_user_memory_readable(e, sizeof(*e)))
            return -EFAULT;
        if (*e == NULL)
            break;
        if (!is_user_string_readable(*e))
            return -EFAULT;
    }

    struct libos_handle* exec = NULL;
    char** new_argv = NULL;
    ret = load_and_check_exec(file, argv, &exec, &new_argv);
    if (ret < 0) {
        return ret;
    }

    /* If `execve` is invoked concurrently by multiple threads, let only one succeed. From this
     * point errors are fatal. */
    static unsigned int first = 0;
    if (__atomic_exchange_n(&first, 1, __ATOMIC_RELAXED) != 0) {
        /* Just exit current thread. */
        thread_exit(/*error_code=*/0, /*term_signal=*/0);
    }
    (void)kill_other_threads();

    /* All other threads are dead. Restoring initial value in case we stay inside same process
     * instance and call execve again. */
    __atomic_store_n(&first, 0, __ATOMIC_RELAXED);

    /* Passing ownership of `exec` and `new_argv`. */
    ret = libos_syscall_execve_rtld(exec, new_argv, envp);
    assert(ret < 0);

    put_handle(exec);
    /* We might have killed some threads and closed some fds and execve failed internally. User app
     * might now be in undefined state, we would better blow everything up. */
    process_exit(/*error_code=*/0, /*term_signal=*/SIGKILL);
}
