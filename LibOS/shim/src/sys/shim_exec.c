/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system call "execve".
 */

#include <errno.h>

#include "pal.h"
#include "shim_internal.h"
#include "shim_lock.h"
#include "shim_process.h"
#include "shim_table.h"
#include "shim_thread.h"
#include "shim_vma.h"

static int close_on_exec(struct shim_fd_handle* fd_hdl, struct shim_handle_map* map) {
    if (fd_hdl->flags & FD_CLOEXEC) {
        struct shim_handle* hdl = __detach_fd_handle(fd_hdl, NULL, map);
        put_handle(hdl);
    }
    return 0;
}

static int close_cloexec_handle(struct shim_handle_map* map) {
    return walk_handle_map(&close_on_exec, map);
}

/* new_argp: pointer to beginning of first stack frame (argc, argv[0], ...)
 * new_auxv: pointer inside first stack frame (auxv[0], auxv[1], ...) */
noreturn static void __shim_do_execve_rtld(void* new_argp, elf_auxv_t* new_auxv) {
    int ret = 0;

    set_default_tls();

    thread_sigaction_reset_on_execve();

    remove_loaded_elf_objects();
    clean_link_map_list();

    reset_brk();

    size_t count;
    struct shim_vma_info* vmas;
    ret = dump_all_vmas(&vmas, &count, /*include_unmapped=*/true);
    if (ret < 0) {
        goto error;
    }

    struct shim_thread* cur_thread = get_cur_thread();
    for (struct shim_vma_info* vma = vmas; vma < vmas + count; vma++) {
        /* Don't free the current stack */
        if (vma->addr == cur_thread->stack || vma->addr == cur_thread->stack_red)
            continue;

        void* tmp_vma = NULL;
        if (bkeep_munmap(vma->addr, vma->length, !!(vma->flags & VMA_INTERNAL), &tmp_vma) < 0) {
            BUG();
        }
        if (DkVirtualMemoryFree(vma->addr, vma->length) < 0) {
            BUG();
        }
        bkeep_remove_tmp_vma(tmp_vma);
    }

    free_vma_info_array(vmas, count);

    lock(&g_process.fs_lock);
    struct shim_handle* exec = g_process.exec;
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

static int shim_do_execve_rtld(struct shim_handle* hdl, const char** argv, const char** envp) {
    struct shim_thread* cur_thread = get_cur_thread();
    int ret;

    if ((ret = close_cloexec_handle(cur_thread->handle_map)) < 0)
        return ret;

    lock(&g_process.fs_lock);
    put_handle(g_process.exec);
    get_handle(hdl);
    g_process.exec = hdl;
    unlock(&g_process.fs_lock);

    /* Update log prefix to include new executable name from `g_process.exec` */
    log_setprefix(shim_get_tcb());

    cur_thread->stack_top = NULL;
    cur_thread->stack     = NULL;
    cur_thread->stack_red = NULL;

    migrated_envp = NULL;

    const char** new_argp;
    elf_auxv_t* new_auxv;
    ret = init_stack(argv, envp, &new_argp, &new_auxv);
    if (ret < 0)
        return ret;

    /* We are done using this handle and we got the ownership from the caller. */
    put_handle(hdl);

    __shim_do_execve_rtld(new_argp, new_auxv);
    /* UNREACHABLE */
}

long shim_do_execve(const char* file, const char** argv, const char** envp) {
    int ret = 0, argc = 0;
    const char** argv_n = NULL;

    if (!is_user_string_readable(file))
        return -EFAULT;

    for (const char** a = argv; /* no condition*/; a++, argc++) {
        if (!is_user_memory_readable(a, sizeof(*a)))
            return -EFAULT;
        if (*a == NULL)
            break;
        if (!is_user_string_readable(*a))
            return -EFAULT;
    }

    /* TODO: This should be removed, but: https://github.com/gramineproject/graphene/issues/2081 */
    if (!envp)
        envp = migrated_envp;

    for (const char** e = envp; /* no condition*/; e++) {
        if (!is_user_memory_readable(e, sizeof(*e)))
            return -EFAULT;
        if (*e == NULL)
            break;
        if (!is_user_string_readable(*e))
            return -EFAULT;
    }

    struct shim_handle* exec = NULL;
    while (1)
    {
        if (!(exec = get_new_handle())) {
            return -ENOMEM;
        }

        if ((ret = open_executable(exec, file)) < 0) {
            put_handle(exec);
            return ret;
        }

        if ((ret = check_elf_object(exec)) < 0) {
            log_warning("file not recognized as ELF, look for shebang");
            char interp_path[BINPRM_BUF_SIZE], interp[BINPRM_BUF_SIZE];
            if((ret = check_and_load_shebang(exec, interp_path)) < 0)
            {
                put_handle(exec);
                return ret;
            }

            int j = 0;
            for (size_t i=0; interp_path[i] != ' '; i++) {
                if (interp_path[i] == '\0')
                    break;

                interp[i] = interp_path[i];
                j = i;
            }

            interp[++j] = '\0';
            file = interp;

            const char* argv_new[] = {file, (0 != strcmp(interp_path, interp))?&interp_path[j+1]:*argv, *argv, NULL};

            size_t size_total = 0, arr_size = 0;
            for (const char** a = argv_new; *a; a++) {
                size_t size = strlen(*a) + 1;
                size_total += size;
                ++arr_size;
            }
            log_debug("size of args %lu, array size %lu", size_total, arr_size);

            argv_n = (const char**)malloc(arr_size * sizeof(char*));
            char* argv_cur;
            argv_cur = (char*)malloc(size_total);

            size_t arr = 0;
            for (const char** a = argv_new; *a; a++) {
                size_t size = strlen(*a) + 1;
                memcpy(argv_cur, *a, size);
                *(argv_n + arr) = argv_cur;
                log_debug("printing elements %s", argv_n[arr]);
                arr++;
                argv_cur += size;
            }
            *(argv_n + arr) = NULL;

            put_handle(exec);
            continue;
        }
        break;
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

    /* Passing ownership of `exec`. */
    ret = shim_do_execve_rtld(exec, argv_n?argv_n:argv, envp);
    assert(ret < 0);

    put_handle(exec);
    /* We might have killed some threads and closed some fds and execve failed internally. User app
     * might now be in undefined state, we would better blow everything up. */
    process_exit(/*error_code=*/0, /*term_signal=*/SIGKILL);
}
