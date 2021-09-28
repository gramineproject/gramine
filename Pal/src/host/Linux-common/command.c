/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include <asm/errno.h>
#include <asm/posix_types.h>
#include <stdint.h>

#include "api.h"
#include "linux_utils.h"
#include "log.h"
#include "syscall.h"

typedef __kernel_pid_t pid_t;

static noreturn int run_command_child(const char* pathname, const char** argv, int pipefd[2]) {
    log_debug("%s: executing...", __func__);

    /* Replace stdout with write end of pipe */
    int ret = DO_SYSCALL(dup2, pipefd[1], 1);
    if (ret < 0) {
        log_warning("%s: dup2() failed: %d", __func__, ret);
        abort();
    }

    /* Close original pipe FDs */
    for (unsigned int i = 0; i < 2; i++) {
        ret = DO_SYSCALL(close, pipefd[i]);
        if (ret < 0) {
            log_warning("%s: close(pipefd[%u]) failed: %d", __func__, i, ret);
            abort();
        }
    }

    /* Execute the program */
    ret = DO_SYSCALL(execve, pathname, argv, /*envp=*/NULL);
    if (ret < 0)
        log_warning("%s: execve() failed: %d", __func__, ret);
    abort();
}

int run_command(const char* pathname, const char** argv, char* buf, size_t buf_size,
                size_t* out_len) {
    int ret;

    int pipefd[2];
    ret = DO_SYSCALL(pipe, pipefd);
    if (ret < 0) {
        log_warning("%s: pipe() failed: %d", __func__, ret);
        return ret;
    }

    pid_t pid = DO_SYSCALL(fork);
    if (pid < 0) {
        log_warning("%s: fork() failed: %d", __func__, ret);
        goto out;
    }

    if (pid == 0) {
        /* Child process (does not return) */
        run_command_child(pathname, argv, pipefd);
    }

    /* Parent process: */

    /* Close the write end of pipe */
    ret = DO_SYSCALL(close, pipefd[1]);
    if (ret < 0) {
        log_warning("%s: close(pipefd[1]) failed: %d", __func__, ret);
        goto out;
    }
    pipefd[1] = -1;

    /* Read up to `len` bytes */
    size_t len = 0;
    do {
        ssize_t n = DO_SYSCALL(read, pipefd[0], &buf[len], buf_size - len);
        if (n == -EINTR)
            continue;
        if (n < 0) {
            log_warning("%s: read() failed: %ld", __func__, n);
            ret = n;
            goto out;
        }
        if (n == 0)
            break;
        len += n;
    } while (len < buf_size);

    assert(len <= buf_size);
    *out_len = len;
    ret = 0;

out:
    /* Close pipe FD(s) */
    for (unsigned int i = 0; i < 2; i++) {
        if (pipefd[i] != -1) {
            int close_ret = DO_SYSCALL(close, pipefd[i]);
            if (close_ret < 0) {
                log_warning("%s: close(pipefd[%u]) failed: %d", __func__, i, close_ret);
                ret = close_ret;
            }
        }
    }

    /* We don't wait for the child process, because PAL uses SIG_IGN for SIGCHLD */
    return ret;
}
