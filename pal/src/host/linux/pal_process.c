/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This source file contains functions to create a child process and terminate the running process.
 * Child does not inherit any objects or memory from its parent process. A parent process may not
 * modify the execution of its children. It can wait for a child to exit using its handle. Also,
 * parent and child may communicate through I/O streams provided by the parent to the child at
 * creation.
 */

#include <asm/errno.h>
#include <asm/fcntl.h>
#include <asm/ioctls.h>
#include <asm/poll.h>
#include <linux/time.h>

#include "api.h"
#include "linux_socket.h"
#include "linux_utils.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"

extern char* g_pal_loader_path;
extern char* g_libpal_path;

static inline int create_process_handle(PAL_HANDLE* parent, PAL_HANDLE* child) {
    PAL_HANDLE phdl = NULL;
    PAL_HANDLE chdl = NULL;
    int fds[2] = {-1, -1};
    int socktype = SOCK_STREAM | SOCK_CLOEXEC;
    int ret;

    ret = DO_SYSCALL(socketpair, AF_UNIX, socktype, 0, fds);
    if (ret < 0) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    phdl = calloc(1, HANDLE_SIZE(process));
    if (!phdl) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    init_handle_hdr(phdl, PAL_TYPE_PROCESS);
    phdl->flags  |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
    phdl->process.stream      = fds[0];
    phdl->process.nonblocking = false;

    chdl = calloc(1, HANDLE_SIZE(process));
    if (!chdl) {
        ret = -PAL_ERROR_NOMEM;
        goto out;
    }

    init_handle_hdr(chdl, PAL_TYPE_PROCESS);
    chdl->flags  |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
    chdl->process.stream      = fds[1];
    chdl->process.nonblocking = false;

    *parent = phdl;
    *child  = chdl;
    ret = 0;
out:
    if (ret < 0) {
        free(phdl);
        free(chdl);
        if (fds[0] != -1)
            DO_SYSCALL(close, fds[0]);
        if (fds[1] != -1)
            DO_SYSCALL(close, fds[1]);
    }
    return ret;
}

struct proc_param {
    PAL_HANDLE parent;
    const char** argv;
};

struct proc_args {
    uint64_t        instance_id;

    unsigned long   memory_quota;

    size_t parent_data_size;
    size_t manifest_data_size;
};

static int child_process(struct proc_param* proc_param) {
    int ret = vfork();
    if (ret)
        return ret;

    /* child */
    DO_SYSCALL(execve, g_pal_loader_path, proc_param->argv, g_pal_linux_state.host_environ);
    /* execve failed, but we're after vfork, so we can't do anything more than just exit */
    DO_SYSCALL(exit_group, 1);
    die_or_inf_loop();
}

int _PalProcessCreate(const char** args, uintptr_t (*reserved_mem_ranges)[2],
                      size_t reserved_mem_ranges_len, PAL_HANDLE* out_handle) {
    PAL_HANDLE parent_handle = NULL;
    PAL_HANDLE child_handle = NULL;
    struct proc_args* proc_args = NULL;
    void* parent_data = NULL;
    void* exec_data = NULL;
    int reserved_mem_ranges_fd = -1;
    int ret;

    /* step 1: create parent and child process handle */

    struct proc_param param;
    ret = create_process_handle(&parent_handle, &child_handle);
    if (ret < 0)
        goto out;

    handle_set_cloexec(parent_handle, false);
    param.parent = parent_handle;

    /* step 2: compose process parameters */

    size_t parent_data_size = 0;
    size_t manifest_data_size = 0;

    ret = handle_serialize(parent_handle, &parent_data);
    if (ret < 0)
        goto out;
    parent_data_size = (size_t)ret;

    manifest_data_size = strlen(g_pal_common_state.raw_manifest_data);

    size_t data_size = parent_data_size + manifest_data_size;
    proc_args = malloc(sizeof(struct proc_args) + data_size);
    if (!proc_args) {
        ret = -ENOMEM;
        goto out;
    }

    proc_args->instance_id = g_pal_common_state.instance_id;
    proc_args->memory_quota = g_pal_linux_state.memory_quota;

    char* data = (char*)(proc_args + 1);

    memcpy(data, parent_data, parent_data_size);
    proc_args->parent_data_size = parent_data_size;
    data += parent_data_size;

    memcpy(data, g_pal_common_state.raw_manifest_data, manifest_data_size);
    proc_args->manifest_data_size = manifest_data_size;
    data += manifest_data_size;

    ret = create_reserved_mem_ranges_fd(reserved_mem_ranges,
                                        reserved_mem_ranges_len * sizeof(*reserved_mem_ranges));
    if (ret < 0) {
        log_error("creating reserved mem ranges fd failed: %s", unix_strerror(ret));
        goto out;
    }
    reserved_mem_ranges_fd = ret;

    char reserved_mem_ranges_fd_str[0x10];
    ret = snprintf(reserved_mem_ranges_fd_str, sizeof(reserved_mem_ranges_fd_str), "%d",
                   reserved_mem_ranges_fd);
    assert(0 < ret && (size_t)ret < sizeof(reserved_mem_ranges_fd_str));

    /* step 3: create a child thread which will execve in the future */

    /* the first argument must be the PAL */
    int argc = 0;
    if (args)
        for (; args[argc]; argc++)
            ;
    param.argv = __alloca(sizeof(const char*) * (argc + 6));
    param.argv[0] = g_pal_loader_path;
    param.argv[1] = g_libpal_path;
    param.argv[2] = "child";
    char parent_fd_str[16];
    snprintf(parent_fd_str, sizeof(parent_fd_str), "%u", parent_handle->process.stream);
    param.argv[3] = parent_fd_str;
    param.argv[4] = reserved_mem_ranges_fd_str;
    if (args)
        memcpy(&param.argv[5], args, sizeof(const char*) * argc);
    param.argv[argc + 5] = NULL;

    /* Child's signal handler may mess with parent's memory during vfork(),
     * so block signals
     */
    ret = block_async_signals(true);
    if (ret < 0)
        goto out;

    ret = child_process(&param);
    if (ret < 0) {
        ret = -PAL_ERROR_DENIED;
        goto out;
    }

    /* children unblock async signals by signal_setup() */
    ret = block_async_signals(false);
    if (ret < 0)
        goto out;

    /* step 4: send parameters over the process handle */

    ret = write_all(child_handle->process.stream, proc_args, sizeof(struct proc_args) + data_size);
    if (ret < 0) {
        ret = unix_to_pal_error(ret);
        goto out;
    }

    *out_handle = child_handle;
    ret = 0;
out:
    free(parent_data);
    free(exec_data);
    free(proc_args);
    if (parent_handle)
        _PalObjectClose(parent_handle);
    if (ret < 0) {
        if (child_handle)
            _PalObjectClose(child_handle);
    }
    if (reserved_mem_ranges_fd >= 0) {
        DO_SYSCALL(close, reserved_mem_ranges_fd);
    }
    return ret;
}

void init_child_process(int parent_stream_fd, PAL_HANDLE* parent_handle, char** manifest_out,
                        uint64_t* instance_id) {
    int ret = 0;

    struct proc_args proc_args;

    ret = read_all(parent_stream_fd, &proc_args, sizeof(proc_args));
    if (ret < 0) {
        INIT_FAIL("communication with parent failed: %s", unix_strerror(ret));
    }

    /* a child must have parent handle and an executable */
    if (!proc_args.parent_data_size)
        INIT_FAIL("invalid process created");

    size_t data_size = proc_args.parent_data_size + proc_args.manifest_data_size;
    char* data = malloc(data_size);
    if (!data)
        INIT_FAIL("Out of memory");

    ret = read_all(parent_stream_fd, data, data_size);
    if (ret < 0) {
        INIT_FAIL("communication with parent failed: %s", unix_strerror(ret));
    }

    /* now deserialize the parent_handle */
    PAL_HANDLE parent = NULL;
    char* data_iter = data;
    ret = handle_deserialize(&parent, data_iter, proc_args.parent_data_size);
    if (ret < 0)
        INIT_FAIL("cannot deserialize parent process handle: %s", pal_strerror(ret));
    data_iter += proc_args.parent_data_size;
    *parent_handle = parent;

    char* manifest = malloc(proc_args.manifest_data_size + 1);
    if (!manifest)
        INIT_FAIL("Out of memory");
    memcpy(manifest, data_iter, proc_args.manifest_data_size);
    manifest[proc_args.manifest_data_size] = '\0';
    data_iter += proc_args.manifest_data_size;

    g_pal_linux_state.memory_quota = proc_args.memory_quota;

    *manifest_out = manifest;
    *instance_id = proc_args.instance_id;
    free(data);
}

noreturn void _PalProcessExit(int exitcode) {
    DO_SYSCALL(exit_group, exitcode);
    die_or_inf_loop();
}

static int64_t proc_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    int64_t bytes = DO_SYSCALL(read, handle->process.stream, buffer, count);

    if (bytes < 0)
        switch (bytes) {
            case -EWOULDBLOCK:
                return -PAL_ERROR_TRYAGAIN;
            case -EINTR:
                return -PAL_ERROR_INTERRUPTED;
            default:
                return -PAL_ERROR_DENIED;
        }

    return bytes;
}

static int64_t proc_write(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    int64_t bytes = DO_SYSCALL(write, handle->process.stream, buffer, count);

    if (bytes < 0)
        switch (bytes) {
            case -EWOULDBLOCK:
                return -PAL_ERROR_TRYAGAIN;
            case -EINTR:
                return -PAL_ERROR_INTERRUPTED;
            default:
                return -PAL_ERROR_DENIED;
        }

    return bytes;
}

static int proc_close(PAL_HANDLE handle) {
    if (handle->process.stream != PAL_IDX_POISON) {
        DO_SYSCALL(close, handle->process.stream);
        handle->process.stream = PAL_IDX_POISON;
    }

    return 0;
}

static int proc_delete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    int shutdown;
    switch (delete_mode) {
        case PAL_DELETE_ALL:
            shutdown = SHUT_RDWR;
            break;
        case PAL_DELETE_READ:
            shutdown = SHUT_RD;
            break;
        case PAL_DELETE_WRITE:
            shutdown = SHUT_WR;
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    if (handle->process.stream != PAL_IDX_POISON)
        DO_SYSCALL(shutdown, handle->process.stream, shutdown);

    return 0;
}

static int proc_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    int ret;
    int val;

    if (handle->process.stream == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    attr->handle_type  = handle->hdr.type;
    attr->nonblocking  = handle->process.nonblocking;

    /* get number of bytes available for reading */
    ret = DO_SYSCALL(ioctl, handle->process.stream, FIONREAD, &val);
    if (ret < 0)
        return unix_to_pal_error(ret);

    attr->pending_size = val;

    return 0;
}

static int proc_attrsetbyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (handle->process.stream == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    int ret;
    if (attr->nonblocking != handle->process.nonblocking) {
        ret = DO_SYSCALL(fcntl, handle->process.stream, F_SETFL,
                         handle->process.nonblocking ? O_NONBLOCK : 0);

        if (ret < 0)
            return unix_to_pal_error(ret);

        handle->process.nonblocking = attr->nonblocking;
    }

    return 0;
}

struct handle_ops g_proc_ops = {
    .read           = &proc_read,
    .write          = &proc_write,
    .close          = &proc_close,
    .delete         = &proc_delete,
    .attrquerybyhdl = &proc_attrquerybyhdl,
    .attrsetbyhdl   = &proc_attrsetbyhdl,
};
