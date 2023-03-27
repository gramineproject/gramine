/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*!
 * \file
 *
 * This file contains the implementation of `/proc` pseudo-filesystem.
 */

#include "api.h"
#include "libos_fs_pseudo.h"
#include "libos_process.h"

/* Maximum number of memory map areas a process may have.
 * From: include/linux/mm.h
 */
#define MAPCOUNT_ELF_CORE_MARGIN    (5)
#define DEFAULT_MAX_MAP_COUNT       (USHRT_MAX - MAPCOUNT_ELF_CORE_MARGIN)

#define INT_MAX_STR_LEN 16

static int proc_pid_max_load(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    size_t buffer_size = 16; /* enough to hold PID_MAX_LIMIT */
    char* buffer = malloc(buffer_size);
    if (!buffer)
        return -ENOMEM;

    static_assert(PID_MAX_LIMIT <= UINT_MAX, "wrong types");
    int ret = snprintf(buffer, buffer_size, "%u", PID_MAX_LIMIT);
    if (ret < 0) {
        free(buffer);
        return ret;
    }
    assert((size_t)ret < buffer_size);

    *out_data = buffer;
    *out_size = buffer_size;
    return 0;
}

static int proc_hardcoded_value(unsigned val, char** out_data, size_t* out_size) {
    char buf[(3 * sizeof val) + 1/* z-terminator*/];
    int ret = snprintf(buf, sizeof buf, "%u", val);
    if (ret < 0)
        return ret;
    assert((size_t)ret < sizeof buf);

    char* buffer = strdup(buf);
    if (!buffer)
        return -ENOMEM;

    *out_data = buffer;
    *out_size = (size_t)ret + 1;
    return 0;
}

static int proc_vm_max_map_count(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    static_assert(DEFAULT_MAX_MAP_COUNT <= UINT_MAX, "default value is to high");
    int ret = proc_hardcoded_value(DEFAULT_MAX_MAP_COUNT, out_data, out_size);
    return ret;
}

int proc_self_follow_link(struct libos_dentry* dent, char** out_target) {
    __UNUSED(dent);
    IDTYPE pid = g_process.pid;
    char name[11];
    snprintf(name, sizeof(name), "%u", pid);
    if (!(*out_target = strdup(name)))
        return -ENOMEM;
    return 0;
}

/* `/proc/<pid>` and `/proc/<pid>/task/<tid>` for our local process and threads */
static void init_thread_dir(struct pseudo_node* ent) {
    pseudo_add_link(ent, "root", &proc_thread_follow_link);
    pseudo_add_link(ent, "cwd", &proc_thread_follow_link);
    pseudo_add_link(ent, "exe", &proc_thread_follow_link);
    pseudo_add_str(ent, "maps", &proc_thread_maps_load);
    pseudo_add_str(ent, "cmdline", &proc_thread_cmdline_load);
    pseudo_add_str(ent, "status", &proc_thread_status_load);
    pseudo_add_str(ent, "statm", &proc_thread_statm_load);
    pseudo_add_str(ent, "stat", &proc_thread_stat_load);

    struct pseudo_node* fd = pseudo_add_dir(ent, "fd");
    struct pseudo_node* fd_link = pseudo_add_link(fd, /*name=*/NULL, &proc_thread_fd_follow_link);
    fd_link->name_exists = &proc_thread_fd_name_exists;
    fd_link->list_names = &proc_thread_fd_list_names;
}

/* `/proc/<pid>` for other processes, uses IPC */
static void init_ipc_thread_dir(struct pseudo_node* ent) {
    pseudo_add_link(ent, "root", &proc_ipc_thread_follow_link);
    pseudo_add_link(ent, "cwd", &proc_ipc_thread_follow_link);
    pseudo_add_link(ent, "exe", &proc_ipc_thread_follow_link);
}

int init_procfs(void) {
    struct pseudo_node* root = pseudo_add_root_dir("proc");

    struct pseudo_node* sys = pseudo_add_dir(root, "sys");
    struct pseudo_node* kernel = pseudo_add_dir(sys, "kernel");
    pseudo_add_str(kernel, "pid_max", &proc_pid_max_load);

    struct pseudo_node* vm = pseudo_add_dir(sys, "vm"); /* /proc/sys/vm/ */
    pseudo_add_str(vm, "max_map_count", &proc_vm_max_map_count);

    pseudo_add_str(root, "meminfo", &proc_meminfo_load);
    pseudo_add_str(root, "cpuinfo", &proc_cpuinfo_load);
    pseudo_add_str(root, "stat", &proc_stat_load);

    pseudo_add_link(root, "self", &proc_self_follow_link);

    struct pseudo_node* thread_pid = pseudo_add_dir(root, /*name=*/NULL);
    thread_pid->name_exists = &proc_thread_pid_name_exists;
    thread_pid->list_names = &proc_thread_pid_list_names;
    init_thread_dir(thread_pid);

    struct pseudo_node* thread_task = pseudo_add_dir(thread_pid, "task");
    struct pseudo_node* thread_tid = pseudo_add_dir(thread_task, /*name=*/NULL);
    thread_tid->name_exists = &proc_thread_tid_name_exists;
    thread_tid->list_names = &proc_thread_tid_list_names;
    init_thread_dir(thread_tid);

    struct pseudo_node* ipc_thread_pid = pseudo_add_dir(root, /*name=*/NULL);
    ipc_thread_pid->name_exists = &proc_ipc_thread_pid_name_exists;
    /* Listing remote processes is not currently supported. */
    ipc_thread_pid->list_names = NULL;
    init_ipc_thread_dir(ipc_thread_pid);

   return 0;
}
