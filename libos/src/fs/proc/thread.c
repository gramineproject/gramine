/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Implementation of `/proc/<pid>` and `/proc/<pid>/task/<tid>`, for the local process.
 */

#include "libos_fs.h"
#include "libos_fs_pseudo.h"
#include "libos_lock.h"
#include "libos_process.h"
#include "libos_rwlock.h"
#include "libos_thread.h"
#include "libos_types.h"
#include "libos_vma.h"

int proc_thread_follow_link(struct libos_dentry* dent, char** out_target) {
    __UNUSED(dent);

    lock(&g_process.fs_lock);

    const char* name = dent->name;
    if (strcmp(name, "root") == 0) {
        dent = g_process.root;
        get_dentry(dent);
    } else if (strcmp(name, "cwd") == 0) {
        dent = g_process.cwd;
        get_dentry(dent);
    } else if (strcmp(name, "exe") == 0) {
        dent = g_process.exec->dentry;
        if (dent)
            get_dentry(dent);
    }

    unlock(&g_process.fs_lock);

    if (!dent)
        return -ENOENT;

    int ret = dentry_abs_path(dent, out_target, /*size=*/NULL);
    if (ret < 0)
        goto out;

    ret = 0;
out:
    put_dentry(dent);
    return ret;
}

int proc_thread_maps_load(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    int ret;
    size_t vma_count;
    struct libos_vma_info* vmas = NULL;
    ret = dump_all_vmas(/*include_unmapped=*/false, &vmas, &vma_count);
    if (ret < 0) {
        return ret;
    }

#define DEFAULT_VMA_BUFFER_SIZE 256

    char* buffer;
    size_t buffer_size = DEFAULT_VMA_BUFFER_SIZE, offset = 0;
    buffer = malloc(buffer_size);
    if (!buffer) {
        ret = -ENOMEM;
        goto err;
    }

    for (struct libos_vma_info* vma = vmas; vma < vmas + vma_count; vma++) {
        size_t old_offset = offset;
        uintptr_t start   = (uintptr_t)vma->addr;
        uintptr_t end     = (uintptr_t)vma->addr + vma->length;
        char pt[3]        = {
            (vma->prot & PROT_READ) ? 'r' : '-',
            (vma->prot & PROT_WRITE) ? 'w' : '-',
            (vma->prot & PROT_EXEC) ? 'x' : '-',
        };
        char pr = (vma->flags & MAP_PRIVATE) ? 'p' : 's';

#define ADDR_FMT(addr) ((addr) > 0xffffffff ? "%lx" : "%08lx")
#define EMIT(fmt...)                                                        \
    do {                                                                    \
        if (offset < buffer_size)                                           \
            offset += snprintf(buffer + offset, buffer_size - offset, fmt); \
    } while (0)

    retry_emit_vma:
        if (vma->file) {
            int dev_major = 0, dev_minor = 0;
            unsigned long ino = vma->file->dentry ? dentry_ino(vma->file->dentry) : 0;
            char* path = NULL;

            if (vma->file->dentry)
                dentry_abs_path(vma->file->dentry, &path, /*size=*/NULL);

            EMIT(ADDR_FMT(start), start);
            EMIT("-");
            EMIT(ADDR_FMT(end), end);
            EMIT(" %c%c%c%c %08lx %02d:%02d %lu %s\n", pt[0], pt[1], pt[2], pr, vma->file_offset,
                 dev_major, dev_minor, ino, path ? path : "[unknown]");

            free(path);
        } else {
            EMIT(ADDR_FMT(start), start);
            EMIT("-");
            EMIT(ADDR_FMT(end), end);
            if (vma->comment[0])
                EMIT(" %c%c%c%c 00000000 00:00 0 %s\n", pt[0], pt[1], pt[2], pr, vma->comment);
            else
                EMIT(" %c%c%c%c 00000000 00:00 0\n", pt[0], pt[1], pt[2], pr);
        }

        if (offset >= buffer_size) {
            char* new_buffer = malloc(buffer_size * 2);
            if (!new_buffer) {
                ret = -ENOMEM;
                goto err;
            }

            offset = old_offset;
            memcpy(new_buffer, buffer, old_offset);
            free(buffer);
            buffer = new_buffer;
            buffer_size *= 2;
            goto retry_emit_vma;
        }
    }

    *out_data = buffer;
    *out_size = offset;
    ret = 0;

err:
    if (ret < 0) {
        free(buffer);
    }
    if (vmas) {
        free_vma_info_array(vmas, vma_count);
    }
    return ret;
}

int proc_thread_cmdline_load(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    size_t buffer_size = g_process.cmdline_size;
    char* buffer = malloc(buffer_size);
    if (!buffer) {
        return -ENOMEM;
    }

    memcpy(buffer, g_process.cmdline, buffer_size);
    *out_data = buffer;
    *out_size = buffer_size;
    return 0;
}

bool proc_thread_pid_name_exists(struct libos_dentry* parent, const char* name) {
    __UNUSED(parent);

    unsigned long pid;
    if (pseudo_parse_ulong(name, IDTYPE_MAX, &pid) < 0)
        return false;

    return pid == g_process.pid;
}

int proc_thread_pid_list_names(struct libos_dentry* parent, readdir_callback_t callback,
                               void* arg) {
    __UNUSED(parent);
    IDTYPE pid = g_process.pid;
    char name[11];
    snprintf(name, sizeof(name), "%u", pid);
    int ret = callback(name, arg);
    if (ret < 0)
        return ret;

    return 0;
}

bool proc_thread_tid_name_exists(struct libos_dentry* parent, const char* name) {
    __UNUSED(parent);

    unsigned long tid;
    if (pseudo_parse_ulong(name, IDTYPE_MAX, &tid) < 0)
        return false;

    struct libos_thread* thread = lookup_thread(tid);
    if (!thread)
        return false;

    put_thread(thread);
    return true;
}

struct walk_thread_arg {
    readdir_callback_t callback;
    void* arg;
};

static int walk_cb(struct libos_thread* thread, void* arg) {
    struct walk_thread_arg* args = arg;

    IDTYPE pid = thread->tid;
    char name[11];
    snprintf(name, sizeof(name), "%u", pid);
    int ret = args->callback(name, args->arg);
    if (ret < 0)
        return ret;
    return 1;
}

int proc_thread_tid_list_names(struct libos_dentry* parent, readdir_callback_t callback,
                               void* arg) {
    __UNUSED(parent);
    struct walk_thread_arg args = {
        .callback = callback,
        .arg = arg,
    };

    int ret = walk_thread_list(&walk_cb, &args, /*one_shot=*/false);
    if (ret < 0)
        return ret;

    return 0;
}

bool proc_thread_fd_name_exists(struct libos_dentry* parent, const char* name) {
    __UNUSED(parent);
    unsigned long fd;
    if (pseudo_parse_ulong(name, UINT32_MAX, &fd) < 0)
        return false;

    struct libos_handle_map* handle_map = get_thread_handle_map(NULL);
    assert(handle_map);
    rwlock_read_lock(&handle_map->lock);

    if (fd > handle_map->fd_top || handle_map->map[fd] == NULL ||
            handle_map->map[fd]->handle == NULL) {
        rwlock_read_unlock(&handle_map->lock);
        return false;
    }

    rwlock_read_unlock(&handle_map->lock);
    return true;
}

int proc_thread_fd_list_names(struct libos_dentry* parent, readdir_callback_t callback, void* arg) {
    __UNUSED(parent);

    struct libos_handle_map* handle_map = get_thread_handle_map(NULL);
    assert(handle_map);
    rwlock_read_lock(&handle_map->lock);

    int ret = 0;
    for (uint32_t i = 0; i <= handle_map->fd_top; i++)
        if (handle_map->map[i] && handle_map->map[i]->handle) {
            char name[11];
            snprintf(name, sizeof(name), "%u", i);
            if ((ret = callback(name, arg)) < 0)
                break;
        }

    rwlock_read_unlock(&handle_map->lock);
    return ret;
}

/*
 * Human-readable string for a handle without attached dentry.
 *
 * TODO: Linux uses names like `pipe:[INODE]`, we could at least include more information whenever
 * we can (e.g. socket address).
 */
static char* describe_handle(struct libos_handle* hdl) {
    const char* str;
    switch (hdl->type) {
        case TYPE_CHROOT:  str = "chroot:[?]";  break;
        case TYPE_DEV:     str = "dev:[?]";     break;
        case TYPE_STR:     str = "str:[?]";     break;
        case TYPE_PSEUDO:  str = "pseudo:[?]";  break;
        case TYPE_PIPE:    str = "pipe:[?]";    break;
        case TYPE_SOCK:    str = "sock:[?]";    break;
        case TYPE_EPOLL:   str = "epoll:[?]";   break;
        case TYPE_EVENTFD: str = "eventfd:[?]"; break;
        case TYPE_SHM:     str = "shm:[?]";     break;
        default:           str = "unknown:[?]"; break;
    }
    return strdup(str);
}

int proc_thread_fd_follow_link(struct libos_dentry* dent, char** out_target) {
    unsigned long fd;
    if (pseudo_parse_ulong(dent->name, UINT32_MAX, &fd) < 0)
        return -ENOENT;

    struct libos_handle_map* handle_map = get_thread_handle_map(NULL);
    assert(handle_map);
    rwlock_read_lock(&handle_map->lock);

    if (fd > handle_map->fd_top || handle_map->map[fd] == NULL ||
            handle_map->map[fd]->handle == NULL) {
        rwlock_read_unlock(&handle_map->lock);
        return -ENOENT;
    }

    int ret;
    struct libos_handle* hdl = handle_map->map[fd]->handle;

    if (hdl->dentry) {
        ret = dentry_abs_path(hdl->dentry, out_target, /*size=*/NULL);
    } else {
        /* The handle does not correspond to a dentry. Do our best to provide a human-readable link
         * target. */
        *out_target = describe_handle(hdl);
        ret = *out_target ? 0 : -ENOMEM;
    }

    rwlock_read_unlock(&handle_map->lock);

    return ret;
}

int proc_thread_status_load(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    size_t size = 0, max = 256;
    size_t i = 0;
    char* str = malloc(max);
    if (!str)
        return -ENOMEM;

    /*
     * Minimal set of attributes from `/proc/[pid]/status`. Only `VmPeak` is supported currently.
     */

    struct {
        const char* fmt;
        unsigned long val;
    } status[] = {
        { "VmPeak:\t%8lu kB\n", get_peak_memory_usage() / 1024 },
    };

    while (i < ARRAY_SIZE(status)) {
        int ret = snprintf(str + size, max - size, status[i].fmt, status[i].val);
        if (ret < 0) {
            free(str);
            return ret;
        }

        if (size + ret >= max) {
            max *= 2;
            size = 0;
            i = 0;
            free(str);
            /* TODO: use `realloc()` once it's available. */
            str = malloc(max);
            if (!str)
                return -ENOMEM;

            continue;
        }

        size += ret;
        i++;
    }

    *out_data = str;
    *out_size = size;
    return 0;
}


int proc_thread_statm_load(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    size_t virtual_mem_size_in_pages = get_total_memory_usage() / PAGE_SIZE;

    size_t size = 0, max = 64;
    size_t i = 0;
    char* str = malloc(max);
    if (!str)
        return -ENOMEM;

    /*
     * Fields of `/proc/[pid]/statm`. Only `VmSize` and `VmRSS` are supported currently.
     */

    struct {
        const char* fmt;
        unsigned long val;
    } status[] = {
        /* size */
        { "%lu", virtual_mem_size_in_pages },
        /* resident */
        { " %lu", virtual_mem_size_in_pages },
        /* shared */
        { " %lu", /*dummy value=*/0 },
        /* text */
        { " %lu", /*dummy value=*/0 },
        /* lib; always 0 */
        { " %lu", 0 },
        /* data */
        { " %lu", /*dummy value=*/0 },
        /* dt; always 0 */
        { " %lu\n", 0 },

    };

    while (i < ARRAY_SIZE(status)) {
        int ret = snprintf(str + size, max - size, status[i].fmt, status[i].val);
        if (ret < 0) {
            free(str);
            return ret;
        }

        if (size + ret >= max) {
            max *= 2;
            size = 0;
            i = 0;
            free(str);
            /* TODO: use `realloc()` once it's available. */
            str = malloc(max);
            if (!str)
                return -ENOMEM;

            continue;
        }

        size += ret;
        i++;
    }

    *out_data = str;
    *out_size = size;
    return 0;
}

static int thread_count(struct libos_thread* thread, void* arg) {
    __UNUSED(thread);
    (*(uint64_t*)arg)++;
    return 1;
}

static uint64_t get_thread_num(void) {
    uint64_t num = 0;
    if (walk_thread_list(thread_count, &num, /*one_shot=*/false) < 0)
        num = 1;
    return num;
}

int proc_thread_stat_load(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    char comm[16] = {0};
    lock(&g_process.fs_lock);
    size_t name_length = g_process.exec->dentry->name_len;
    memcpy(comm, g_process.exec->dentry->name,
           name_length > sizeof(comm) - 1 ? sizeof(comm) - 1 : name_length);
    unlock(&g_process.fs_lock);
    size_t virtual_mem_size = get_total_memory_usage();

    size_t size = 0, max = 256;
    char* str = malloc(max);
    if (!str)
        return -ENOMEM;

    /* This lock is needed for accessing `pgid` and `sid`. */
    rwlock_read_lock(&g_process_id_lock);
    struct {
        const char* fmt;
        unsigned long val;
    } status[] = {
        /* 4-10 */
        /* ppid */
        { " %d", g_process.ppid },
        /* pgrp */
        { " %d", g_process.pgid },
        /* session */
        { " %d", g_process.sid },
        /* tty_nr */
        { " %d", /*dummy value=*/0 },
        /* tpgid */
        { " %d", /*dummy value=*/0 },
        /* flags; PF_RANDOMIZE */
        { " %u", g_pal_public_state->disable_aslr ? 0 : 0x00400000 },
        /* minflt */
        { " %lu", /*dummy value=*/0 },

        /* 11-20 */
        /* cminflt */
        { " %lu", /*dummy value=*/0 },
        /* majflt */
        { " %lu", /*dummy value=*/0 },
        /* cmajflt */
        { " %lu", /*dummy value=*/0 },
        /* utime */
        { " %lu", /*dummy value=*/0 },
        /* stime */
        { " %lu", /*dummy value=*/0 },
        /* cutime */
        { " %ld", /*dummy value=*/0 },
        /* cstime */
        { " %ld", /*dummy value=*/0 },
        /* priority */
        { " %ld", /*dummy value=*/0 },
        /* nice */
        { " %ld", /*dummy value=*/0 },
        /* num_threads */
        { " %ld", get_thread_num() },

        /* 21-30 */
        /* itrealvalue; always zero in Linux */
        { " %ld", 0 },
        /* starttime */
        { " %llu", /*dummy value=*/0 },
        /* vsize */
        { " %lu", virtual_mem_size },
        /* rss */
        { " %lu", virtual_mem_size / PAGE_SIZE },
        /* rsslim */
        { " %lu", /*dummy value=*/0 },
        /* startcode */
        { " %lu", /*dummy value=*/0 },
        /* endcode */
        { " %lu", /*dummy value=*/0 },
        /* startstack */
        { " %lu", /*dummy value=*/0 },
        /* kstkesp */
        { " %lu", /*dummy value=*/0 },
        /* kstkeip */
        { " %lu", /*dummy value=*/0 },

        /* 31-40 */
        /* signal */
        { " %lu", /*dummy value=*/0 },
        /* blocked */
        { " %lu", /*dummy value=*/0 },
        /* sigignore */
        { " %lu", /*dummy value=*/0 },
        /* sigcatch */
        { " %lu", /*dummy value=*/0 },
        /* wchan */
        { " %lu", /*dummy value=*/0 },
        /* nswap; always 0 */
        { " %lu", 0 },
        /* cnswap; always 0 */
        { " %lu", 0 },
        /* exit_signal */
        { " %d", /*dummy value=*/0 },
        /* processor */
        { " %d", /*dummy value=*/0 },
        /* rt_priority */
        { " %u", /*dummy value=*/0 },

        /* 41-50 */
        /* policy */
        { " %u", /*dummy value=*/0 },
        /* delayacct_blkio_ticks */
        { " %llu", /*dummy value=*/0 },
        /* guest_time */
        { " %lu", /*dummy value=*/0 },
        /* cguest_time */
        { " %ld", /*dummy value=*/0 },
        /* start_data */
        { " %lu", /*dummy value=*/0 },
        /* end_data */
        { " %lu", /*dummy value=*/0 },
        /* start_brk */
        { " %lu", /*dummy value=*/0 },
        /* arg_start */
        { " %lu", /*dummy value=*/0 },
        /* arg_end */
        { " %lu", /*dummy value=*/0 },
        /* env_start */
        { " %lu", /*dummy value=*/0 },

        /* 51-52 */
        /* env_end */
        { " %lu", /*dummy value=*/0 },
        /* exit_code */
        { " %d\n", /*dummy value=*/0 },
    };
    rwlock_read_unlock(&g_process_id_lock);

    size_t i = 0;
    while (i < ARRAY_SIZE(status)) {
        int ret;
        if (i == 0) {
            /* Print first 3 fields: pid, comm, state. */
            ret = snprintf(str, max, "%d (%s) R", g_process.pid, comm);
            if (ret < 0) {
                free(str);
                return ret;
            }
            assert((size_t)ret < max);
            size += ret;
        }

        ret = snprintf(str + size, max - size, status[i].fmt, status[i].val);
        if (ret < 0) {
            free(str);
            return ret;
        }

        if (size + ret >= max) {
            max *= 2;
            size = 0;
            i = 0;
            free(str);
            /* TODO: use `realloc()` once it's available. */
            str = malloc(max);
            if (!str)
                return -ENOMEM;

            continue;
        }

        size += ret;
        i++;
    }

    *out_data = str;
    *out_size = size;
    return 0;
}
