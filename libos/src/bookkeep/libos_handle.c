/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains code to maintain bookkeeping for handles in library OS.
 */

#include "libos_checkpoint.h"
#include "libos_fs.h"
#include "libos_fs_lock.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_thread.h"
#include "pal.h"
#include "stat.h"
#include "toml_utils.h"

static struct libos_lock handle_mgr_lock;

#define HANDLE_MGR_ALLOC 32

#define SYSTEM_LOCK()   lock(&handle_mgr_lock)
#define SYSTEM_UNLOCK() unlock(&handle_mgr_lock)
#define SYSTEM_LOCKED() locked(&handle_mgr_lock)

#define OBJ_TYPE struct libos_handle
#include "memmgr.h"

static MEM_MGR handle_mgr = NULL;

#define INIT_HANDLE_MAP_SIZE 32

void maybe_lock_pos_handle(struct libos_handle* hdl) {
    if (hdl->seekable)
        lock(&hdl->pos_lock);
}

void maybe_unlock_pos_handle(struct libos_handle* hdl) {
    if (hdl->seekable)
        unlock(&hdl->pos_lock);
}

int open_executable(struct libos_handle* hdl, const char* path) {
    struct libos_dentry* dent = NULL;

    lock(&g_dcache_lock);
    int ret = path_lookupat(/*start=*/NULL, path, LOOKUP_FOLLOW, &dent);
    if (ret < 0) {
        goto out;
    }

    if (dent->inode->type != S_IFREG) {
        ret = -EACCES;
        goto out;
    }

    if (!(dent->inode->perm & S_IXUSR)) {
        ret = -EACCES;
        goto out;
    }

    ret = dentry_open(hdl, dent, O_RDONLY);
    if (ret < 0) {
        goto out;
    }

    ret = 0;
out:
    unlock(&g_dcache_lock);
    if (dent)
        put_dentry(dent);

    return ret;
}

int init_exec_handle(const char* const* argv, char*** out_new_argv) {
    lock(&g_process.fs_lock);
    if (g_process.exec) {
        /* `g_process.exec` handle is already initialized if we did execve. See
         * `libos_syscall_execve_rtld`. */
        unlock(&g_process.fs_lock);
        *out_new_argv = NULL;
        return 0;
    }
    unlock(&g_process.fs_lock);

    /* Initialize `g_process.exec` based on `libos.entrypoint` manifest key. */
    char* entrypoint = NULL;
    const char* exec_path;
    struct libos_handle* exec_handle = NULL;
    int ret;

    /* Initialize `g_process.exec` based on `libos.entrypoint` manifest key. */
    assert(g_manifest_root);
    ret = toml_string_in(g_manifest_root, "libos.entrypoint", &entrypoint);
    if (ret < 0) {
        log_error("Cannot parse 'libos.entrypoint'");
        ret = -EINVAL;
        goto out;
    }
    if (!entrypoint) {
        log_error("'libos.entrypoint' must be specified in the manifest");
        ret = -EINVAL;
        goto out;
    }

    exec_path = entrypoint;

    if (strstartswith(exec_path, URI_PREFIX_FILE)) {
        /* Technically we could skip this check, but it's something easy to confuse with
         * loader.entrypoint, so better to have this handled nicely for the users. */
        log_error("'libos.entrypoint' should be an in-Gramine path, not URI.");
        ret = -EINVAL;
        goto out;
    }

    char** new_argv = NULL;
    ret = load_and_check_exec(exec_path, argv, &exec_handle, &new_argv);
    if (ret < 0) {
        goto out;
    }

    lock(&g_process.fs_lock);
    g_process.exec = exec_handle;
    get_handle(exec_handle);
    unlock(&g_process.fs_lock);

    *out_new_argv = new_argv;
    ret = 0;
out:
    free(entrypoint);
    if (exec_handle)
        put_handle(exec_handle);
    return ret;
}

static struct libos_handle_map* get_new_handle_map(uint32_t size);

static int __init_handle(struct libos_fd_handle** fdhdl, uint32_t fd, struct libos_handle* hdl,
                         int fd_flags);

static int __enlarge_handle_map(struct libos_handle_map* map, uint32_t size);

int init_handle(void) {
    if (!create_lock(&handle_mgr_lock)) {
        return -ENOMEM;
    }

    handle_mgr = create_mem_mgr(init_align_up(HANDLE_MGR_ALLOC));
    if (!handle_mgr) {
        return -ENOMEM;
    }

    /* after fork, in the new child process, `libos_init` is run, hence this function too - but
     * forked process will get its RLIMIT_NOFILE from the checkpoint */
    assert(g_pal_public_state);
    if (g_pal_public_state->parent_process)
        return 0;

    assert(g_manifest_root);
    int64_t fds_limit_init64;
    int ret = toml_int_in(g_manifest_root, "sys.fds.limit",
                          /*defaultval=*/get_rlimit_cur(RLIMIT_NOFILE),
                          &fds_limit_init64);
    if (ret < 0) {
        log_error("Cannot parse 'sys.fds.limit'");
        return -EINVAL;
    }
    if (fds_limit_init64 < 0) {
        log_error("'sys.fds.limit' is negative (%ld)", fds_limit_init64);
        return -EINVAL;
    }
    set_rlimit_cur(RLIMIT_NOFILE, (uint64_t)fds_limit_init64);

    return 0;
}

int init_std_handles(void) {
    int ret;
    struct libos_thread* thread = get_cur_thread();

    if (thread->handle_map)
        return 0;

    struct libos_handle_map* handle_map = get_thread_handle_map(thread);

    if (!handle_map) {
        handle_map = get_new_handle_map(INIT_HANDLE_MAP_SIZE);
        if (!handle_map)
            return -ENOMEM;

        set_handle_map(thread, handle_map);
        put_handle_map(handle_map);
    }

    /* `handle_map` is set in current thread, no need to increase ref-count. */

    rwlock_write_lock(&handle_map->lock);

    if (handle_map->fd_size < 3) {
        ret = __enlarge_handle_map(handle_map, INIT_HANDLE_MAP_SIZE);
        if (ret < 0) {
            rwlock_write_unlock(&handle_map->lock);
            return ret;
        }
    }

    /* initialize stdin */
    if (!HANDLE_ALLOCATED(handle_map->map[0])) {
        struct libos_handle* stdin_hdl = get_new_handle();
        if (!stdin_hdl) {
            rwlock_write_unlock(&handle_map->lock);
            return -ENOMEM;
        }

        ret = open_namei(stdin_hdl, /*start=*/NULL, "/dev/tty", O_RDONLY, LOOKUP_FOLLOW,
                         /*found=*/NULL);
        if (ret < 0) {
            rwlock_write_unlock(&handle_map->lock);
            put_handle(stdin_hdl);
            return ret;
        }

        __init_handle(&handle_map->map[0], /*fd=*/0, stdin_hdl, /*flags=*/0);
        put_handle(stdin_hdl);
    }

    /* initialize stdout */
    if (!HANDLE_ALLOCATED(handle_map->map[1])) {
        struct libos_handle* stdout_hdl = get_new_handle();
        if (!stdout_hdl) {
            rwlock_write_unlock(&handle_map->lock);
            return -ENOMEM;
        }

        ret = open_namei(stdout_hdl, /*start=*/NULL, "/dev/tty", O_WRONLY | O_APPEND, LOOKUP_FOLLOW,
                         /*found=*/NULL);
        if (ret < 0) {
            rwlock_write_unlock(&handle_map->lock);
            put_handle(stdout_hdl);
            return ret;
        }

        __init_handle(&handle_map->map[1], /*fd=*/1, stdout_hdl, /*flags=*/0);
        put_handle(stdout_hdl);
    }

    /* initialize stderr as duplicate of stdout */
    if (!HANDLE_ALLOCATED(handle_map->map[2])) {
        struct libos_handle* stdout_hdl = handle_map->map[1]->handle;
        __init_handle(&handle_map->map[2], /*fd=*/2, stdout_hdl, /*flags=*/0);
    }

    if (handle_map->fd_top == FD_NULL || handle_map->fd_top < 2)
        handle_map->fd_top = 2;

    rwlock_write_unlock(&handle_map->lock);
    return 0;
}

struct libos_handle* __get_fd_handle(uint32_t fd, int* fd_flags, struct libos_handle_map* map) {
    assert(map);
    assert(rwlock_is_read_locked(&map->lock) || rwlock_is_write_locked(&map->lock));

    struct libos_fd_handle* fd_handle = NULL;

    if (map->fd_top != FD_NULL && fd <= map->fd_top) {
        fd_handle = map->map[fd];
        if (!HANDLE_ALLOCATED(fd_handle))
            return NULL;

        if (fd_flags)
            *fd_flags = fd_handle->flags;

        return fd_handle->handle;
    }
    return NULL;
}

struct libos_handle* get_fd_handle(uint32_t fd, int* fd_flags, struct libos_handle_map* map) {
    map = map ?: get_thread_handle_map(NULL);
    assert(map);

    struct libos_handle* hdl = NULL;
    rwlock_read_lock(&map->lock);
    if ((hdl = __get_fd_handle(fd, fd_flags, map)))
        get_handle(hdl);
    rwlock_read_unlock(&map->lock);
    return hdl;
}

static struct libos_handle* __detach_fd_handle(struct libos_fd_handle* fd, int* flags,
                                               struct libos_handle_map* map) {
    assert(rwlock_is_write_locked(&map->lock));

    struct libos_handle* handle = NULL;

    if (HANDLE_ALLOCATED(fd)) {
        uint32_t vfd = fd->vfd;
        handle = fd->handle;
        int handle_fd = vfd;
        if (flags)
            *flags = fd->flags;

        fd->vfd    = FD_NULL;
        fd->handle = NULL;
        fd->flags  = 0;

        if (vfd == map->fd_top)
            do {
                if (vfd == 0) {
                    map->fd_top = FD_NULL;
                    break;
                }
                map->fd_top = vfd - 1;
                vfd--;
            } while (!HANDLE_ALLOCATED(map->map[vfd]));

        delete_epoll_items_for_fd(handle_fd, handle);
    }

    return handle;
}

static int clear_posix_locks(struct libos_handle* handle) {
    int ret = 0;
    if (handle) {
        lock(&handle->lock);
        if (handle->dentry) {
            /* Clear file (POSIX) locks for a file. We are required to do that every time a FD is
             * closed, even if the process holds other handles for that file, or duplicated FDs for
             * the same handle. */
            struct libos_file_lock file_lock = {
                .family = FILE_LOCK_POSIX,
                .type   = F_UNLCK,
                .start  = 0,
                .end    = FS_LOCK_EOF,
                .pid    = g_process.pid,
            };
            ret = file_lock_set(handle->dentry, &file_lock, /*block=*/false);
            if (ret < 0) {
                log_warning("error releasing locks: %s", unix_strerror(ret));
            }
        }
        unlock(&handle->lock);
    }
    return ret;
}

struct libos_handle* detach_fd_handle(uint32_t fd, int* flags,
                                      struct libos_handle_map* handle_map) {
    struct libos_handle* handle = NULL;

    if (!handle_map && !(handle_map = get_thread_handle_map(NULL)))
        return NULL;

    rwlock_write_lock(&handle_map->lock);

    if (fd < handle_map->fd_size)
        handle = __detach_fd_handle(handle_map->map[fd], flags, handle_map);

    rwlock_write_unlock(&handle_map->lock);

    (void)clear_posix_locks(handle);

    return handle;
}

struct libos_handle* get_new_handle(void) {
    struct libos_handle* new_handle =
        get_mem_obj_from_mgr_enlarge(handle_mgr, size_align_up(HANDLE_MGR_ALLOC));
    if (!new_handle)
        return NULL;

    memset(new_handle, 0, sizeof(struct libos_handle));
    refcount_set(&new_handle->ref_count, 1);
    if (!create_lock(&new_handle->lock)) {
        free_mem_obj_to_mgr(handle_mgr, new_handle);
        return NULL;
    }
    if (!create_lock(&new_handle->pos_lock)) {
        destroy_lock(&new_handle->lock);
        free_mem_obj_to_mgr(handle_mgr, new_handle);
        return NULL;
    }
    INIT_LISTP(&new_handle->epoll_items);
    new_handle->epoll_items_count = 0;

    static uint32_t local_id_counter = 0;
    uint32_t next_id_counter = __atomic_add_fetch(&local_id_counter, 1, __ATOMIC_RELAXED);
    if (!next_id_counter) {
        /* overflow of local_id_counter, this may lead to aliasing of different handles and is
         * potentially a security vulnerability, so just terminate the whole process */
        log_error("overflow when allocating a handle ID, not safe to proceed");
        BUG();
    }
    new_handle->id = ((uint64_t)g_process.pid << 32) | next_id_counter;
    new_handle->created_by_process = true;

    return new_handle;
}

static int __init_handle(struct libos_fd_handle** fdhdl, uint32_t fd, struct libos_handle* hdl,
                         int fd_flags) {
    struct libos_fd_handle* new_handle = *fdhdl;
    assert((fd_flags & ~FD_CLOEXEC) == 0);  // The only supported flag right now

    if (!new_handle) {
        new_handle = malloc(sizeof(struct libos_fd_handle));
        if (!new_handle)
            return -ENOMEM;
        *fdhdl = new_handle;
    }

    new_handle->vfd   = fd;
    new_handle->flags = fd_flags;
    get_handle(hdl);
    new_handle->handle = hdl;
    return 0;
}

/*
 * Helper function for set_new_fd_handle*(). If find_free is true, tries to find the first free fd
 * (starting from the provided one), otherwise, tries to use fd as-is.
 */
static int __set_new_fd_handle(uint32_t fd, struct libos_handle* hdl, int fd_flags,
                               struct libos_handle_map* handle_map, bool find_free) {
    int ret;

    if (!handle_map && !(handle_map = get_thread_handle_map(NULL)))
        return -EBADF;

    rwlock_write_lock(&handle_map->lock);

    if (handle_map->fd_top != FD_NULL) {
        assert(handle_map->map);
        if (find_free) {
            // find first free fd
            while (fd <= handle_map->fd_top && HANDLE_ALLOCATED(handle_map->map[fd])) {
                fd++;
            }
        } else {
            // check if requested fd is occupied
            if (fd <= handle_map->fd_top && HANDLE_ALLOCATED(handle_map->map[fd])) {
                ret = -EBADF;
                goto out;
            }
        }
    }

    if (fd >= get_rlimit_cur(RLIMIT_NOFILE)) {
        ret = -EMFILE;
        goto out;
    }

    // Enlarge handle_map->map (or allocate if necessary)
    if (fd >= handle_map->fd_size) {
        uint32_t new_size = handle_map->fd_size;
        if (new_size == 0)
            new_size = INIT_HANDLE_MAP_SIZE;

        while (new_size <= fd) {
            if (__builtin_mul_overflow(new_size, 2, &new_size)) {
                ret = -ENFILE;
                goto out;
            }
        }

        ret = __enlarge_handle_map(handle_map, new_size);
        if (ret < 0)
            goto out;
    }

    assert(handle_map->map);
    assert(fd < handle_map->fd_size);
    ret = __init_handle(&handle_map->map[fd], fd, hdl, fd_flags);
    if (ret < 0)
        goto out;

    if (handle_map->fd_top == FD_NULL || fd > handle_map->fd_top)
        handle_map->fd_top = fd;

    ret = fd;

out:
    rwlock_write_unlock(&handle_map->lock);
    return ret;
}

int set_new_fd_handle(struct libos_handle* hdl, int fd_flags, struct libos_handle_map* handle_map) {
    return __set_new_fd_handle(0, hdl, fd_flags, handle_map, /*find_first=*/true);
}

int set_new_fd_handle_by_fd(uint32_t fd, struct libos_handle* hdl, int fd_flags,
                            struct libos_handle_map* handle_map) {
    return __set_new_fd_handle(fd, hdl, fd_flags, handle_map, /*find_first=*/false);
}

int set_new_fd_handle_above_fd(uint32_t fd, struct libos_handle* hdl, int fd_flags,
                               struct libos_handle_map* handle_map) {
    return __set_new_fd_handle(fd, hdl, fd_flags, handle_map, /*find_first=*/true);
}

void get_handle(struct libos_handle* hdl) {
    refcount_inc(&hdl->ref_count);
}

static void destroy_handle(struct libos_handle* hdl) {
    destroy_lock(&hdl->lock);
    destroy_lock(&hdl->pos_lock);

    free_mem_obj_to_mgr(handle_mgr, hdl);
}

static int clear_flock_locks(struct libos_handle* hdl) {
    /* Clear flock (BSD) locks for a file. We are required to do that when the handle is closed. */
    int ret = 0;
    if (hdl) {
        lock(&hdl->lock);
        if (hdl->dentry && hdl->created_by_process) {
            assert(hdl->ref_count == 0);
            struct libos_file_lock file_lock = {
                .family    = FILE_LOCK_FLOCK,
                .type      = F_UNLCK,
                .handle_id = hdl->id,
            };
            int ret = file_lock_set(hdl->dentry, &file_lock, /*block=*/false);
            if (ret < 0) {
                log_warning("error releasing locks: %s", unix_strerror(ret));
            }
        }
        unlock(&hdl->lock);
    }
    return ret;
}

void put_handle(struct libos_handle* hdl) {
    refcount_t ref_count = refcount_dec(&hdl->ref_count);

    if (!ref_count) {
        assert(hdl->epoll_items_count == 0);
        assert(LISTP_EMPTY(&hdl->epoll_items));

        if (hdl->is_dir) {
            clear_directory_handle(hdl);
        }

        if (hdl->fs && hdl->fs->fs_ops && hdl->fs->fs_ops->close)
            hdl->fs->fs_ops->close(hdl);

        free(hdl->uri);

        if (hdl->pal_handle) {
            PalObjectDestroy(hdl->pal_handle);
            hdl->pal_handle = NULL;
        }

        if (hdl->dentry) { /* no locking needed as no other reference exists */
            (void)clear_flock_locks(hdl);
            put_dentry(hdl->dentry);
        }

        if (hdl->inode)
            put_inode(hdl->inode);

        destroy_handle(hdl);
    }
}

static struct libos_handle_map* get_new_handle_map(uint32_t size) {
    struct libos_handle_map* handle_map = calloc(1, sizeof(struct libos_handle_map));

    if (!handle_map)
        return NULL;

    handle_map->map = calloc(size, sizeof(*handle_map->map));

    if (!handle_map->map) {
        free(handle_map);
        return NULL;
    }

    handle_map->fd_top  = FD_NULL;
    handle_map->fd_size = size;
    if (!rwlock_create(&handle_map->lock)) {
        free(handle_map->map);
        free(handle_map);
        return NULL;
    }

    refcount_set(&handle_map->ref_count, 1);

    return handle_map;
}

static int __enlarge_handle_map(struct libos_handle_map* map, uint32_t size) {
    assert(rwlock_is_write_locked(&map->lock));

    if (size <= map->fd_size)
        return 0;

    struct libos_fd_handle** new_map = calloc(size, sizeof(new_map[0]));
    if (!new_map)
        return -ENOMEM;

    memcpy(new_map, map->map, map->fd_size * sizeof(new_map[0]));
    free(map->map);
    map->map     = new_map;
    map->fd_size = size;
    return 0;
}

int dup_handle_map(struct libos_handle_map** new, struct libos_handle_map* old_map) {
    rwlock_read_lock(&old_map->lock);

    /* allocate a new handle mapping with the same size as
       the old one */
    struct libos_handle_map* new_map = get_new_handle_map(old_map->fd_size);

    if (!new_map)
        return -ENOMEM;

    new_map->fd_top = old_map->fd_top;

    if (old_map->fd_top == FD_NULL)
        goto done;

    for (uint32_t i = 0; i <= old_map->fd_top; i++) {
        struct libos_fd_handle* fd_old = old_map->map[i];
        struct libos_fd_handle* fd_new;

        /* now we go through the handle map and reassign each
           of them being allocated */
        if (HANDLE_ALLOCATED(fd_old)) {
            /* first, get the handle to prevent it from being deleted */
            struct libos_handle* hdl = fd_old->handle;
            get_handle(hdl);

            fd_new = malloc(sizeof(struct libos_fd_handle));
            if (!fd_new) {
                for (uint32_t j = 0; j < i; j++) {
                    put_handle(new_map->map[j]->handle);
                    free(new_map->map[j]);
                }
                rwlock_read_unlock(&old_map->lock);
                *new = NULL;
                free(new_map);
                return -ENOMEM;
            }

            /* DP: I assume we really need a deep copy of the handle map? */
            new_map->map[i] = fd_new;
            fd_new->vfd     = fd_old->vfd;
            fd_new->handle  = hdl;
            fd_new->flags   = fd_old->flags;
        }
    }

done:
    rwlock_read_unlock(&old_map->lock);
    *new = new_map;
    return 0;
}

void get_handle_map(struct libos_handle_map* map) {
    refcount_inc(&map->ref_count);
}

void put_handle_map(struct libos_handle_map* map) {
    refcount_t ref_count = refcount_dec(&map->ref_count);

    if (!ref_count) {
        if (map->fd_top == FD_NULL)
            goto done;

        for (uint32_t i = 0; i <= map->fd_top; i++) {
            if (!map->map[i])
                continue;

            if (map->map[i]->vfd != FD_NULL) {
                struct libos_handle* handle = map->map[i]->handle;

                if (handle)
                    put_handle(handle);
            }

            free(map->map[i]);
        }

    done:
        rwlock_destroy(&map->lock);
        free(map->map);
        free(map);
    }
}

static int walk_handle_map_writable(int (*callback)(struct libos_fd_handle*,
                                                    struct libos_handle_map*),
                                    struct libos_handle_map* map) {
    int ret = 0;
    rwlock_write_lock(&map->lock);

    for (uint32_t i = 0; map->fd_top != FD_NULL && i <= map->fd_top; i++) {
        if (!HANDLE_ALLOCATED(map->map[i]))
            continue;

        if ((ret = (*callback)(map->map[i], map)) < 0)
            break;
    }

    rwlock_write_unlock(&map->lock);
    return ret;
}

static int detach_fd(struct libos_fd_handle* fd_hdl, struct libos_handle_map* map) {
    struct libos_handle* hdl = __detach_fd_handle(fd_hdl, NULL, map);
    put_handle(hdl);
    return 0;
}

void detach_all_fds(void) {
    struct libos_handle_map* handle_map = get_thread_handle_map(NULL);
    assert(handle_map);

    /* TODO: either this should check the return value or the iterator function should not halt on
     *       errors. */
    walk_handle_map_writable(&detach_fd, handle_map);
}

void close_cloexec_handles(struct libos_handle_map* map) {
    rwlock_write_lock(&map->lock);

    for (uint32_t i = 0; map->fd_top != FD_NULL && i <= map->fd_top; i++) {
        struct libos_fd_handle* fd_hdl = map->map[i];

        if (!HANDLE_ALLOCATED(fd_hdl))
            continue;

        if (fd_hdl->flags & FD_CLOEXEC) {
            struct libos_handle* hdl = __detach_fd_handle(fd_hdl, NULL, map);

            rwlock_write_unlock(&map->lock);
            (void)clear_posix_locks(hdl);

            put_handle(hdl);
            rwlock_write_lock(&map->lock);
        }
    }

    rwlock_write_unlock(&map->lock);
}

void close_handle_range(uint32_t first, uint32_t last, bool cloexec) {
    struct libos_handle_map* handle_map = get_thread_handle_map(NULL);
    rwlock_write_lock(&handle_map->lock);

    for (uint32_t i = first; handle_map->fd_top != FD_NULL && i <= handle_map->fd_top && i <= last;
         i++) {
        struct libos_fd_handle* fd_hdl = handle_map->map[i];

        if (!HANDLE_ALLOCATED(fd_hdl))
            continue;

        if (cloexec) {
            fd_hdl->flags |= FD_CLOEXEC;
        } else {
            struct libos_handle* hdl = __detach_fd_handle(fd_hdl, NULL, handle_map);

            rwlock_write_unlock(&handle_map->lock);
            (void)clear_posix_locks(hdl);

            put_handle(hdl);
            rwlock_write_lock(&handle_map->lock);
        }
    }

    rwlock_write_unlock(&handle_map->lock);
}

BEGIN_CP_FUNC(handle) {
    __UNUSED(size);
    assert(size == sizeof(struct libos_handle));

    struct libos_handle* hdl     = (struct libos_handle*)obj;
    struct libos_handle* new_hdl = NULL;

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off = ADD_CP_OFFSET(sizeof(struct libos_handle));
        ADD_TO_CP_MAP(obj, off);
        new_hdl = (struct libos_handle*)(base + off);

        if (hdl->type == TYPE_SOCK) {
            /* We need this lock taken before `hdl->lock`. This checkpointing mess needs to be
             * untangled. */
            lock(&hdl->info.sock.lock);
        }

        /* TODO: this lock is not released on errors. The main problem here is that `DO_CP` can
         * just return... */
        lock(&hdl->lock);
        *new_hdl = *hdl;

        new_hdl->created_by_process = false;
        new_hdl->dentry = NULL;
        refcount_set(&new_hdl->ref_count, 0);
        clear_lock(&new_hdl->lock);
        clear_lock(&new_hdl->pos_lock);

        DO_CP(fs, hdl->fs, &new_hdl->fs);

        if (hdl->uri)
            DO_CP_MEMBER(str, hdl, new_hdl, uri);

        if (hdl->is_dir) {
            /*
             * We don't checkpoint children dentries of a directory dentry, so the child process
             * will need to list the directory again. However, we keep `dir_info.pos` unchanged
             * so that `getdents/getdents64` will resume from the same place.
             */
            new_hdl->dir_info.dents = NULL;
            new_hdl->dir_info.count = 0;
        }

        if (hdl->dentry) {
            DO_CP_MEMBER(dentry, hdl, new_hdl, dentry);
        }

        /* This list is created empty and all necessary references are added when checkpointing
         * items lists from specific epoll handles. See `epoll_items_list` checkpointing in
         * `libos_epoll.c` for more details. */
        INIT_LISTP(&new_hdl->epoll_items);
        new_hdl->epoll_items_count = 0;

        /* TODO: move this into epoll specific `checkout` callback.
         * It's impossible at the moment, because `DO_CP` is a macro that can be only used inside
         * BEGIN_CP_FUNC. */
        if (hdl->type == TYPE_EPOLL) {
            struct libos_epoll_handle* epoll = &new_hdl->info.epoll;
            clear_lock(&epoll->lock);
            INIT_LISTP(&epoll->waiters);
            INIT_LISTP(&epoll->items);
            epoll->items_count = 0;
            DO_CP(epoll_items_list, hdl, new_hdl);
        }

        if (hdl->type == TYPE_SOCK) {
            PAL_HANDLE pal_handle = __atomic_load_n(&hdl->info.sock.pal_handle, __ATOMIC_ACQUIRE);
            new_hdl->info.sock.pal_handle = NULL;
            if (pal_handle) {
                struct libos_palhdl_entry* entry;
                DO_CP(palhdl_ptr, &pal_handle, &entry);
                entry->phandle = &new_hdl->info.sock.pal_handle;
            }
        }

        if (hdl->fs && hdl->fs->fs_ops && hdl->fs->fs_ops->checkout) {
            int ret = hdl->fs->fs_ops->checkout(new_hdl);
            if (ret < 0) {
                return ret;
            }
        }

        if (new_hdl->pal_handle) {
            struct libos_palhdl_entry* entry;
            DO_CP(palhdl_ptr, &hdl->pal_handle, &entry);
            entry->phandle = &new_hdl->pal_handle;
        }

        unlock(&hdl->lock);
        if (hdl->type == TYPE_SOCK) {
            unlock(&hdl->info.sock.lock);
        }

        if (hdl->inode) {
            /* NOTE: Checkpointing `inode` will take `inode->lock`, so we need to do it after
             * `hdl->lock` is released. */
            DO_CP_MEMBER(inode, hdl, new_hdl, inode);
        }

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_hdl = (struct libos_handle*)(base + off);
    }

    if (objp)
        *objp = (void*)new_hdl;
}
END_CP_FUNC(handle)

BEGIN_RS_FUNC(handle) {
    struct libos_handle* hdl = (void*)(base + GET_CP_FUNC_ENTRY());
    __UNUSED(offset);

    CP_REBASE(hdl->fs);
    CP_REBASE(hdl->dentry);
    CP_REBASE(hdl->inode);
    CP_REBASE(hdl->epoll_items);

    if (!create_lock(&hdl->lock)) {
        return -ENOMEM;
    }

    if (!create_lock(&hdl->pos_lock)) {
        return -ENOMEM;
    }

    if (hdl->dentry) {
        get_dentry(hdl->dentry);
    }

    if (hdl->inode) {
        get_inode(hdl->inode);
    }

    /* TODO: move this to epoll specific `checkin` callback. */
    switch (hdl->type) {
        case TYPE_EPOLL:;
            struct libos_epoll_handle* epoll = &hdl->info.epoll;
            if (!create_lock(&epoll->lock)) {
                return -ENOMEM;
            }
            CP_REBASE(epoll->waiters);
            /* `epoll->items` is rebased in epoll_items_list RS_FUNC. */
            break;
        default:
            break;
    }

    if (hdl->fs && hdl->fs->fs_ops && hdl->fs->fs_ops->checkin) {
        int ret = hdl->fs->fs_ops->checkin(hdl);
        if (ret < 0)
            return ret;
    }
}
END_RS_FUNC(handle)

BEGIN_CP_FUNC(fd_handle) {
    __UNUSED(size);
    assert(size == sizeof(struct libos_fd_handle));

    struct libos_fd_handle* fdhdl     = (struct libos_fd_handle*)obj;
    struct libos_fd_handle* new_fdhdl = NULL;

    size_t off = ADD_CP_OFFSET(sizeof(struct libos_fd_handle));
    new_fdhdl = (struct libos_fd_handle*)(base + off);
    *new_fdhdl = *fdhdl;
    DO_CP(handle, fdhdl->handle, &new_fdhdl->handle);
    ADD_CP_FUNC_ENTRY(off);

    if (objp)
        *objp = (void*)new_fdhdl;
}
END_CP_FUNC_NO_RS(fd_handle)

BEGIN_CP_FUNC(handle_map) {
    __UNUSED(size);
    assert(size >= sizeof(struct libos_handle_map));

    struct libos_handle_map* handle_map     = (struct libos_handle_map*)obj;
    struct libos_handle_map* new_handle_map = NULL;
    struct libos_fd_handle** ptr_array;

    rwlock_read_lock(&handle_map->lock);

    int fd_size = handle_map->fd_top != FD_NULL ? handle_map->fd_top + 1 : 0;

    size = sizeof(struct libos_handle_map) + (sizeof(struct libos_fd_handle*) * fd_size);

    size_t off = GET_FROM_CP_MAP(obj);

    if (!off) {
        off            = ADD_CP_OFFSET(size);
        new_handle_map = (struct libos_handle_map*)(base + off);

        *new_handle_map = *handle_map;

        ptr_array = (void*)new_handle_map + sizeof(struct libos_handle_map);

        new_handle_map->fd_size = fd_size;
        new_handle_map->map     = fd_size ? ptr_array : NULL;

        refcount_set(&new_handle_map->ref_count, 0);
        new_handle_map->lock = (struct libos_rwlock){0};

        for (int i = 0; i < fd_size; i++) {
            if (HANDLE_ALLOCATED(handle_map->map[i]))
                DO_CP(fd_handle, handle_map->map[i], &ptr_array[i]);
            else
                ptr_array[i] = NULL;
        }

        ADD_CP_FUNC_ENTRY(off);
    } else {
        new_handle_map = (struct libos_handle_map*)(base + off);
    }

    rwlock_read_unlock(&handle_map->lock);

    if (objp)
        *objp = (void*)new_handle_map;
}
END_CP_FUNC(handle_map)

BEGIN_RS_FUNC(handle_map) {
    struct libos_handle_map* handle_map = (void*)(base + GET_CP_FUNC_ENTRY());
    __UNUSED(offset);

    CP_REBASE(handle_map->map);
    assert(handle_map->map);

    DEBUG_RS("size=%d,top=%d", handle_map->fd_size, handle_map->fd_top);

    if (!rwlock_create(&handle_map->lock)) {
        return -ENOMEM;
    }
    rwlock_write_lock(&handle_map->lock);

    if (handle_map->fd_top != FD_NULL)
        for (uint32_t i = 0; i <= handle_map->fd_top; i++) {
            CP_REBASE(handle_map->map[i]);
            if (HANDLE_ALLOCATED(handle_map->map[i])) {
                CP_REBASE(handle_map->map[i]->handle);
                struct libos_handle* hdl = handle_map->map[i]->handle;
                assert(hdl);
                get_handle(hdl);
                DEBUG_RS("[%d]%s", i, hdl->uri ?: hdl->fs_type);
            }
        }

    rwlock_write_unlock(&handle_map->lock);
}
END_RS_FUNC(handle_map)
