/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include "libos_fs.h"
#include "libos_fs_lock.h"
#include "libos_ipc.h"
#include "libos_lock.h"
#include "linux_abi/fs.h"

/*
 * Global lock for the whole subsystem. Protects access to `g_dent_file_locks_list`, and also to
 * dentry fields (`file_locks` and `maybe_has_file_locks`).
 */
static struct libos_lock g_fs_lock_lock;

/*
 * Describes a pending request for a file lock. After processing the request, the object is removed,
 * and a possible waiter is notified (see below).
 *
 * If the request is initiated by another process over IPC, `notify.vmid` and `notify.seq` should be
 * set to parameters of IPC message. After processing the request, IPC response will be sent.
 *
 * If the request is initiated by process leader, `notify.vmid` should be set to 0, and
 * `notify.event` should be set to an event handle. After processing the request, the event will be
 * triggered, and `*notify.result` will be set to the result.
 */
DEFINE_LISTP(file_lock_request);
DEFINE_LIST(file_lock_request);
struct file_lock_request {
    struct libos_file_lock file_lock;

    struct {
        IDTYPE vmid;
        unsigned int seq;

        /* Note that `event` and `result` are owned by the side making the request, and outlive this
         * object (we delete it as soon as the request is processed). */
        PAL_HANDLE event;
        int* result;
    } notify;

    LIST_TYPE(file_lock_request) list;
};

/* Describes file locks' details for a given dentry. Holds both POSIX (fcntl) and BSD (flock)
 * locks. */
DEFINE_LISTP(dent_file_locks);
DEFINE_LIST(dent_file_locks);
struct dent_file_locks {
    struct libos_dentry* dent;

    /* Used to disallow mixing of POSIX and BSD locks on the same file (dentry). Note that all file
     * locking requests are processed by the leader process, so even if POSIX and BSD locks are
     * created in different processes, they will end up in the leader and it will update these
     * fields. */
    bool posix_used;
    bool flock_used;

    /*
     * POSIX (fcntl) and BSD (flock) locks for a given dentry.
     *
     * For POSIX locks:
     *   - sorted by PID and then by start position (so that we are able to merge and split locks),
     *   - the ranges do not overlap within a given PID.
     *
     * BSD locks do not have ranges, thus the above properties do not apply.
     */
    LISTP_TYPE(libos_file_lock) file_locks;

    /* Pending requests. */
    LISTP_TYPE(file_lock_request) file_lock_requests;

    /* List node, for `g_dent_file_locks_list`. */
    LIST_TYPE(dent_file_locks) list;
};

/* Global list of `dent_file_locks` objects. Used for cleanup. */
static LISTP_TYPE(dent_file_locks) g_dent_file_locks_list = LISTP_INIT;

int init_fs_lock(void) {
    if (g_process_ipc_ids.leader_vmid)
        return 0;

    return create_lock(&g_fs_lock_lock);
}

static int find_dent_file_locks(struct libos_dentry* dent, bool create,
                                struct dent_file_locks** out_dent_file_locks) {
    assert(locked(&g_fs_lock_lock));
    if (!dent->file_locks && create) {
        struct dent_file_locks* dent_file_locks = malloc(sizeof(*dent_file_locks));
        if (!dent_file_locks)
            return -ENOMEM;
        dent_file_locks->posix_used = false;
        dent_file_locks->flock_used = false;
        dent_file_locks->dent = dent;
        get_dentry(dent);
        INIT_LISTP(&dent_file_locks->file_locks);
        INIT_LISTP(&dent_file_locks->file_lock_requests);
        dent->file_locks = dent_file_locks;

        LISTP_ADD(dent_file_locks, &g_dent_file_locks_list, list);
    }
    *out_dent_file_locks = dent->file_locks;
    return 0;
}

static int file_lock_dump_write_all(const char* str, size_t size, void* arg) {
    __UNUSED(arg);
    log_always("file_lock: %.*s", (int)size, str);
    return 0;
}

/* Log current locks for a file, for debugging purposes. */
static void file_locks_dump(struct dent_file_locks* dent_file_locks) {
    assert(locked(&g_fs_lock_lock));
    struct print_buf buf = INIT_PRINT_BUF(&file_lock_dump_write_all);
    IDTYPE pid = 0;
    bool force_flush = false;

    struct libos_file_lock* file_lock;
    LISTP_FOR_EACH_ENTRY(file_lock, &dent_file_locks->file_locks, list) {
        char c;
        switch (file_lock->type) {
            case F_RDLCK: c = 'r'; break;
            case F_WRLCK: c = 'w'; break;
            default: c = '?'; break;
        }

        if (file_lock->family == FILE_LOCK_POSIX) {
            if (file_lock->pid != pid) {
                if (force_flush)
                    buf_flush(&buf);
                pid = file_lock->pid;
                force_flush = true;
                buf_printf(&buf, "fcntl (POSIX): pid=%d:", pid);
            }
            if (file_lock->end == FS_LOCK_EOF) {
                buf_printf(&buf, " %c[%lu..end]", c, file_lock->start);
            } else {
                buf_printf(&buf, " %c[%lu..%lu]", c, file_lock->start, file_lock->end);
            }
        } else {
            assert(file_lock->family == FILE_LOCK_FLOCK);
            if (force_flush)
                buf_flush(&buf);
            force_flush = true;
            buf_printf(&buf, " flock (BSD): handle id=%lu: %c", file_lock->handle_id, c);
        }
    }

    if (LISTP_EMPTY(&dent_file_locks->file_locks)) {
        buf_printf(&buf, "no locks");
    }
    buf_flush(&buf);
}

/* Removes `dent_file_locks` if it's not necessary (no locks are held or requested for a file). */
static void dent_file_locks_gc(struct dent_file_locks* dent_file_locks) {
    assert(locked(&g_fs_lock_lock));
    if (g_log_level >= LOG_LEVEL_TRACE)
        file_locks_dump(dent_file_locks);
    if (LISTP_EMPTY(&dent_file_locks->file_locks)
            && LISTP_EMPTY(&dent_file_locks->file_lock_requests)) {
        struct libos_dentry* dent = dent_file_locks->dent;
        dent->file_locks = NULL;

        LISTP_DEL(dent_file_locks, &g_dent_file_locks_list, list);

        put_dentry(dent);
        free(dent_file_locks);
    }
}

/*
 * Find first lock that conflicts with `file_lock`. For POSIX (fcntl) locks, two locks conflict if
 * they have different PIDs, their ranges overlap, and at least one of them is a write lock. For BSD
 * (flock) locks, two locks conflict if they have different handle IDs and at least one of them is
 * an exclusive lock.
 */
static struct libos_file_lock* file_lock_find_conflict(struct dent_file_locks* dent_file_locks,
                                                       struct libos_file_lock* file_lock) {
    assert(locked(&g_fs_lock_lock));
    assert(file_lock->type != F_UNLCK);

    struct libos_file_lock* cur;
    /* Gramine doesn't support mixing POSIX and flock types of locks: it fails loudly. */
    if (file_lock->family == FILE_LOCK_POSIX) {
        LISTP_FOR_EACH_ENTRY(cur, &dent_file_locks->file_locks, list) {
            if (cur->pid != file_lock->pid && file_lock->start <= cur->end
                    && cur->start <= file_lock->end
                    && (cur->type == F_WRLCK || file_lock->type == F_WRLCK))
                return cur;
        }
    } else {
        assert(file_lock->family == FILE_LOCK_FLOCK);
        LISTP_FOR_EACH_ENTRY(cur, &dent_file_locks->file_locks, list) {
            if (cur->handle_id != file_lock->handle_id
                    && (cur->type == F_WRLCK || file_lock->type == F_WRLCK))
                return cur;
        }
    }
    return NULL;
}

/*
 * Add a new lock request. Before releasing `g_fs_lock_lock`, the caller has to initialize the
 * `notify` part of the request (see `struct file_lock_request` above).
 */
static int file_lock_add_request(struct dent_file_locks* dent_file_locks,
                                 struct libos_file_lock* file_lock,
                                 struct file_lock_request** out_req) {
    assert(locked(&g_fs_lock_lock));
    assert(file_lock->type != F_UNLCK);

    struct file_lock_request* req = malloc(sizeof(*req));
    if (!req)
        return -ENOMEM;
    req->file_lock = *file_lock;
    LISTP_ADD(req, &dent_file_locks->file_lock_requests, list);
    *out_req = req;
    return 0;
}

/*
 * Main part of `file_lock_set`. Adds/removes a POSIX lock (depending on `file_lock->type`), assumes
 * we already verified there are no conflicts. Replaces existing locks for a given PID, and merges
 * adjacent locks if possible.
 *
 * See also Linux sources (`fs/locks.c`) for a similar implementation.
 */
static int _posix_lock_set(struct dent_file_locks* dent_file_locks,
                           struct libos_file_lock* file_lock) {
    assert(locked(&g_fs_lock_lock));
    assert(file_lock->family == FILE_LOCK_POSIX);

    /* Preallocate new locks first, so that we don't fail after modifying something. */

    /* Lock to be added. Not necessary for F_UNLCK, because we're only removing existing locks. */
    struct libos_file_lock* new = NULL;
    if (file_lock->type != F_UNLCK) {
        new = malloc(sizeof(*new));
        if (!new)
            return -ENOMEM;
    }

    /* Extra lock that we might need when splitting existing one. */
    struct libos_file_lock* extra = malloc(sizeof(*extra));
    if (!extra) {
        free(new);
        return -ENOMEM;
    }

    /* Target range: we will be changing it when merging existing locks. */
    uint64_t start = file_lock->start;
    uint64_t end   = file_lock->end;

    /* `prev` will be set to the last lock before target range, so that we add the new lock just
     * after `prev`. */
    struct libos_file_lock* prev = NULL;

    struct libos_file_lock* cur;
    struct libos_file_lock* tmp;
    LISTP_FOR_EACH_ENTRY_SAFE(cur, tmp, &dent_file_locks->file_locks, list) {
        if (cur->family != FILE_LOCK_POSIX)
            continue;

        if (cur->pid < file_lock->pid) {
            prev = cur;
            continue;
        }
        if (file_lock->pid < cur->pid) {
            break;
        }

        if (cur->type == file_lock->type) {
            /* Same lock type: we can possibly merge the locks. */

            if (start > 0 && cur->end < start - 1) {
                /* `cur` ends before target range begins, and is not even adjacent */
                prev = cur;
            } else if (end < FS_LOCK_EOF && end + 1 < cur->start) {
                /* `cur` begins after target range ends, and is not even adjacent - we're
                 * done */
                break;
            } else {
                /* `cur` is either adjacent to target range, or overlaps with it. Delete it, and
                 * expand the target range. */
                start = MIN(start, cur->start);
                end = MAX(end, cur->end);
                LISTP_DEL(cur, &dent_file_locks->file_locks, list);
                free(cur);
            }
        } else {
            /* Different lock types: if they overlap, we delete the target range. */

            if (cur->end < start) {
                /* `cur` ends before target range begins */
                prev = cur;
            } else if (end < cur->start) {
                /* `cur` begins after target range ends - we're done */
                break;
            } else if (cur->start < start && cur->end <= end) {
                /*
                 * `cur` overlaps with beginning of target range. Shorten `cur`.
                 *
                 * cur:  =======
                 * tgt:    -------
                 *
                 * cur:  ==
                 */
                assert(start > 0);
                cur->end = start - 1;
                prev = cur;
            } else if (cur->start < start && cur->end > end) {
                /*
                 * The target range is inside `cur`. Split `cur` and finish.
                 *
                 * cur:    ========
                 * tgt:      ----
                 *
                 * cur:    ==
                 * extra:        ==
                 */

                /* We'll need `extra` only once, because we exit the loop afterwards. */
                assert(extra);

                assert(start > 0);
                extra->family = FILE_LOCK_POSIX;
                extra->type = cur->type;
                extra->start = end + 1;
                extra->end = cur->end;
                extra->pid = cur->pid;
                extra->handle_id = 0; /* unused in POSIX (fcntl) locks, unset for sanity */
                cur->end = start - 1;
                LISTP_ADD_AFTER(extra, cur, &dent_file_locks->file_locks, list);
                extra = NULL;
                /* We're done: the new lock, if any, will be added after `cur`. */
                prev = cur;
                break;
            } else if (start <= cur->start && cur->end <= end) {
                /*
                 * `cur` is completely covered by target range. Delete `cur`.
                 *
                 * cur:    ====
                 * tgt:  --------
                 */
                LISTP_DEL(cur, &dent_file_locks->file_locks, list);
                free(cur);
            } else {
                /*
                 * `cur` overlaps with end of target range. Shorten `cur` and finish.
                 *
                 * cur:    ====
                 * tgt: -----
                 *
                 * cur:      ==
                 */
                assert(start <= cur->start && end < cur->end);
                assert(end < FS_LOCK_EOF);
                cur->start = end + 1;
                break;
            }
        }
    }

    if (new) {
        assert(file_lock->type != F_UNLCK);

        new->family = FILE_LOCK_POSIX;
        new->type = file_lock->type;
        new->start = start;
        new->end = end;
        new->pid = file_lock->pid;
        new->handle_id = 0; /* unused in POSIX (fcntl) locks, unset for sanity */

#ifdef DEBUG
        /* Assert that list order is preserved */
        struct libos_file_lock* next = prev
            ? LISTP_NEXT_ENTRY(prev, &dent_file_locks->file_locks, list)
            : LISTP_FIRST_ENTRY(&dent_file_locks->file_locks, struct libos_file_lock, list);
        if (prev)
            assert(prev->pid < file_lock->pid
                    || (prev->pid == file_lock->pid && prev->end < start));
        if (next)
            assert(file_lock->pid < next->pid || (file_lock->pid == next->pid && end < next->start));
#endif

        if (prev) {
            LISTP_ADD_AFTER(new, prev, &dent_file_locks->file_locks, list);
        } else {
            LISTP_ADD(new, &dent_file_locks->file_locks, list);
        }
    }

    if (extra)
        free(extra);
    return 0;
}

/*
 * Main part of `file_lock_set`. Adds/removes a BSD lock (depending on `file_lock->type`), assumes
 * we already verified there are no conflicts. Replaces existing locks for a given handle ID.
 */
static int _flock_lock_set(struct dent_file_locks* dent_file_locks,
                           struct libos_file_lock* file_lock) {
    assert(locked(&g_fs_lock_lock));
    assert(file_lock->family == FILE_LOCK_FLOCK);

    /* Lock to be added. Not necessary for F_UNLCK, because we're only removing existing locks. */
    struct libos_file_lock* new = NULL;
    if (file_lock->type != F_UNLCK) {
        new = malloc(sizeof(*new));
        if (!new)
            return -ENOMEM;
    }

    struct libos_file_lock* cur;
    struct libos_file_lock* tmp;
    LISTP_FOR_EACH_ENTRY_SAFE(cur, tmp, &dent_file_locks->file_locks, list) {
        if (cur->family != FILE_LOCK_FLOCK)
            continue;

        if (cur->handle_id == file_lock->handle_id) {
            LISTP_DEL(cur, &dent_file_locks->file_locks, list);
            free(cur);
            break;
        }
    }

    if (new) {
        assert(file_lock->type != F_UNLCK);
        new->family = FILE_LOCK_FLOCK;
        new->type = file_lock->type;
        new->handle_id = file_lock->handle_id;
        new->start = new->end = new->pid = 0; /* unused in BSD (flock) locks, unset for sanity */

        LISTP_ADD(new, &dent_file_locks->file_locks, list);
    }

    return 0;
}

/*
 * Process pending requests. This function should be called after any modification to the list of
 * locks, since we might have unblocked a request.
 *
 * TODO: This is pretty inefficient, but perhaps good enough for now...
 */
static void file_lock_process_requests(struct dent_file_locks* dent_file_locks) {
    assert(locked(&g_fs_lock_lock));

    bool changed;
    do {
        changed = false;

        struct file_lock_request* req;
        struct file_lock_request* tmp;
        LISTP_FOR_EACH_ENTRY_SAFE(req, tmp, &dent_file_locks->file_lock_requests, list) {
            struct libos_file_lock* conflict = file_lock_find_conflict(dent_file_locks,
                                                                       &req->file_lock);
            if (!conflict) {
                int result = req->file_lock.family == FILE_LOCK_POSIX
                                 ? _posix_lock_set(dent_file_locks, &req->file_lock)
                                 : _flock_lock_set(dent_file_locks, &req->file_lock);
                LISTP_DEL(req, &dent_file_locks->file_lock_requests, list);

                /* Notify the waiter that we processed their request. Note that the result might
                 * still be a failure (-ENOMEM). */
                if (req->notify.vmid == 0) {
                    assert(req->notify.event);
                    assert(req->notify.result);
                    *req->notify.result = result;
                    PalEventSet(req->notify.event);
                } else {
                    assert(!req->notify.event);
                    assert(!req->notify.result);

                    int ret = ipc_file_lock_set_send_response(req->notify.vmid, req->notify.seq,
                                                              result);
                    if (ret < 0) {
                        log_warning("file lock: error sending result over IPC: %s",
                                    unix_strerror(ret));
                    }
                }
                free(req);
                changed = true;
            }
        }
    } while (changed);
}

/* Add/remove a lock if possible. On conflict, returns -EAGAIN (if `wait` is false) or adds a new
 * request (if `wait` is true). */
static int file_lock_set_or_add_request(struct libos_dentry* dent,
                                        struct libos_file_lock* file_lock,
                                        bool wait, struct file_lock_request** out_req) {
    assert(locked(&g_fs_lock_lock));

    struct dent_file_locks* dent_file_locks = NULL;
    int ret = find_dent_file_locks(dent, /*create=*/file_lock->type != F_UNLCK, &dent_file_locks);
    if (ret < 0)
        goto out;
    if (!dent_file_locks) {
        assert(file_lock->type == F_UNLCK);
        /* Nothing to unlock. */
        return 0;
    }

    if (file_lock->type != F_UNLCK) {
        if ((file_lock->family == FILE_LOCK_FLOCK && dent_file_locks->posix_used)
                || (file_lock->family == FILE_LOCK_POSIX && dent_file_locks->flock_used)) {
            log_error("Application wants to use both POSIX (fcntl) and BSD (flock) file locks on "
                      "the same file. This is not supported.");
            ret = -EPERM;
            goto out;
        }
    }

    struct libos_file_lock* conflict = NULL;
    if (file_lock->type != F_UNLCK)
        conflict = file_lock_find_conflict(dent_file_locks, file_lock);
    if (conflict) {
        if (!wait) {
            ret = -EAGAIN;
            goto out;
        }

        struct file_lock_request* req;
        ret = file_lock_add_request(dent_file_locks, file_lock, &req);
        if (ret < 0)
            goto out;

        *out_req = req;
    } else {
        ret = file_lock->family == FILE_LOCK_POSIX ? _posix_lock_set(dent_file_locks, file_lock)
                                                   : _flock_lock_set(dent_file_locks, file_lock);
        if (ret < 0)
            goto out;
        file_lock_process_requests(dent_file_locks);
        *out_req = NULL;
    }

    if (file_lock->type != F_UNLCK) {
        if (file_lock->family == FILE_LOCK_POSIX)
            dent_file_locks->posix_used = true;
        if (file_lock->family == FILE_LOCK_FLOCK)
            dent_file_locks->flock_used = true;
    }
    ret = 0;
out:
    if (dent_file_locks)
        dent_file_locks_gc(dent_file_locks);
    return ret;
}

int file_lock_set(struct libos_dentry* dent, struct libos_file_lock* file_lock, bool wait) {
    assert(file_lock->family == FILE_LOCK_POSIX || file_lock->family == FILE_LOCK_FLOCK);
    assert(file_lock->family == FILE_LOCK_POSIX ? file_lock->pid : file_lock->handle_id);

    int ret;
    if (g_process_ipc_ids.leader_vmid) {
        /* In the IPC version, we use `dent->maybe_has_file_locks` to short-circuit unlocking files
         * that we never locked. This is to prevent unnecessary IPC calls on a handle. */
        lock(&g_fs_lock_lock);
        if (file_lock->type == F_RDLCK || file_lock->type == F_WRLCK) {
            dent->maybe_has_file_locks = true;
        } else if (!dent->maybe_has_file_locks) {
            /* We know we're not holding any locks for the file */
            unlock(&g_fs_lock_lock);
            return 0;
        }
        unlock(&g_fs_lock_lock);

        char* path;
        ret = dentry_abs_path(dent, &path, /*size=*/NULL);
        if (ret < 0)
            return ret;

        ret = ipc_file_lock_set(path, file_lock, wait);
        free(path);
        return ret;
    }

    lock(&g_fs_lock_lock);

    PAL_HANDLE event = NULL;
    struct file_lock_request* req = NULL;
    ret = file_lock_set_or_add_request(dent, file_lock, wait, &req);
    if (ret < 0)
        goto out;
    if (req) {
        /* `file_lock_set_or_add_request` is allowed to add a request only if `wait` is true */
        assert(wait);

        int result;
        ret = PalEventCreate(&event, /*init_signaled=*/false, /*auto_clear=*/false);
        if (ret < 0)
            goto out;
        req->notify.vmid = 0;
        req->notify.seq = 0;
        req->notify.event = event;
        req->notify.result = &result;

        unlock(&g_fs_lock_lock);
        ret = event_wait_with_retry(event);
        lock(&g_fs_lock_lock);
        if (ret < 0)
            goto out;

        ret = result;
    } else {
        ret = 0;
    }
out:
    unlock(&g_fs_lock_lock);
    if (event)
        PalObjectDestroy(event);
    return ret;
}

int file_lock_set_from_ipc(const char* path, struct libos_file_lock* file_lock, bool wait,
                           IDTYPE vmid, unsigned long seq) {
    assert(file_lock->family == FILE_LOCK_POSIX || file_lock->family == FILE_LOCK_FLOCK);
    assert(file_lock->family == FILE_LOCK_POSIX ? file_lock->pid : file_lock->handle_id);
    assert(!g_process_ipc_ids.leader_vmid);

    struct libos_dentry* dent = NULL;
    struct file_lock_request* req = NULL;

    lock(&g_dcache_lock);
    int ret = path_lookupat(g_dentry_root, path, LOOKUP_NO_FOLLOW, &dent);
    unlock(&g_dcache_lock);
    if (ret < 0) {
        log_warning("file_lock_set_from_ipc: error on dentry lookup for %s: %d", path, ret);
        goto out;
    }

    lock(&g_fs_lock_lock);
    ret = file_lock_set_or_add_request(dent, file_lock, wait, &req);
    unlock(&g_fs_lock_lock);
    if (ret < 0)
        goto out;

    if (req) {
        /* `file_lock_set_or_add_request` is allowed to add a request only if `wait` is true */
        assert(wait);

        req->notify.vmid = vmid;
        req->notify.seq = seq;
        req->notify.event = NULL;
        req->notify.result = NULL;
    }
    ret = 0;
out:
    if (dent)
        put_dentry(dent);
    if (req) {
        /* We added a request, so response will be sent later. */
        return 0;
    }
    return ipc_file_lock_set_send_response(vmid, seq, ret);
}

int file_lock_get(struct libos_dentry* dent, struct libos_file_lock* file_lock,
                  struct libos_file_lock* out_file_lock) {
    assert(file_lock->family == FILE_LOCK_POSIX || file_lock->family == FILE_LOCK_FLOCK);
    assert(file_lock->family == FILE_LOCK_POSIX ? file_lock->pid : file_lock->handle_id);
    assert(file_lock->type != F_UNLCK);

    int ret;
    if (g_process_ipc_ids.leader_vmid) {
        char* path;
        ret = dentry_abs_path(dent, &path, /*size=*/NULL);
        if (ret < 0)
            return ret;

        ret = ipc_file_lock_get(path, file_lock, out_file_lock);
        free(path);
        return ret;
    }

    lock(&g_fs_lock_lock);

    struct dent_file_locks* dent_file_locks = NULL;
    ret = find_dent_file_locks(dent, /*create=*/false, &dent_file_locks);
    if (ret < 0)
        goto out;

    struct libos_file_lock* conflict = NULL;
    if (dent_file_locks)
        conflict = file_lock_find_conflict(dent_file_locks, file_lock);
    if (conflict) {
        out_file_lock->family = conflict->family;
        out_file_lock->type = conflict->type;
        out_file_lock->start = conflict->start;
        out_file_lock->end = conflict->end;
        out_file_lock->pid = conflict->pid;
        out_file_lock->handle_id = conflict->handle_id;
    } else {
        out_file_lock->type = F_UNLCK;
    }
    ret = 0;

out:
    if (dent_file_locks)
        dent_file_locks_gc(dent_file_locks);

    unlock(&g_fs_lock_lock);
    return ret;
}

int file_lock_get_from_ipc(const char* path, struct libos_file_lock* file_lock,
                           struct libos_file_lock* out_file_lock) {
    assert(file_lock->family == FILE_LOCK_POSIX || file_lock->family == FILE_LOCK_FLOCK);
    assert(file_lock->family == FILE_LOCK_POSIX ? file_lock->pid : file_lock->handle_id);
    assert(!g_process_ipc_ids.leader_vmid);

    struct libos_dentry* dent = NULL;
    lock(&g_dcache_lock);
    int ret = path_lookupat(g_dentry_root, path, LOOKUP_NO_FOLLOW, &dent);
    unlock(&g_dcache_lock);
    if (ret < 0) {
        log_warning("file_lock_get_from_ipc: error on dentry lookup for %s: %s", path,
                    unix_strerror(ret));
        return ret;
    }

    ret = file_lock_get(dent, file_lock, out_file_lock);
    put_dentry(dent);
    return ret;
}

/* Removes all POSIX locks and lock requests for a given PID and dentry. */
static int file_lock_clear_pid_from_dentry(struct libos_dentry* dent, IDTYPE pid) {
    assert(locked(&g_fs_lock_lock));

    struct dent_file_locks* dent_file_locks;
    int ret = find_dent_file_locks(dent, /*create=*/false, &dent_file_locks);
    if (ret < 0)
        return ret;
    if (!dent_file_locks) {
        /* Nothing to process. */
        return 0;
    }

    bool changed = false;

    struct libos_file_lock* file_lock;
    struct libos_file_lock* file_lock_tmp;
    LISTP_FOR_EACH_ENTRY_SAFE(file_lock, file_lock_tmp, &dent_file_locks->file_locks, list) {
        if (file_lock->family == FILE_LOCK_POSIX && file_lock->pid == pid) {
            LISTP_DEL(file_lock, &dent_file_locks->file_locks, list);
            free(file_lock);
            changed = true;
        }
    }

    struct file_lock_request* req;
    struct file_lock_request* req_tmp;
    LISTP_FOR_EACH_ENTRY_SAFE(req, req_tmp, &dent_file_locks->file_lock_requests, list) {
        if (req->file_lock.family == FILE_LOCK_POSIX && req->file_lock.pid == pid) {
            assert(!req->notify.event);
            LISTP_DEL(req, &dent_file_locks->file_lock_requests, list);
            free(req);
        }
    }

    if (changed) {
        file_lock_process_requests(dent_file_locks);
        dent_file_locks_gc(dent_file_locks);
    }

    return 0;
}

int file_lock_clear_pid(IDTYPE pid) {
    if (g_process_ipc_ids.leader_vmid) {
        return ipc_file_lock_clear_pid(pid);
    }

    log_debug("clearing file (POSIX) locks for pid %d", pid);

    int ret;

    struct dent_file_locks* dent_file_locks;
    struct dent_file_locks* dent_file_locks_tmp;

    lock(&g_fs_lock_lock);
    LISTP_FOR_EACH_ENTRY_SAFE(dent_file_locks, dent_file_locks_tmp, &g_dent_file_locks_list, list) {
        /* Note that the below call might end up deleting `dent_file_locks` */
        ret = file_lock_clear_pid_from_dentry(dent_file_locks->dent, pid);
        if (ret < 0)
            goto out;
    }

    ret = 0;
out:
    unlock(&g_fs_lock_lock);
    return ret;
}
