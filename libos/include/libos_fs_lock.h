/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * File locks. Both POSIX locks (fcntl syscall) and BSD locks (flock syscall) are implemented via
 * a common struct `libos_file_lock`. See `man fcntl` and `man flock` for details.
 */

#pragma once

#include <stdbool.h>

#include "libos_types.h"
#include "list.h"

#define FS_LOCK_EOF ((uint64_t)-1)

struct libos_dentry;

/* Initialize the file locking subsystem. */
int init_fs_lock(void);

/*
 * File locks. Describes both POSIX locks aka advisory record locks (fcntl syscall) and BSD locks
 * (flock syscall). See `man fcntl` and `man flock` for details.
 *
 * The current implementation works over IPC and handles all requests in the main process. It has
 * the following caveats:
 *
 * - Lock requests from other processes will always have the overhead of IPC round-trip, even if the
 *   lock is uncontested.
 * - The main process has to be able to look up the same file, so locking will not work for files in
 *   local-process-only filesystems (tmpfs).
 * - The lock requests cannot be interrupted (EINTR).
 * - The locks work only on files that have a dentry (no pipes, sockets etc.).
 * - Only for POSIX (fcntl) locks: no deadlock detection (EDEADLK).
 */

enum libos_file_lock_family {
    FILE_LOCK_UNKNOWN, /* this is only to catch uninitialized-variable errors */
    FILE_LOCK_POSIX,
    FILE_LOCK_FLOCK,
};

DEFINE_LISTP(libos_file_lock);
DEFINE_LIST(libos_file_lock);
struct libos_file_lock {
    /* Lock family: FILE_LOCK_POSIX, FILE_LOCK_FLOCK */
    enum libos_file_lock_family family;

    /* Lock type: F_RDLCK, F_WRLCK, F_UNLCK */
    int type;

    /* List node, used internally */
    LIST_TYPE(libos_file_lock) list;

    /* FILE_LOCK_POSIX fields */
    uint64_t start; /* First byte of range */
    uint64_t end;   /* Last byte of range (use FS_LOCK_EOF for a range until end of file) */
    IDTYPE pid;     /* PID of process taking the lock */

    /* FILE_LOCK_FLOCK fields */
    uint64_t handle_id; /* Unique handle ID using which the lock is taken */
};

/*!
 * \brief Set or remove a lock on a file.
 *
 * \param dent       The dentry for a file.
 * \param file_lock  Parameters of new lock.
 * \param wait       If true, will wait until a lock can be taken.
 *
 * This is the equivalent of `fnctl(F_SETLK/F_SETLKW)`.
 *
 * If `file_lock->type` is `F_UNLCK`, the function will remove locks as follows:
 * - For POSIX (fcntl) locks, remove all POSIX locks held by the given PID for the given range.
 * - For BSD (flock) locks, remove all BSD locks held by the given handle ID.
 *
 * Removing a lock never waits.
 *
 * If `file_lock->type` is `F_RDLCK` or `F_WRLCK`, the function will create a new lock as follows:
 * - For POSIX (fcntl) locks, for the given PID and range, replace the existing POSIX locks held by
 *   the given PID for that range.
 * - For BSD (flock) locks, replace the existing BSD locks held by the given handle ID.
 *
 * If there are conflicting locks, the function either waits (if `wait` is true), or fails with
 * `-EAGAIN` (if `wait` is false).
 */
int file_lock_set(struct libos_dentry* dent, struct libos_file_lock* file_lock, bool wait);

/*!
 * \brief Check for conflicting locks on a file.
 *
 * \param      dent           The dentry for a file.
 * \param      file_lock      Parameters of new lock (type cannot be `F_UNLCK`).
 * \param[out] out_file_lock  On success, set to `F_UNLCK` or details of a conflicting lock.
 *
 * This is the equivalent of `fcntl(F_GETLK)`.
 *
 * The function checks if there are conflicting locks:
 * - For POSIX (fcntl) locks, check for other PIDs preventing the proposed lock from being placed.
 * - For BSD (flock) locks, check for other handle IDs preventing the proposed lock from being
 *   placed.
 *
 * If the lock could be placed, `out_file_lock->type` is set to `F_UNLCK`. Otherwise,
 * `out_file_lock` fields (`type`, `start, `end`, `pid`, `handle_id`) are set to details of a
 * conflicting lock.
 */
int file_lock_get(struct libos_dentry* dent, struct libos_file_lock* file_lock,
                  struct libos_file_lock* out_file_lock);

/* Removes all locks for a given PID. Applicable only for POSIX locks. Should be called before
 * process exit. */
int file_lock_clear_pid(IDTYPE pid);

/*!
 * \brief Set or remove a lock on a file (IPC handler).
 *
 * \param path       Absolute path for a file.
 * \param file_lock  Parameters of new lock.
 * \param wait       If true, will postpone the response until a lock can be taken.
 * \param vmid       Target process for IPC response.
 * \param seq        Sequence number for IPC response.
 *
 * This is a version of `file_lock_set` called from an IPC callback. This function is responsible
 * for either sending an IPC response immediately, or scheduling one for later (if `wait` is true
 * and the lock cannot be taken immediately).
 *
 * This function will only return a negative error code when failing to send a response. A failure
 * to add a lock (-EAGAIN, -ENOMEM etc.) will be sent in the response instead.
 */
int file_lock_set_from_ipc(const char* path, struct libos_file_lock* file_lock, bool wait,
                           IDTYPE vmid, unsigned long seq);

/*!
 * \brief Check for conflicting locks on a file (IPC handler).
 *
 * \param      path           Absolute path for a file.
 * \param      file_lock      Parameters of new lock (type cannot be `F_UNLCK`).
 * \param[out] out_file_lock  On success, set to `F_UNLCK` or details of a conflicting lock.
 *
 * This is a version of `file_lock_get` called from an IPC callback. The caller is responsible to
 * send the returned value and `out_file_lock` in an IPC response.
 */
int file_lock_get_from_ipc(const char* path, struct libos_file_lock* file_lock,
                           struct libos_file_lock* out_file_lock);
