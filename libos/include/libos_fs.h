/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Definitions of types and functions for file system bookkeeping.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "libos_defs.h"
#include "libos_handle.h"
#include "libos_refcount.h"
#include "libos_types.h"
#include "libos_utils.h"
#include "linux_abi/fs.h"
#include "linux_abi/limits.h"
#include "list.h"
#include "pal.h"

enum file_check_policy {
    FILE_CHECK_POLICY_STRICT = 0,
    FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG,
};
extern enum file_check_policy g_file_check_policy;

struct trusted_file_hash {
    uint8_t bytes[32];
};
struct trusted_chunk_hash {
    uint8_t bytes[16];
};
struct trusted_file;
struct allowed_file;

struct trusted_file* get_trusted_file(const char* path);
struct allowed_file* get_allowed_file(const char* path);
size_t get_chunk_hashes_size(size_t file_size);
int load_trusted_file(struct trusted_file* tf, size_t file_size,
                      struct trusted_chunk_hash** out_chunk_hashes);
int read_and_verify_trusted_file(PAL_HANDLE handle, uint64_t offset, size_t count, uint8_t* buf,
                                 size_t file_size, struct trusted_chunk_hash* chunk_hashes);
int register_allowed_file(const char* path);
int init_trusted_files(void);
int init_allowed_files(void);
int init_file_check_policy(void);

struct libos_handle;

/* Describes mount parameters. Passed to `mount_fs`, and to the `mount` callback. */
struct libos_mount_params {
    /* Filesystem type (corresponds to `name` field of `libos_fs` */
    const char* type;

    /* Path to the mountpoint */
    const char* path;

    /* PAL URI, or NULL if not applicable */
    const char* uri;

    /* Key name (used by `chroot_encrypted` filesystem), or NULL if not applicable */
    const char* key_name;

    /* Whether to enable file recovery (used by `chroot_encrypted` filesystem), false if not
     * applicable */
    bool enable_recovery;
};

struct libos_fs_ops {
    /* mount: mount an uri to the certain location */
    int (*mount)(struct libos_mount_params* params, void** mount_data);
    int (*unmount)(void* mount_data);

    /* close: clean up the file state inside the handle */
    int (*close)(struct libos_handle* hdl);

    /*
     * \brief Read from file.
     *
     * \param         hdl    File handle.
     * \param         buf    Buffer to read into.
     * \param         count  Size of `buffer`.
     * \param[in,out] pos    Position at which to start reading. Might be updated on success.
     *
     * \returns Number of bytes read on success, negative error code on failure.
     *
     * This callback updates `*pos` if the file is seekable (e.g. not a pipe or socket).
     *
     * TODO: Callers should make sure that `count` doesn't overflow `ssize_t`, and `*pos + count`
     * doesn't overflow `file_off_t`.
     */
    ssize_t (*read)(struct libos_handle* hdl, void* buf, size_t count, file_off_t* pos);

    /*
     * \brief Write to file.
     *
     * \param         hdl    File handle.
     * \param         buf    Buffer to write from.
     * \param         count  Size of `buffer`.
     * \param[in,out] pos    Position at which to start writing. Might be updated on success.
     *
     * \returns Number of bytes written on success, negative error code on failure.
     *
     * This callback updates `*pos` if the file is seekable (e.g. not a pipe or socket).
     *
     * TODO: Callers should make sure that `count` doesn't overflow `ssize_t`, and `*pos + count`
     * doesn't overflow `file_off_t`.
     */
    ssize_t (*write)(struct libos_handle* hdl, const void* buf, size_t count, file_off_t* pos);

    /*!
     * \brief Read a continuous data chunk into multiple buffers.
     *
     * \param         handle   Handle.
     * \param         iov      Array of buffers to read to.
     * \param         iov_len  Length of \p iov.
     * \param[in,out] pos      Position at which to start reading. Might be updated on success.
     *
     * \returns Number of bytes read on success, negative error code on failure.
     */
    ssize_t (*readv)(struct libos_handle* handle, struct iovec* iov, size_t iov_len,
                     file_off_t* pos);

    /*!
     * \brief Write a continuous data chunk from multiple buffers.
     *
     * \param         handle   Handle.
     * \param         iov      Array of buffers to write from.
     * \param         iov_len  Length of \p iov.
     * \param[in,out] pos      Position at which to start writing. Might be updated on success.
     *
     * \returns Number of bytes written on success, negative error code on failure.
     */
    ssize_t (*writev)(struct libos_handle* handle, struct iovec* iov, size_t iov_len,
                      file_off_t* pos);

    /*
     * \brief Map file at an address.
     *
     * \param hdl                  File handle.
     * \param addr                 Address of the memory region. Cannot be NULL.
     * \param size                 Size of the memory region.
     * \param prot                 Permissions for the memory region (`PROT_*`).
     * \param flags                `mmap` flags (`MAP_*`).
     * \param offset               Offset in file.
     * \param[out] out_valid_size  Valid size (i.e. backed by file).
     *
     * Maps the file at given address. This might involve mapping directly (`PalDeviceMap`), or
     * mapping anonymous memory (`PalVirtualMemoryAlloc`) and writing data.
     *
     * The contents of the mapping are initialized using `size` bytes starting at `offset` offset in
     * the file. For a file size that is not a multiple of the page size, the remaining bytes on the
     * last page are zeroed. Pages that are not backed by file contents are inaccessible
     * (effectively they have PROT_NONE permissions). This function returns the valid size (i.e. the
     * pages backed by file contents) in `out_valid_size`.
     *
     * `addr`, `offset` and `size` must be alloc-aligned (see `IS_ALLOC_ALIGNED*` macros in
     * `libos_internal.h`).
     */
    int (*mmap)(struct libos_handle* hdl, void* addr, size_t size, int prot, int flags,
                uint64_t offset, size_t* out_valid_size);

    /*
     * \brief Write back mapped memory to file.
     *
     * \param hdl     File handle.
     * \param addr    Address of the memory region. Cannot be NULL.
     * \param size    Size of the memory region.
     * \param prot    Permissions for the memory region (`PROT_*`).
     * \param flags   `mmap` flags (`MAP_*`).
     * \param offset  Offset in file.
     *
     * Writes back any changes made by the user.
     *
     * The parameters should describe either a region originally mapped with `mmap` callback, or a
     * part of that region. This function should only be called for a shared mapping, i.e. `flags`
     * must contain `MAP_SHARED`.
     */
    int (*msync)(struct libos_handle* hdl, void* addr, size_t size, int prot, int flags,
                 uint64_t offset);

    /* flush: flush out user buffer */
    int (*flush)(struct libos_handle* hdl);

    /* seek: the content from the file opened as handle */
    file_off_t (*seek)(struct libos_handle* hdl, file_off_t offset, int whence);

    /* Returns 0 on success, -errno on error */
    int (*truncate)(struct libos_handle* hdl, file_off_t len);

    /* hstat: get status of the file; `st_ino` will be taken from dentry, if there's one */
    int (*hstat)(struct libos_handle* hdl, struct stat* buf);

    /*!
     * \brief Set flags on the handle.
     *
     * \param handle  The handle to set flags on.
     * \param flags   Flags to set.
     * \param mask    Indicates which flags to change. Only bits set in \p mask will be changed
     *                (to values taken from \p flags). Must be non zero.
     */
    int (*setflags)(struct libos_handle* handle, unsigned int flags, unsigned int mask);

    int (*ioctl)(struct libos_handle* handle, unsigned int cmd, unsigned long arg);

    /* lock and unlock the file */
    int (*lock)(const char* trim_name);
    int (*unlock)(const char* trim_name);

    /* lock and unlock the file system */
    int (*lockfs)(void);
    int (*unlockfs)(void);

    /* checkout/reowned/checkin a single handle for migration */
    int (*checkout)(struct libos_handle* hdl);
    int (*checkin)(struct libos_handle* hdl);

    /* Poll a single handle. Must not block. */
    int (*poll)(struct libos_handle* hdl, int in_events, int* out_events);

    /* Verify a single handle after poll. Must update `pal_ret_events` in-place with only allowed
     * ones. Used in e.g. secure eventfd FS to verify if the host is not lying to us. */
    void (*post_poll)(struct libos_handle* hdl, pal_wait_flags_t* pal_ret_events);

    /* checkpoint/migrate the file system */
    ssize_t (*checkpoint)(void** checkpoint, void* mount_data);
    int (*migrate)(void* checkpoint, void** mount_data);

    /*
     * \brief Change file permissions.
     *
     * \param hdl   File handle.
     * \param perm  New permissions for the file.
     *
     * Changes the permissions of a file associated with a given file handle.
     *
     * On success, the caller should update `hdl->inode->perm`.
     */
    int (*fchmod)(struct libos_handle* hdl, mode_t perm);
};

/* Limit for the number of dentry children. This is mostly to prevent overflow if (untrusted) host
 * pretends to have many files in a directory. */
#define DENTRY_MAX_CHILDREN 1000000

/*
 * Describes a single path within a mounted filesystem. If `inode` is set, it is the file at given
 * path.
 *
 * A dentry is called *positive* if `inode` is set, *negative* otherwise.
 */
DEFINE_LIST(libos_dentry);
DEFINE_LISTP(libos_dentry);
struct libos_dentry {
    /* Inode associated with this dentry, or NULL. Protected by `g_dcache_lock`. */
    struct libos_inode* inode;

    /* File name, maximum of NAME_MAX characters. By convention, the root has an empty name. Does
     * not change. Length is kept for performance reasons. */
    char* name;
    size_t name_len;

    /* Mounted filesystem this dentry belongs to. Does not change. */
    struct libos_mount* mount;

    /* Parent of this dentry, but only within the same mount. If you need the dentry one level up,
     * regardless of mounts (i.e. `..`), you should use `dentry_up()` instead. Does not change. */
    struct libos_dentry* parent;

    /* The following fields are protected by `g_dcache_lock`. */
    size_t nchildren;
    LISTP_TYPE(libos_dentry) children; /* These children and siblings link */
    LIST_TYPE(libos_dentry) siblings;

    /* Filesystem mounted under this dentry. If set, this dentry is a mountpoint: filesystem
     * operations should use `attached_mount->root` instead of this dentry. Protected by
     * `g_dcache_lock`. */
    struct libos_mount* attached_mount;

    /* File locks information, stored only in the main process. Managed by `libos_fs_lock.c`. */
    struct dent_file_locks* file_locks;

    /* True if the file might have locks placed by current process. Used in processes other than
     * main process, to prevent unnecessary IPC calls on handle close. Managed by
     * `libos_fs_lock.c`. */
    bool maybe_has_file_locks;

    refcount_t ref_count;
};

/*
 * Describes a single file in Gramine filesystem.
 *
 * The fields in this structure are protected by `lock`, with the exception of fields that do not
 * change (`type`, `mount`, `fs`).
 */
struct libos_inode {
    /* File type: S_IFREG, S_IFDIR, S_IFLNK etc. Does not change. */
    mode_t type;

    /* File permissions: PERM_rwxrwxrwx, etc. */
    mode_t perm;

    /* File size */
    file_off_t size;

    /* credentials */
    IDTYPE uid, gid;

    /* Create/modify/access time */
    time_t ctime;
    time_t mtime;
    time_t atime;

    /* Mounted filesystem this inode belongs to. Does not change. */
    struct libos_mount* mount;

    /* Filesystem to use for operations on this file: this is usually `mount->fs`, but can be
     * different in case of special files (such as named pipes or sockets). */
    struct libos_fs* fs;

    /* Filesystem-specific data */
    void* data;

    /* Number of VMAs the file is mmapped to; should be accessed using atomic operations. */
    uint64_t num_mmapped;

    struct libos_lock lock;
    refcount_t ref_count;
};

typedef int (*readdir_callback_t)(const char* name, void* arg);

/* TODO: Some of these operations could be simplified if they take an `inode` parameter. */
struct libos_d_ops {
    /*
     * \brief Look up a file.
     *
     * \param dent  Dentry, negative.
     *
     * Queries the underlying filesystem for a path described by a dentry (`dent->name` and
     * `dent->parent`). On success, creates an inode and attaches it to the dentry.
     *
     * The caller should hold `g_dcache_lock`.
     */
    int (*lookup)(struct libos_dentry* dent);

    /*
     * \brief Open an existing file.
     *
     * \param hdl    A newly created handle.
     * \param dent   Dentry, positive.
     * \param flags  Open flags, including access mode (O_RDONLY / O_WRONLY / O_RDWR).
     *
     * Opens a file, and if successful, prepares the handle for use by the filesystem. Always sets
     * the `type` field.
     *
     * The caller should hold `g_dcache_lock`. On success, the caller should initialize the
     * following handle fields: `fs`, `dentry`, `flags`, `acc_mode`.
     */
    int (*open)(struct libos_handle* hdl, struct libos_dentry* dent, int flags);

    /*
     * \brief Create and open a new regular file.
     *
     * \param hdl    A newly created handle.
     * \param dent   Dentry, negative (file to be created).
     * \param flags  Open flags, including access mode (O_RDONLY / O_WRONLY / O_RDWR).
     * \param perm   Permissions of the new file.
     *
     * Creates and opens a new regular file at path described by `dent`. On success, creates an
     * inode and attaches it to the dentry (as in `lookup`) and prepares the handle for use by the
     * filesystem (as in `open`).
     *
     * The caller should hold `g_dcache_lock`. On success, the caller should finish preparing the
     * handle (as in `open`).
     */
    int (*creat)(struct libos_handle* hdl, struct libos_dentry* dent, int flags, mode_t perm);

    /*
     * \brief Create a directory.
     *
     * \param dent  Dentry, negative (directory to be created).
     * \param perm  Permissions of the new directory.
     *
     * Creates a new directory at path described by `dent`. On success, creates an inode and
     * attaches it to the dentry (as in `lookup`).
     *
     * The caller should hold `g_dcache_lock`.
     */
    int (*mkdir)(struct libos_dentry* dent, mode_t perm);

    /*
     * \brief Unlink a file.
     *
     * \param dent  Dentry, positive, must have a parent.
     *
     * Unlinks a file described by `dent`. Note that there might be handles for that file; if
     * possible, they should still work.
     *
     * The caller should hold `g_dcache_lock`. On success, the caller should detach the inode from
     * the dentry.
     */
    int (*unlink)(struct libos_dentry* dent);

    /*
     * \brief Get file status.
     *
     * \param dent  Dentry, positive.
     * \param buf   Status buffer to fill.
     *
     * Fills `buf` with information about a file. Omits `st_ino` (which is later filled by the
     * caller).
     *
     * The caller should hold `g_dcache_lock`.
     */
    int (*stat)(struct libos_dentry* dent, struct stat* buf);

    /*
     * \brief Extract the target of a symbolic link.
     *
     * \param dent        Dentry, positive, describing a symlink.
     * \param out_target  On success, contains link target.
     *
     * Determines the target of a symbolic link, and sets `*out_target` to an allocated string.
     *
     * The caller should hold `g_dcache_lock`. On success, the caller should free `*out_target`.
     */
    int (*follow_link)(struct libos_dentry* dent, char** out_target);

    /*
     * \brief Change file permissions.
     *
     * \param dent  Dentry, positive.
     * \param perm  New permissions for the file.
     *
     * Changes the permissions for a file.
     *
     * The caller should hold `g_dcache_lock`. On success, the caller should update
     * `dent->inode->perm`.
     */
    int (*chmod)(struct libos_dentry* dent, mode_t perm);

    /*
     * \brief Rename a file.
     *
     * \param old  Source dentry, positive.
     * \param new  Target dentry, can be negative or positive.
     *
     * Moves a file described by `old` to the path described by `new`. Updates the fields of `new`
     * (same as `lookup`).
     *
     * Note that the file described by `new` might exist, in which case the rename operation will
     * unlink it.
     *
     * The caller should hold `g_dcache_lock`. On success, the caller should mark the old dentry as
     * negative, and the new dentry as non-negative.
     */
    int (*rename)(struct libos_dentry* old, struct libos_dentry* new);

    /*!
     * \brief List all files in the directory.
     *
     * \param dent      The dentry, must be positive and describing a directory.
     * \param callback  The callback to invoke on each file name.
     * \param arg       Argument to pass to the callback.
     *
     * Calls `callback(name, arg)` for all file names in the directory. `name` is not guaranteed to
     * be valid after callback returns, so the callback should copy it if necessary.
     *
     * `arg` can be used to pass additional data to the callback, e.g. a list to add a name to.
     *
     * If the callback returns a negative error code, it's interpreted as a failure and `readdir`
     * stops, returning the same error code.
     *
     * The caller should hold `g_dcache_lock`.
     */
    int (*readdir)(struct libos_dentry* dent, readdir_callback_t callback, void* arg);

    /*!
     * \brief Deallocate inode data.
     *
     * \param inode  The inode about to be freed.
     *
     * Deallocates any custom data stored in the inode by filesystem. Called before deleting the
     * inode.
     *
     * The caller should hold `inode->lock`.
     */
    void (*idrop)(struct libos_inode* inode);

    /*!
     * \brief Checkpoint inode data.
     *
     * \param inode     The inode to be checkpointed.
     * \param out_data  On success, contains a newly allocated buffer with data.
     * \param out_size  On success, contains data size.
     *
     * Prepares any custom data necessary to migrate the inode. Called when checkpointing the inode.
     *
     * The caller should hold `inode->lock`. On success, the caller should free `*out_data`.
     */
    int (*icheckpoint)(struct libos_inode* inode, void** out_data, size_t* out_size);

    /*!
     * \brief Restore inode data from checkpoint.
     *
     * \param inode  Newly restored inode.
     * \param data   Checkpoint data (prepared by the `icheckpoint` callback).
     *
     * Restores custom state of the inode. Called when restoring the inode from checkpoint, after
     * all other fields are set.
     */
    int (*irestore)(struct libos_inode* inode, void* data);
};

struct libos_fs {
    /* Null-terminated, used in manifest and for uniquely identifying a filesystem. */
    char name[16];
    struct libos_fs_ops* fs_ops;
    struct libos_d_ops* d_ops;
};

DEFINE_LIST(libos_mount);
struct libos_mount {
    struct libos_fs* fs;

    struct libos_dentry* mount_point;

    char* path;
    char* uri;

    struct libos_dentry* root;

    void* data;

    bool enable_recovery;

    void* cpdata;
    size_t cpsize;

    refcount_t ref_count;
    LIST_TYPE(libos_mount) hlist;
    LIST_TYPE(libos_mount) list;
};

extern struct libos_dentry* g_dentry_root;

#define F_OK   0
#define X_OK 001
#define W_OK 002
#define R_OK 004
#define MAY_EXEC  001
#define MAY_WRITE 002
#define MAY_READ  004
#if 0
#define MAY_APPEND 010
#endif

#define ACC_MODE(x)                                        \
    ((((x) == O_RDONLY || (x) == O_RDWR) ? MAY_READ : 0) | \
     (((x) == O_WRONLY || (x) == O_RDWR) ? MAY_WRITE : 0))

/* initialization for fs and mounts */
int init_fs(void);
int init_trusted_allowed_files(void);
int init_mount_root(void);
int init_mount(void);
int mount_etcfs(void);

/* file system operations */

/*!
 * \brief Mount a new filesystem.
 *
 * Creates a new `libos_mount` structure (mounted filesystem) and attaches to the dentry under
 * `params->path`. That means (assuming the dentry is called `mount_point`):
 *
 * - `mount_point->attached_mount` is the new filesystem,
 * - `mount_point->attached_mount->root` is the dentry of new filesystem's root.
 *
 * Subsequent lookups for `params->path` and paths starting with `params->path` will retrieve the
 * new filesystem's root, not the mountpoint.
 *
 * As a result, multiple mount operations for the same path will create a chain (mount1 -> root1 ->
 * mount2 -> root2 ...), effectively stacking the mounts and ensuring only the last one is visible.
 *
 * The function will ensure that the mountpoint exists: if necessary, new directories will be
 * created using the `synthetic` filesystem. This is a departure from Unix mount, necessary to
 * implement Gramine manifest semantics.
 *
 * TODO: On failure, this function does not clean the synthetic nodes it just created.
 */
int mount_fs(struct libos_mount_params* params);

void get_mount(struct libos_mount* mount);
void put_mount(struct libos_mount* mount);

struct libos_mount* find_mount_from_uri(const char* uri);

int walk_mounts(int (*walk)(struct libos_mount* mount, void* arg), void* arg);

/* functions for dcache supports */
int init_dcache(void);

extern struct libos_lock g_dcache_lock;

/*!
 * \brief Dump dentry cache.
 *
 * \param dent  The starting dentry, or NULL (will default to dentry root).
 *
 * Dumps the dentry cache using `log_always`, starting from the provided dentry. Intended for
 * debugging the filesystem - just add it manually to the code.
 */
void dump_dcache(struct libos_dentry* dent);

/*!
 * \brief Check file permissions, similar to Unix access.
 *
 * \param dentry  The dentry to check.
 * \param mask    Mask, same as for Unix access.
 *
 * Checks permissions for a dentry. Because Gramine currently has no notion of users, this will
 * always use the "user" part of file mode.
 *
 * The caller should hold `g_dcache_lock`.
 *
 * `dentry` can be negative (in which case the function will return -ENOENT).
 */
int check_permissions(struct libos_dentry* dent, mode_t mask);

/*
 * Flags for `path_lookupat`.
 *
 * Note that, opposite to user-level O_NOFOLLOW, we define LOOKUP_FOLLOW as a positive flag, and add
 * LOOKUP_NO_FOLLOW as a pseudo-flag for readability.
 *
 * This is modeled after Linux and BSD codebases, which define a positive FOLLOW flag, and a
 * negative pseudo-flag was introduced by FreeBSD.
 */
#define LOOKUP_NO_FOLLOW       0
#define LOOKUP_FOLLOW          0x1
#define LOOKUP_CREATE          0x2
#define LOOKUP_DIRECTORY       0x4
#define LOOKUP_MAKE_SYNTHETIC  0x8

/* Maximum number of nested symlinks that `path_lookupat` and related functions will follow */
#define MAX_LINK_DEPTH 8

/*!
 * \brief Look up a path, retrieving a dentry.
 *
 * \param      start  The start dentry for relative paths, or NULL (in which case it will default
 *                    to process' cwd).
 * \param      path   The path to look up.
 * \param      flags  Lookup flags (see description below).
 * \param[out] found  Pointer to retrieved dentry.
 *
 * The caller should hold `g_dcache_lock`.
 *
 * On success, returns 0, and puts the retrieved dentry in `*found`. The reference count of the
 * dentry will be increased by one.
 *
 * If LOOKUP_CREATE is set, the retrieved dentry can be negative. Otherwise, it is guaranteed to be
 * positive.
 *
 * On failure, returns a negative error code, and sets `*found` to NULL.
 *
 * Supports the following flags:
 *
 * - LOOKUP_FOLLOW: if `path` refers to a symbolic link, follow it (the default is to return the
 *   dentry to the link). Note that symbolic links for intermediate path segments are always
 *   followed.
 *
 * - LOOKUP_NO_FOLLOW: this is a pseudo-flag defined as 0. You can use it to indicate to the reader
 *   that symbolic links are intentionally not being followed.
 *
 * - LOOKUP_CREATE: if the file under `path` does not exist, but can be created (i.e. the parent
 *   directory exists), the function will succeed and a negative dentry will be put in `*found`. If
 *   the parent directory also does not exist, the function will still fail with -ENOENT.
 *
 * - LOOKUP_DIRECTORY: expect the file under `path` to be a directory, and fail with -ENOTDIR
 *   otherwise
 *
 * - LOOKUP_MAKE_SYNTHETIC: for any components on the path that do not exist, create directories
 *   using the `synthetic` filesystem. This is intended for use when creating mountpoints specified
 *   in manifest.
 *
 * Note that a path with trailing slash is always treated as a directory, and LOOKUP_FOLLOW /
 * LOOKUP_CREATE do not apply.
 *
 * TODO: This function doesn't check any permissions. It should return -EACCES on inaccessible
 * directories.
 */
int path_lookupat(struct libos_dentry* start, const char* path, int flags,
                  struct libos_dentry** found);

/*!
 * This function returns a dentry (in *dir) from a handle corresponding to dirfd.
 * If dirfd == AT_FDCWD returns current working directory.
 *
 * Returned dentry must be a directory.
 *
 * Increments dentry ref count by one.
 */
int get_dirfd_dentry(int dirfd, struct libos_dentry** dir);

/*!
 * \brief Open a file under a given path, similar to Unix open.
 *
 * \param      hdl    Handle to associate with dentry, can be NULL.
 * \param      start  The start dentry for relative paths, or NULL (in which case it will default
 *                    to process' cwd).
 * \param      path   The path to look up.
 * \param      flags  Unix open flags (see below).
 * \param      mode   Unix file mode, used when creating a new file/directory.
 * \param[out] found  Pointer to retrieved dentry, can be NULL.
 *
 * If `hdl` is provided, on success it will be associated with the dentry. Otherwise, the file will
 * just be retrieved or created.
 *
 * If `found` is provided, on success it will be set to the file's dentry (and its reference count
 * will be increased), and on failure it will be set to NULL.
 *
 * Similar to Unix open, `flags` must include one of O_RDONLY, O_WRONLY or O_RDWR. In addition,
 * the following flags are supported by this function:
 * - O_CREAT: create a new file if one does not exist
 * - O_EXCL: fail if the file already exists
 * - O_DIRECTORY: expect/create a directory instead of regular file
 * - O_NOFOLLOW: don't follow symbolic links when resolving a path
 * - O_TRUNC: truncate the file after opening
 * - O_APPEND: open file in append mode for writing
 *
 * The flags (including any not listed above), as well as file mode, are passed to the underlying
 * filesystem.
 *
 * Note that unlike Linux `open`, this function called with O_CREAT and O_DIRECTORY will attempt to
 * create a directory (Linux `open` ignores the O_DIRECTORY flag and creates a regular file).
 * However, that behaviour of Linux `open` is a bug, and emulating it is inconvenient for us
 * (because we use this function for both `open` and `mkdir`).
 *
 * TODO: This function checks permissions of the opened file (if it exists) and parent directory (if
 * the file is being created), but not permissions for the whole path. That check probably should be
 * added to `path_lookupat`.
 *
 * TODO: The set of allowed flags should be checked in syscalls that use this function.
 */
int open_namei(struct libos_handle* hdl, struct libos_dentry* start, const char* path, int flags,
               int mode, struct libos_dentry** found);

/*!
 * \brief Open an already retrieved dentry, and associates a handle with it.
 *
 * \param hdl    Handle to associate with dentry.
 * \param dent   The dentry to open.
 * \param flags  Unix open flags.
 *
 * The dentry has to be positive. The caller has to hold `g_dcache_lock`.
 *
 * The `flags` parameter will be passed to the underlying filesystem's `open` function. If O_TRUNC
 * flag is specified, the filesystem's `truncate` function will also be called.
 */
int dentry_open(struct libos_handle* hdl, struct libos_dentry* dent, int flags);

/*!
 * \brief Populate a directory handle with current dentries.
 *
 * \param hdl  A directory handle.
 *
 * This function populates the `hdl->dir_info` structure with current dentries in a directory, so
 * that the directory can be listed using `getdents/getdents64` syscalls.
 *
 * The caller should hold `g_dcache_lock` and `hdl->lock`.
 *
 * If the handle is currently populated (i.e. `hdl->dir_info.dents` is not null), this function is a
 * no-op. If you want to refresh the handle with new contents, call `clear_directory_handle` first.
 */
int populate_directory_handle(struct libos_handle* hdl);

/*!
 * \brief Clear dentries from a directory handle.
 *
 * \param hdl  A directory handle.
 *
 * This function discards an array of dentries previously prepared by `populate_directory_handle`.
 *
 * If the handle is currently not populated (i.e. `hdl->dir_info.dents` is null), this function is a
 * no-op.
 */
void clear_directory_handle(struct libos_handle* hdl);

/* Increment the reference count on dent */
void get_dentry(struct libos_dentry* dent);
/* Decrement the reference count on dent */
void put_dentry(struct libos_dentry* dent);

/*!
 * \brief Get the dentry one level up.
 *
 * \param dent  The dentry.
 *
 * \returns The dentry one level up, or NULL if one does not exist.
 *
 * Computes the dentry pointed to by ".." from the current one, unless the current dentry is at
 * global root. Unlike the `parent` field, this traverses mounted filesystems (i.e. works also for a
 * root dentry of a mount).
 */
struct libos_dentry* dentry_up(struct libos_dentry* dent);

/*!
 * \brief Garbage-collect a dentry, if possible.
 *
 * \param dentry  The dentry (has to have a parent).
 *
 * This function checks if a dentry is unused, and deletes it if that's true. The caller must hold
 * `g_dcache_lock`.
 *
 * A dentry is unused if it has no external references and is negative. Such dentries can remain
 * after failed lookups or file deletion.
 *
 * The function should be called when processing a list of children, after you're done with a given
 * dentry. It guarantees that the amortized cost of processing such dentries is constant, i.e. they
 * will be only encountered once.
 *
 * \code
 * struct libos_dentry* child;
 * struct libos_dentry* tmp;
 *
 * LISTP_FOR_EACH_ENTRY_SAFE(child, tmp, &dent->children, siblings) {
 *     // do something with `child`, increase ref count if used
 *     ...
 *     dentry_gc(child);
 * }
 * \endcode
 */
void dentry_gc(struct libos_dentry* dent);

/*!
 * \brief Compute an absolute path for dentry, allocating memory for it.
 *
 * \param      dent  The dentry.
 * \param[out] path  Will be set to computed path.
 * \param[out] size  If not NULL, will be set to path size, including null terminator.
 *
 * \returns 0 on success, negative error code otherwise.
 *
 * This function computes an absolute path for dentry, allocating a new buffer for it. The path
 * should later be freed using `free`.
 *
 * An absolute path is a combination of all names up to the global root (not including the root,
 * which by convention has an empty name), separated by `/`, and beginning with `/`.
 *
 * TODO: It would be more natural to use a `len` parameter instead (for length without null
 * terminator).
 */
int dentry_abs_path(struct libos_dentry* dent, char** path, size_t* size);

/*!
 * \brief Compute a relative path for dentry, allocating memory for it.
 *
 * \param      dent  The dentry.
 * \param[out] path  Will be set to computed path.
 * \param[out] size  If not NULL, will be set to path size, including null terminator.
 *
 * \returns 0 on success, negative error code otherwise.
 *
 * This function computes a relative path for dentry, allocating a new buffer for it. The path
 * should later be freed using `free`.
 *
 * A relative path is a combination of all names up to the root of the dentry's filesystem (not
 * including the root), separated by `/`. A relative path never begins with `/`.
 *
 * TODO: It would be more natural to use a `len` parameter instead (for length without null
 * terminator).
 */
int dentry_rel_path(struct libos_dentry* dent, char** path, size_t* size);

/*
 * Calculate the URI for a dentry. The URI scheme is determined by file type (`type` field). It
 * needs to be passed separately (instead of using `dent->inode->type`) because the dentry might not
 * have inode associated yet: we might be creating a new file, or looking up a file we don't know
 * yet.
 */
int dentry_uri(struct libos_dentry* dent, mode_t type, char** out_uri);

ino_t dentry_ino(struct libos_dentry* dent);

/*!
 * \brief Allocate and initializes a new dentry.
 *
 * \param mount     The mount the dentry is under.
 * \param parent    The parent node, or NULL if this is supposed to be the mount root.
 * \param name      Name of the new dentry.
 * \param name_len  Length of the name.
 *
 * \returns The new dentry, or NULL in case of allocation failure.
 *
 * The caller should hold `g_dcache_lock`.
 *
 * The function will initialize the following fields: `mount` and `fs` (if `mount` provided),
 * `name`, and parent/children links.
 *
 * The reference count of the returned dentry will be 2 if `parent` was provided, 1 otherwise.
 *
 * The `mount` parameter should typically be `parent->mount`, but is passed explicitly to support
 * initializing the root dentry of a newly mounted filesystem. The `fs` field will be initialized to
 * `mount->fs`, but you can later change it to support special files.
 */
struct libos_dentry* get_new_dentry(struct libos_mount* mount, struct libos_dentry* parent,
                                    const char* name, size_t name_len);

/*!
 * \brief Search for a child of a dentry with a given name.
 *
 * \param parent    The dentry to search under.
 * \param name      Name of searched dentry.
 * \param name_len  Length of the name.
 *
 * \returns The dentry, or NULL if not found.
 *
 * The caller should hold `g_dcache_lock`.
 *
 * If found, the reference count on the returned dentry is incremented.
 */
struct libos_dentry* lookup_dcache(struct libos_dentry* parent, const char* name, size_t name_len);

/*
 * Returns true if `anc` is an ancestor of `dent`. Both dentries need to be within the same mounted
 * filesystem.
 */
bool dentry_is_ancestor(struct libos_dentry* anc, struct libos_dentry* dent);

/* XXX: Future work: current dcache never shrinks. Would be nice to be able to do something like LRU
 * under space pressure, although for a single app, this may be over-kill. */

/*!
 * \brief Allocate and initialize a new inode.
 *
 * \param mount  The mount the inode is under.
 * \param type   Inode type (S_IFREG, S_IFDIR, etc.).
 * \param perm   Inode permissions (PERM_rwxrwxrwx, etc.).
 */
struct libos_inode* get_new_inode(struct libos_mount* mount, mode_t type, mode_t perm);

void get_inode(struct libos_inode* inode);
void put_inode(struct libos_inode* inode);

/*
 * Hashing utilities for paths.
 *
 * TODO: The following functions are used for inode numbers and in a few other places where we need
 * a (mostly) unique number for a given path. Unfortunately, they do not guarantee full
 * uniqueness. We might need a better solution for the filesystem to be fully consistent.
 */

HASHTYPE hash_str(const char* str);
HASHTYPE hash_name(HASHTYPE parent_hbuf, const char* name);
HASHTYPE hash_abs_path(struct libos_dentry* dent);

#define READDIR_BUF_SIZE 4096

extern struct libos_fs_ops chroot_fs_ops;
extern struct libos_d_ops chroot_d_ops;

extern struct libos_fs_ops str_fs_ops;
extern struct libos_d_ops str_d_ops;

extern struct libos_fs_ops tmp_fs_ops;
extern struct libos_d_ops tmp_d_ops;

/* XXX: why these are called "builtin"? */
extern struct libos_fs chroot_builtin_fs;
extern struct libos_fs chroot_encrypted_builtin_fs;
extern struct libos_fs tmp_builtin_fs;
extern struct libos_fs pipe_builtin_fs;
extern struct libos_fs fifo_builtin_fs;
extern struct libos_fs socket_builtin_fs;
extern struct libos_fs epoll_builtin_fs;
extern struct libos_fs eventfd_builtin_fs;
extern struct libos_fs synthetic_builtin_fs;
extern struct libos_fs path_builtin_fs;
extern struct libos_fs shm_builtin_fs;

struct libos_fs* find_fs(const char* name);

/*!
 * \brief Compute file position for `seek`.
 *
 * \param      pos      Current file position (non-negative).
 * \param      size     File size (non-negative).
 * \param      offset   Desired offset.
 * \param      origin   `seek` origin parameter (SEEK_SET, SEEK_CUR, SEEK_END).
 * \param[out] out_pos  On success, contains new file position.
 *
 * Computes new file position according to `seek` semantics. The new position will be non-negative,
 * although it can be larger than file size.
 */
int generic_seek(file_off_t pos, file_off_t size, file_off_t offset, int origin,
                 file_off_t* out_pos);

int generic_readdir(struct libos_dentry* dent, readdir_callback_t callback, void* arg);

int generic_inode_stat(struct libos_dentry* dent, struct stat* buf);
int generic_inode_hstat(struct libos_handle* hdl, struct stat* buf);
file_off_t generic_inode_seek(struct libos_handle* hdl, file_off_t offset, int origin);
int generic_inode_poll(struct libos_handle* hdl, int in_events, int* out_events);

int generic_emulated_mmap(struct libos_handle* hdl, void* addr, size_t size, int prot, int flags,
                          uint64_t offset, size_t* valid_size);
int generic_emulated_msync(struct libos_handle* hdl, void* addr, size_t size, int prot, int flags,
                           uint64_t offset);
int generic_truncate(struct libos_handle* hdl, file_off_t size);

int synthetic_setup_dentry(struct libos_dentry* dent, mode_t type, mode_t perm);

int fifo_setup_dentry(struct libos_dentry* dent, mode_t perm, int fd_read, int fd_write);

int chroot_readdir(struct libos_dentry* dent, readdir_callback_t callback, void* arg);
