/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls "unlink", "unlinkat", "mkdir", "mkdirat", "rmdir", "umask",
 * "chmod", "fchmod", "fchmodat", "rename", "renameat" and "sendfile".
 */

#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_process.h"
#include "libos_table.h"
#include "linux_abi/errors.h"
#include "linux_abi/fs.h"
#include "perm.h"
#include "stat.h"

/*
 * Read/write in 64KB chunks in the sendfile() syscall. This syscall also has an optimization of
 * using a statically allocated buffer instead of allocating on the heap (as our internal malloc()
 * has subpar performance). To prevent data races of multiple threads executing sendfile() at the
 * same time and thus potentially corrupting a single static buffer, we optimize for a common case:
 * only the first thread uses the static buffer whereas other threads fall back to a slower heap
 * allocation.
 */
#define BUF_SIZE (64 * 1024)
static char g_sendfile_buf[BUF_SIZE];
static bool g_sendfile_buf_in_use = false;

/* The kernel would look up the parent directory, and remove the child from the inode. But we are
 * working with the PAL, so we open the file, truncate and close it. */
long libos_syscall_unlink(const char* file) {
    return libos_syscall_unlinkat(AT_FDCWD, file, 0);
}

long libos_syscall_unlinkat(int dfd, const char* pathname, int flag) {
    if (!is_user_string_readable(pathname))
        return -EFAULT;

    if (flag & ~AT_REMOVEDIR)
        return -EINVAL;

    struct libos_dentry* dir = NULL;
    struct libos_dentry* dent = NULL;
    int ret;

    if (*pathname != '/' && (ret = get_dirfd_dentry(dfd, &dir)) < 0)
        return ret;

    lock(&g_dcache_lock);
    ret = path_lookupat(dir, pathname, LOOKUP_NO_FOLLOW, &dent);
    if (ret < 0)
        goto out;

    if (!dent->parent) {
        ret = -EACCES;
        goto out;
    }

    if (flag & AT_REMOVEDIR) {
        if (dent->inode->type != S_IFDIR) {
            ret = -ENOTDIR;
            goto out;
        }
    } else {
        if (dent->inode->type == S_IFDIR) {
            ret = -EISDIR;
            goto out;
        }
    }

    struct libos_fs* fs = dent->inode->fs;
    if (fs->d_ops && fs->d_ops->unlink) {
        ret = fs->d_ops->unlink(dent);
        if (ret < 0) {
            goto out;
        }
    }

    put_inode(dent->inode);
    dent->inode = NULL;
    ret = 0;
out:
    unlock(&g_dcache_lock);
    if (dir)
        put_dentry(dir);
    if (dent)
        put_dentry(dent);
    return ret;
}

long libos_syscall_mkdir(const char* pathname, int mode) {
    return libos_syscall_mkdirat(AT_FDCWD, pathname, mode);
}

long libos_syscall_mkdirat(int dfd, const char* pathname, int mode) {
    if (!is_user_string_readable(pathname))
        return -EFAULT;

    lock(&g_process.fs_lock);
    mode_t umask = g_process.umask;
    unlock(&g_process.fs_lock);

    /* In addition to permission bits, Linux `mkdirat` honors the sticky bit (see man page) */
    mode &= (PERM_rwxrwxrwx | S_ISVTX);

    mode &= ~umask;

    struct libos_dentry* dir = NULL;
    int ret = 0;

    if (*pathname != '/' && (ret = get_dirfd_dentry(dfd, &dir)) < 0)
        return ret;

    ret = open_namei(NULL, dir, pathname, O_CREAT | O_EXCL | O_DIRECTORY, mode, NULL);

    if (dir)
        put_dentry(dir);
    return ret;
}

long libos_syscall_rmdir(const char* pathname) {
    int ret = 0;
    struct libos_dentry* dent = NULL;

    if (!is_user_string_readable(pathname))
        return -EFAULT;

    lock(&g_dcache_lock);
    ret = path_lookupat(/*start=*/NULL, pathname, LOOKUP_NO_FOLLOW | LOOKUP_DIRECTORY, &dent);
    if (ret < 0) {
        goto out;
    }

    if (!dent->parent) {
        ret = -EACCES;
        goto out;
    }

    if (dent->inode->type != S_IFDIR) {
        ret = -ENOTDIR;
        goto out;
    }

    struct libos_fs* fs = dent->inode->fs;
    if (!fs || !fs->d_ops || !fs->d_ops->unlink) {
        ret = -EACCES;
        goto out;
    }

    ret = fs->d_ops->unlink(dent);
    if (ret < 0)
        goto out;

    put_inode(dent->inode);
    dent->inode = NULL;
    ret = 0;
out:
    unlock(&g_dcache_lock);
    if (dent)
        put_dentry(dent);
    return ret;
}

long libos_syscall_umask(mode_t mask) {
    lock(&g_process.fs_lock);
    mode_t old = g_process.umask;
    g_process.umask = mask & 0777;
    unlock(&g_process.fs_lock);
    return old;
}

long libos_syscall_chmod(const char* path, mode_t mode) {
    return libos_syscall_fchmodat(AT_FDCWD, path, mode);
}

long libos_syscall_fchmodat(int dfd, const char* filename, mode_t mode) {
    if (!is_user_string_readable(filename))
        return -EFAULT;

    /* This isn't documented, but that's what Linux does. */
    mode_t perm = mode & 07777;

    struct libos_dentry* dir = NULL;
    struct libos_dentry* dent = NULL;
    int ret = 0;

    if (strnlen(filename, PATH_MAX + 1) == PATH_MAX + 1)
        return -ENAMETOOLONG;

    if (strlen(filename) == 0)
        return -ENOENT;

    if (*filename != '/' && (ret = get_dirfd_dentry(dfd, &dir)) < 0)
        return ret;

    lock(&g_dcache_lock);
    ret = path_lookupat(dir, filename, LOOKUP_FOLLOW, &dent);
    if (ret < 0)
        goto out;

    struct libos_fs* fs = dent->inode->fs;
    if (fs && fs->d_ops && fs->d_ops->chmod) {
        if ((ret = fs->d_ops->chmod(dent, perm)) < 0)
            goto out_dent;
    }

    lock(&dent->inode->lock);
    dent->inode->perm = perm;
    unlock(&dent->inode->lock);

out_dent:
    put_dentry(dent);
out:
    unlock(&g_dcache_lock);
    if (dir)
        put_dentry(dir);
    return ret;
}

long libos_syscall_fchmod(int fd, mode_t mode) {
    struct libos_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    /* This isn't documented, but that's what Linux does. */
    mode_t perm = mode & 07777;

    int ret;
    if (!hdl->inode) {
        ret = -ENOENT;
        goto out;
    }

    struct libos_fs* fs = hdl->inode->fs;
    if (fs && fs->fs_ops && fs->fs_ops->fchmod) {
        ret = fs->fs_ops->fchmod(hdl, perm);
        if (ret < 0)
            goto out;
    }

    lock(&hdl->inode->lock);
    hdl->inode->perm = perm;
    unlock(&hdl->inode->lock);

    ret = 0;
out:
    put_handle(hdl);
    return ret;
}

long libos_syscall_chown(const char* path, uid_t uid, gid_t gid) {
    return libos_syscall_fchownat(AT_FDCWD, path, uid, gid, 0);
}

long libos_syscall_fchownat(int dfd, const char* filename, uid_t uid, gid_t gid, int flags) {
    __UNUSED(flags);

    if (!is_user_string_readable(filename))
        return -EFAULT;

    struct libos_dentry* dir = NULL;
    struct libos_dentry* dent = NULL;
    int ret = 0;

    if (*filename != '/' && (ret = get_dirfd_dentry(dfd, &dir)) < 0)
        return ret;

    lock(&g_dcache_lock);
    ret = path_lookupat(dir, filename, LOOKUP_FOLLOW, &dent);
    if (ret < 0)
        goto out;

    lock(&dent->inode->lock);
    dent->inode->uid = (uid == (uid_t)-1) ? dent->inode->uid : uid;
    dent->inode->gid = (gid == (gid_t)-1) ? dent->inode->gid : gid;
    unlock(&dent->inode->lock);

    put_dentry(dent);
out:
    unlock(&g_dcache_lock);
    if (dir)
        put_dentry(dir);
    return ret;
}

long libos_syscall_fchown(int fd, uid_t uid, gid_t gid) {
    struct libos_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret;
    if (!hdl->inode) {
        ret = -ENOENT;
        goto out;
    }

    lock(&hdl->inode->lock);
    hdl->inode->uid = (uid == (uid_t)-1) ? hdl->inode->uid : uid;
    hdl->inode->gid = (gid == (gid_t)-1) ? hdl->inode->gid : gid;
    unlock(&hdl->inode->lock);

    ret = 0;
out:
    put_handle(hdl);
    return ret;
}

static int do_rename(struct libos_dentry* old_dent, struct libos_dentry* new_dent) {
    assert(locked(&g_dcache_lock));
    assert(old_dent->inode);

    if ((old_dent->inode->type != S_IFREG) || (new_dent->inode &&
                                               new_dent->inode->type != S_IFREG)) {
        /* Current implementation of fs does not allow for renaming anything but regular files */
        return -ENOSYS;
    }

    if (old_dent->mount != new_dent->mount) {
        /* Disallow cross mount renames */
        return -EXDEV;
    }

    struct libos_fs* fs = old_dent->inode->fs;
    if (!fs || !fs->d_ops || !fs->d_ops->rename) {
        return -EPERM;
    }

    if (old_dent->inode->type == S_IFDIR) {
        if (new_dent->inode) {
            if (new_dent->inode->type != S_IFDIR) {
                return -ENOTDIR;
            }
            if (new_dent->nchildren > 0) {
                return -ENOTEMPTY;
            }
        }
    } else if (new_dent->inode && new_dent->inode->type == S_IFDIR) {
        return -EISDIR;
    }

    if (dentry_is_ancestor(old_dent, new_dent) || dentry_is_ancestor(new_dent, old_dent)) {
        return -EINVAL;
    }

    /* TODO: Add appropriate checks for hardlinks once they get implemented. */

    int ret = fs->d_ops->rename(old_dent, new_dent);
    if (ret < 0)
        return ret;

    if (new_dent->inode)
        put_inode(new_dent->inode);
    new_dent->inode = old_dent->inode;
    old_dent->inode = NULL;
    return 0;
}

long libos_syscall_rename(const char* oldpath, const char* newpath) {
    return libos_syscall_renameat(AT_FDCWD, oldpath, AT_FDCWD, newpath);
}

long libos_syscall_renameat(int olddirfd, const char* oldpath, int newdirfd, const char* newpath) {
    struct libos_dentry* old_dir_dent = NULL;
    struct libos_dentry* old_dent     = NULL;
    struct libos_dentry* new_dir_dent = NULL;
    struct libos_dentry* new_dent     = NULL;
    int ret = 0;

    if (!is_user_string_readable(oldpath) || !is_user_string_readable(newpath)) {
        return -EFAULT;
    }

    lock(&g_dcache_lock);

    if (strcmp(oldpath, newpath) == 0) {
        goto out;
    }

    if (*oldpath != '/' && (ret = get_dirfd_dentry(olddirfd, &old_dir_dent)) < 0) {
        goto out;
    }

    ret = path_lookupat(old_dir_dent, oldpath, LOOKUP_NO_FOLLOW, &old_dent);
    if (ret < 0) {
        goto out;
    }

    if (!old_dent->inode) {
        ret = -ENOENT;
        goto out;
    }

    if (*newpath != '/' && (ret = get_dirfd_dentry(newdirfd, &new_dir_dent)) < 0) {
        goto out;
    }

    ret = path_lookupat(new_dir_dent, newpath, LOOKUP_NO_FOLLOW | LOOKUP_CREATE, &new_dent);
    if (ret < 0)
        goto out;

    // Both dentries should have a ref count of at least 2 at this point
    assert(refcount_get(&old_dent->ref_count) >= 2);
    assert(refcount_get(&new_dent->ref_count) >= 2);

    ret = do_rename(old_dent, new_dent);

out:
    unlock(&g_dcache_lock);
    if (old_dir_dent)
        put_dentry(old_dir_dent);
    if (old_dent)
        put_dentry(old_dent);
    if (new_dir_dent)
        put_dentry(new_dir_dent);
    if (new_dent)
        put_dentry(new_dent);
    return ret;
}

long libos_syscall_sendfile(int out_fd, int in_fd, off_t* offset, size_t count) {
    long ret;
    char* buf = NULL;

    /* "unused" to silence newer Clang; we keep this variable as it may be helpful once we improve
     * the `sendfile()` implementation, see one of the TODOs below */
    __attribute__((unused)) size_t read_from_in = 0;

    size_t copied_to_out = 0;

    if (offset && !is_user_memory_writable(offset, sizeof(*offset)))
        return -EFAULT;

    struct libos_handle* in_hdl = get_fd_handle(in_fd, NULL, NULL);
    if (!in_hdl)
        return -EBADF;

    struct libos_handle* out_hdl = get_fd_handle(out_fd, NULL, NULL);
    if (!out_hdl) {
        put_handle(in_hdl);
        return -EBADF;
    }

    if (!in_hdl->fs || !in_hdl->fs->fs_ops || !out_hdl->fs || !out_hdl->fs->fs_ops) {
        ret = -EINVAL;
        goto out;
    }

    if (!(in_hdl->acc_mode & MAY_READ) || !(out_hdl->acc_mode & MAY_WRITE)) {
        /* error out if input fd isn't readable or output fd isn't writable */
        ret = -EBADF;
        goto out;
    }

    if (out_hdl->flags & O_APPEND) {
        /* Linux errors out if output fd has the O_APPEND flag set; comply with this behavior */
        ret = -EINVAL;
        goto out;
    }

    /* FIXME: This sendfile() emulation is very simple and not particularly efficient: it reads from
     *        input FD in BUF_SIZE chunks and writes into output FD. Mmap-based emulation may be
     *        more efficient but adds complexity (not all handle types provide mmap callback). */

    bool buf_in_use = __atomic_exchange_n(&g_sendfile_buf_in_use, true, __ATOMIC_ACQUIRE);
    if (!buf_in_use) {
        /* no other thread was using the static buffer */
        buf = g_sendfile_buf;
    } else {
        buf = malloc(BUF_SIZE);
        if (!buf) {
            ret = -ENOMEM;
            goto out;
        }
    }

    if (!count) {
        ret = 0;
        goto out;
    }

    /*
     * If `offset` is not NULL, we use `*offset` as starting offset for reading, and update
     * `*offset` afterwards (and keep the offset in input handle unchanged).
     *
     * If `offset` is NULL, we use the offset in input handle, and update it afterwards (only if the
     * input handle is seekable).
     */
    file_off_t pos_in = 0;
    if (offset) {
        if (!in_hdl->fs->fs_ops->seek) {
            ret = -ESPIPE;
            goto out;
        }
        pos_in = *offset;
        if (pos_in < 0) {
            ret = -EINVAL;
            goto out;
        }
    } else {
        maybe_lock_pos_handle(in_hdl);
        pos_in = in_hdl->pos;
        maybe_unlock_pos_handle(in_hdl);
    }

    while (copied_to_out < count) {
        size_t to_copy = count - copied_to_out > BUF_SIZE ? BUF_SIZE : count - copied_to_out;

        ssize_t x = in_hdl->fs->fs_ops->read(in_hdl, buf, to_copy, &pos_in);
        if (x < 0) {
            ret = x;
            goto out_update;
        }
        assert(x <= (ssize_t)to_copy);

        read_from_in += x;

        if (x == 0) {
            /* no more data in input FD, let's return however many bytes copied_to_out up until now */
            break;
        }

        maybe_lock_pos_handle(out_hdl);
        ssize_t y = out_hdl->fs->fs_ops->write(out_hdl, buf, x, &out_hdl->pos);
        maybe_unlock_pos_handle(out_hdl);
        if (y < 0) {
            ret = y;
            goto out_update;
        }
        assert(y <= x);

        copied_to_out += y;

        if (y < x) {
            /* written less bytes to output fd than read from input fd -> out of sync now; don't try
             * to be smart and simply return however many bytes we copied_to_out up until now */
            /* TODO: need to revert in_fd's file position to (read_from_in - x + y) from original
             *       offset and maybe continue this loop */
            break;
        }
    }

    ret = 0;

out_update:
    /* Update either `*offset` or the offset in input file (see the comment above `pos_in`
     * declaration). Note that we do it even if one of the read/write operations failed. */
    if (offset) {
        *offset = pos_in;
    } else if (in_hdl->seekable) {
        maybe_lock_pos_handle(in_hdl);
        in_hdl->pos = pos_in;
        maybe_unlock_pos_handle(in_hdl);
    }

out:
    if (buf == g_sendfile_buf)
        __atomic_store_n(&g_sendfile_buf_in_use, false, __ATOMIC_RELEASE);
    else
        free(buf);
    put_handle(in_hdl);
    put_handle(out_hdl);
    return copied_to_out ? (long)copied_to_out : ret;
}

long libos_syscall_chroot(const char* filename) {
    if (!is_user_string_readable(filename))
        return -EFAULT;

    int ret = 0;
    struct libos_dentry* dent = NULL;
    lock(&g_dcache_lock);
    ret = path_lookupat(/*start=*/NULL, filename, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &dent);
    unlock(&g_dcache_lock);
    if (ret < 0)
        goto out;

    if (!dent) {
        ret = -ENOENT;
        goto out;
    }

    lock(&g_process.fs_lock);
    put_dentry(g_process.root);
    g_process.root = dent;
    unlock(&g_process.fs_lock);
out:
    return ret;
}
