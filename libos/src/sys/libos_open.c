/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Implementation of system calls: "read", "write", "open", "creat", "openat", "close", "lseek",
 * "pread64", "pwrite64", "getdents", "getdents64", "fsync", "truncate" and "ftruncate".
 */

#define _POSIX_C_SOURCE 200809L  /* for SSIZE_MAX */

#include <errno.h>
#include <limits.h>
#include <linux/fadvise.h>
#include <linux/fcntl.h>
#include <stdalign.h>

#include "libos_fs.h"
#include "libos_handle.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_process.h"
#include "libos_table.h"
#include "stat.h"

ssize_t do_handle_read(struct libos_handle* hdl, void* buf, size_t count) {
    if (!(hdl->acc_mode & MAY_READ))
        return -EBADF;

    struct libos_fs* fs = hdl->fs;
    assert(fs && fs->fs_ops);

    if (!fs->fs_ops->read)
        return -EBADF;

    if (hdl->is_dir)
        return -EISDIR;

    lock(&hdl->pos_lock);
    ssize_t ret = fs->fs_ops->read(hdl, buf, count, &hdl->pos);
    unlock(&hdl->pos_lock);
    return ret;
}

long libos_syscall_read(int fd, void* buf, size_t count) {
    if (!is_user_memory_writable(buf, count))
        return -EFAULT;

    struct libos_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    ssize_t ret = do_handle_read(hdl, buf, count);
    put_handle(hdl);
    if (ret == -EINTR) {
        ret = -ERESTARTSYS;
    }
    return ret;
}

ssize_t do_handle_write(struct libos_handle* hdl, const void* buf, size_t count) {
    if (!(hdl->acc_mode & MAY_WRITE))
        return -EBADF;

    struct libos_fs* fs = hdl->fs;
    assert(fs && fs->fs_ops);

    if (!fs->fs_ops->write)
        return -EBADF;

    if (hdl->is_dir)
        return -EISDIR;

    lock(&hdl->pos_lock);
    ssize_t ret = fs->fs_ops->write(hdl, buf, count, &hdl->pos);
    unlock(&hdl->pos_lock);
    return ret;
}

long libos_syscall_write(int fd, const void* buf, size_t count) {
    if (!is_user_memory_readable((void*)buf, count))
        return -EFAULT;

    struct libos_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    ssize_t ret = do_handle_write(hdl, buf, count);
    put_handle(hdl);
    if (ret == -EINTR) {
        ret = -ERESTARTSYS;
    }
    return ret;
}

long libos_syscall_open(const char* file, int flags, mode_t mode) {
    return libos_syscall_openat(AT_FDCWD, file, flags, mode);
}

long libos_syscall_creat(const char* path, mode_t mode) {
    return libos_syscall_open(path, O_CREAT | O_TRUNC | O_WRONLY, mode);
}

long libos_syscall_openat(int dfd, const char* filename, int flags, int mode) {
    /* Clear invalid flags. */
    flags &= O_ACCMODE | O_APPEND |  O_CLOEXEC | O_CREAT | O_DIRECT | O_DIRECTORY | O_DSYNC | O_EXCL
             | O_LARGEFILE | O_NOATIME | O_NOCTTY | O_NOFOLLOW | O_NONBLOCK | O_PATH | O_SYNC
             | O_TMPFILE | O_TRUNC;

    /* TODO: fail explicitly on valid but unsupported flags. */

    if (flags & O_PATH) {
        flags &= O_PATH | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW;
    }

    if (!is_user_string_readable(filename))
        return -EFAULT;

    if (!(flags & O_CREAT)) {
        /* `mode` should be ignored if O_CREAT is not specified, according to man */
        mode = 0;
    } else {
        lock(&g_process.fs_lock);
        mode_t umask = g_process.umask;
        unlock(&g_process.fs_lock);

        /* Clear invalid bits */
        mode &= 07777;

        mode &= ~umask;
    }

    struct libos_dentry* dir = NULL;
    int ret = 0;

    if (*filename != '/' && (ret = get_dirfd_dentry(dfd, &dir)) < 0)
        return ret;

    struct libos_handle* hdl = get_new_handle();
    if (!hdl) {
        ret = -ENOMEM;
        goto out;
    }

    ret = open_namei(hdl, dir, filename, flags, mode, NULL);
    if (ret < 0) {
        /* If this was blocking `open` (e.g. on FIFO), it might have returned `-EINTR`. */
        if (ret == -EINTR) {
            ret = -ERESTARTSYS;
        }
        goto out_hdl;
    }

    ret = set_new_fd_handle(hdl, flags & O_CLOEXEC ? FD_CLOEXEC : 0, NULL);

out_hdl:
    put_handle(hdl);
out:
    if (dir)
        put_dentry(dir);
    return ret;
}

long libos_syscall_close(int fd) {
    struct libos_handle* handle = detach_fd_handle(fd, NULL, NULL);
    if (!handle)
        return -EBADF;

    put_handle(handle);
    return 0;
}

/* See also `do_getdents`. */
static file_off_t do_lseek_dir(struct libos_handle* hdl, off_t offset, int origin) {
    assert(hdl->is_dir);

    lock(&g_dcache_lock);
    lock(&hdl->pos_lock);
    lock(&hdl->lock);

    file_off_t ret;

    /* Refresh the directory handle, so that after `lseek` the user sees an updated listing. */
    clear_directory_handle(hdl);
    if ((ret = populate_directory_handle(hdl)) < 0)
        goto out;

    struct libos_dir_handle* dirhdl = &hdl->dir_info;

    file_off_t pos;
    ret = generic_seek(hdl->pos, dirhdl->count, offset, origin, &pos);
    if (ret < 0)
        goto out;
    hdl->pos = pos;
    ret = pos;

out:
    unlock(&hdl->lock);
    unlock(&hdl->pos_lock);
    unlock(&g_dcache_lock);
    return ret;
}

/* lseek is simply doing arithmetic on the offset, no PAL call here */
long libos_syscall_lseek(int fd, off_t offset, int origin) {
    if (origin != SEEK_SET && origin != SEEK_CUR && origin != SEEK_END)
        return -EINVAL;

    struct libos_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    off_t ret = 0;
    if (hdl->is_dir) {
        ret = do_lseek_dir(hdl, offset, origin);
        goto out;
    }

    struct libos_fs* fs = hdl->fs;
    assert(fs && fs->fs_ops);

    if (!fs->fs_ops->seek) {
        ret = -ESPIPE;
        goto out;
    }

    ret = fs->fs_ops->seek(hdl, offset, origin);
out:
    put_handle(hdl);
    return ret;
}

long libos_syscall_pread64(int fd, char* buf, size_t count, loff_t offset) {
    if (!is_user_memory_writable(buf, count))
        return -EFAULT;

    if (offset < 0)
        return -EINVAL;

    struct libos_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    struct libos_fs* fs = hdl->fs;
    ssize_t ret = -EACCES;

    if (!(hdl->acc_mode & MAY_READ)) {
        ret = -EBADF;
        goto out;
    }

    if (!fs || !fs->fs_ops)
        goto out;

    if (!fs->fs_ops->seek) {
        ret = -ESPIPE;
        goto out;
    }

    if (!fs->fs_ops->read)
        goto out;

    if (hdl->is_dir) {
        ret = -EISDIR;
        goto out;
    }

    file_off_t pos = offset;
    ret = fs->fs_ops->read(hdl, buf, count, &pos);
out:
    put_handle(hdl);
    return ret;
}

long libos_syscall_pwrite64(int fd, char* buf, size_t count, loff_t offset) {
    if (!is_user_memory_readable(buf, count))
        return -EFAULT;

    if (offset < 0)
        return -EINVAL;

    struct libos_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    struct libos_fs* fs = hdl->fs;
    ssize_t ret = -EACCES;

    if (!(hdl->acc_mode & MAY_WRITE)) {
        ret = -EBADF;
        goto out;
    }

    if (!fs || !fs->fs_ops)
        goto out;

    if (!fs->fs_ops->seek) {
        ret = -ESPIPE;
        goto out;
    }

    if (!fs->fs_ops->write)
        goto out;

    if (hdl->is_dir) {
        ret = -EISDIR;
        goto out;
    }

    file_off_t pos = offset;
    ret = fs->fs_ops->write(hdl, buf, count, &pos);
out:
    put_handle(hdl);
    return ret;
}

static int get_dirent_type(mode_t type) {
    switch (type) {
        case S_IFLNK:
            return LINUX_DT_LNK;
        case S_IFREG:
            return LINUX_DT_REG;
        case S_IFDIR:
            return LINUX_DT_DIR;
        case S_IFCHR:
            return LINUX_DT_CHR;
        case S_IFBLK:
            return LINUX_DT_BLK;
        case S_IFIFO:
            return LINUX_DT_FIFO;
        case S_IFSOCK:
            return LINUX_DT_SOCK;
        default:
            return LINUX_DT_UNKNOWN;
    }
}

static ssize_t do_getdents(int fd, uint8_t* buf, size_t buf_size, bool is_getdents64) {
    if (!is_user_memory_writable(buf, buf_size))
        return -EFAULT;

    struct libos_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    ssize_t ret;

    if (!hdl->is_dir) {
        ret = -ENOTDIR;
        goto out_no_unlock;
    }

    if (!hdl->dentry->inode) {
        ret = -ENOENT;
        goto out_no_unlock;
    }

    lock(&g_dcache_lock);
    lock(&hdl->pos_lock);
    lock(&hdl->lock);

    struct libos_dir_handle* dirhdl = &hdl->dir_info;
    if ((ret = populate_directory_handle(hdl)) < 0)
        goto out;

    size_t buf_pos = 0;
    while ((size_t)hdl->pos < dirhdl->count) {
        struct libos_dentry* dent = dirhdl->dents[hdl->pos];
        assert(dent->inode);

        const char* name;
        size_t name_len;

        if (hdl->pos == 0) {
            name = ".";
            name_len = 1;
        } else if (hdl->pos == 1) {
            name = "..";
            name_len = 2;
        } else {
            name = dent->name;
            name_len = dent->name_len;
        }

        uint64_t d_ino = dentry_ino(dent);
        char d_type = get_dirent_type(dent->inode->type);

        size_t ent_size;

        if (is_getdents64) {
            ent_size = ALIGN_UP(sizeof(struct linux_dirent64) + name_len + 1,
                                alignof(struct linux_dirent64));
            if (buf_pos + ent_size > buf_size)
                break;

            struct linux_dirent64* ent = (struct linux_dirent64*)(buf + buf_pos);
            memset(ent, 0, ent_size); // this ensures `name` will be null-terminated

            ent->d_ino = d_ino;
            ent->d_off = hdl->pos;
            ent->d_reclen = ent_size;
            ent->d_type = d_type;
            memcpy(&ent->d_name, name, name_len);
        } else {
            /* Note that `struct linux_dirent_tail` starts with a zero padding byte, so we don't
             * need to account for extra null byte at the end of `name`. */
            ent_size = ALIGN_UP(
                sizeof(struct linux_dirent) + sizeof(struct linux_dirent_tail) + name_len,
                alignof(struct linux_dirent)
            );
            if (buf_pos + ent_size > buf_size)
                break;

            struct linux_dirent* ent = (struct linux_dirent*)(buf + buf_pos);
            struct linux_dirent_tail* tail =
                (struct linux_dirent_tail*)(buf + buf_pos + ent_size - sizeof(*tail));
            memset(ent, 0, ent_size); // this ensures `name` will be null-terminated

            ent->d_ino = d_ino;
            ent->d_off = hdl->pos;
            ent->d_reclen = ent_size;
            memcpy(&ent->d_name, name, name_len);
            tail->d_type = d_type;
        }

        buf_pos += ent_size;
        hdl->pos++;
    }

    /* Guard against overflow */
    size_t limit = is_getdents64 ? (size_t)LONG_MAX : (size_t)SSIZE_MAX;
    if (buf_pos > limit) {
        ret = -EINVAL;
        goto out;
    }

    /* Return EINVAL if buffer is too small to hold anything */
    if (buf_pos == 0 && (size_t)hdl->pos < dirhdl->count) {
        ret = -EINVAL;
        goto out;
    }

    ret = buf_pos;
out:
    unlock(&hdl->lock);
    unlock(&hdl->pos_lock);
    unlock(&g_dcache_lock);
out_no_unlock:
    put_handle(hdl);
    return ret;
}

static_assert(sizeof(long) <= sizeof(ssize_t),
              "return type of do_getdents() is too small for getdents32");

long libos_syscall_getdents(int fd, struct linux_dirent* buf, unsigned int count) {
    return do_getdents(fd, (uint8_t*)buf, count, /*is_getdents64=*/false);
}

long libos_syscall_getdents64(int fd, struct linux_dirent64* buf, size_t count) {
    return do_getdents(fd, (uint8_t*)buf, count, /*is_getdents64=*/true);
}

long libos_syscall_fsync(int fd) {
    struct libos_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    int ret;
    struct libos_fs* fs = hdl->fs;

    if (!fs || !fs->fs_ops) {
        ret = -EACCES;
        goto out;
    }

    if (hdl->is_dir) {
        /* FS subsystem doesn't do anything meaningful with dirs, so flushing a dir is a no-op */
        ret = 0;
        goto out;
    }

    if (!fs->fs_ops->flush) {
        ret = -EINVAL; /* Linux kernel returns EINVAL on special files (not EROFS) */
        goto out;
    }

    ret = fs->fs_ops->flush(hdl);
out:
    put_handle(hdl);
    return ret;
}

long libos_syscall_fdatasync(int fd) {
    /* assume fsync() >> fdatasync(); no app should depend on only syncing data for correctness */
    return libos_syscall_fsync(fd);
}

long libos_syscall_truncate(const char* path, loff_t length) {
    if (length < 0)
        return -EINVAL;

    int ret;

    if (!is_user_string_readable(path))
        return -EFAULT;

    struct libos_handle* hdl = get_new_handle();
    if (!hdl)
        return -ENOMEM;

    ret = open_namei(hdl, /*start=*/NULL, path, LOOKUP_FOLLOW, O_WRONLY, /*found=*/NULL);
    if (ret < 0)
        goto out;

    struct libos_fs* fs = hdl->fs;

    if (!fs->fs_ops->truncate) {
        ret = -EROFS;
        goto out;
    }

    ret = fs->fs_ops->truncate(hdl, length);
out:
    put_handle(hdl);
    return ret;
}

long libos_syscall_ftruncate(int fd, loff_t length) {
    if (length < 0)
        return -EINVAL;

    struct libos_handle* hdl = get_fd_handle(fd, NULL, NULL);
    if (!hdl)
        return -EBADF;

    struct libos_fs* fs = hdl->fs;
    int ret;

    if (!(hdl->acc_mode & MAY_WRITE)) {
        /* Note that we return EINVAL here, not EBADF like in `read`/`write`. This is what Linux
         * does. */
        ret = -EINVAL;
        goto out;
    }

    if (!fs || !fs->fs_ops) {
        ret = -EINVAL;
        goto out;
    }

    if (hdl->is_dir || !fs->fs_ops->truncate) {
        ret = -EINVAL;
        goto out;
    }

    ret = fs->fs_ops->truncate(hdl, length);
out:
    put_handle(hdl);
    return ret;
}

long libos_syscall_fallocate(int fd, int mode, loff_t offset, loff_t len) {
    int ret;
    if (offset < 0) {
        return -EINVAL;
    }
    if (len <= 0) {
        return -EINVAL;
    }
    if (mode) {
        log_warning("fallocate only supported with 0 as mode");
        return -ENOSYS;
    }

    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }
    if (handle->type == TYPE_PIPE) {
        ret = -ESPIPE;
        goto out;
    }
    if (!handle->inode || handle->inode->type != S_IFREG) {
        ret = -ENODEV;
        goto out;
    }

    if (!(handle->acc_mode & MAY_WRITE)) {
        ret = -EBADF;
        goto out;
    }

    struct libos_fs* fs = handle->fs;
    if (!fs || !fs->fs_ops) {
        ret = -EINVAL;
        goto out;
    }
    if (!fs->fs_ops->truncate) {
        ret = -EOPNOTSUPP;
        goto out;
    }

    loff_t end;
    if (__builtin_add_overflow(offset, len, &end)) {
        ret = -EFBIG;
        goto out;
    }

    /* Simple implementation: extend the file if required, otherwise act as a no-op.
     * WARNING: if two threads try doing `fallocate` at the same time with 2 different sizes (and
     * both bigger than the current size) or one does `fallocate` and the other tries writing to
     * the end of the file, there is a possibility of a race which would actually truncate the file.
     * Hopefully no sane application does that. */
    lock(&handle->inode->lock);
    file_off_t size = handle->inode->size;
    unlock(&handle->inode->lock);
    if (end > size) {
        ret = fs->fs_ops->truncate(handle, end);
    } else {
        ret = 0;
    }

out:
    put_handle(handle);
    return ret;
}

long libos_syscall_fadvise64(int fd, loff_t offset, size_t len, int advice) {
    __UNUSED(offset);
    __UNUSED(len);
    int ret;

    switch (advice) {
        case POSIX_FADV_NORMAL:
        case POSIX_FADV_RANDOM:
        case POSIX_FADV_SEQUENTIAL:
        case POSIX_FADV_WILLNEED:
        case POSIX_FADV_NOREUSE:
        case POSIX_FADV_DONTNEED:
            break;
        default:
            return -EINVAL;
    }

    struct libos_handle* handle = get_fd_handle(fd, NULL, NULL);
    if (!handle) {
        return -EBADF;
    }

    if (handle->type == TYPE_PIPE) {
        ret = -ESPIPE;
        goto out;
    }

    /* currently just a no-op */
    ret = 0;

out:
    put_handle(handle);
    return ret;
}
