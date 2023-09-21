/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */
/* Copyright (C) 2020 Intel Labs */

/*
 * Operations to handle devices (with special case of "dev:tty" which is stdin/stdout).
 *
 * TODO: Some devices allow lseek() but typically with device-specific semantics. Gramine currently
 *       emulates lseek() completely in LibOS layer, thus seeking at PAL layer cannot be correctly
 *       implemented (without device-specific changes to LibOS layer).
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_flags_conv.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "path_utils.h"
#include "perm.h"

static int dev_open(PAL_HANDLE* handle, const char* type, const char* uri, enum pal_access access,
                    pal_share_flags_t share, enum pal_create_mode create,
                    pal_stream_options_t options) {
    int ret;
    char* normpath = NULL;

    if (strcmp(type, URI_TYPE_DEV))
        return -PAL_ERROR_INVAL;

    assert(WITHIN_MASK(share,   PAL_SHARE_MASK));
    assert(WITHIN_MASK(options, PAL_OPTION_MASK));

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(dev));
    if (!hdl)
        return -PAL_ERROR_NOMEM;

    init_handle_hdr(hdl, PAL_TYPE_DEV);

    if (!strcmp(uri, "tty")) {
        /* special case of "dev:tty" device which is the standard input + standard output */
        hdl->dev.nonblocking = false;

        if (access == PAL_ACCESS_RDONLY) {
            hdl->flags |= PAL_HANDLE_FD_READABLE;
            hdl->dev.fd = 0; /* host stdin */
        } else if (access == PAL_ACCESS_WRONLY) {
            hdl->flags |= PAL_HANDLE_FD_WRITABLE;
            hdl->dev.fd = 1; /* host stdout */
        } else {
            assert(access == PAL_ACCESS_RDWR);
            ret = -PAL_ERROR_INVAL;
            goto fail;
        }
    } else {
        /* other devices must be opened through the host */

        /* normalize uri into normpath */
        size_t normpath_size = strlen(uri) + 1;
        normpath = malloc(normpath_size);
        if (!normpath){
            ret = -PAL_ERROR_NOMEM;
            goto fail;
        }

        ret = get_norm_path(uri, normpath, &normpath_size);
        if (ret < 0) {
            log_warning("Could not normalize path (%s): %s", uri, pal_strerror(ret));
            ret = -PAL_ERROR_DENIED;
            goto fail;
        }

        hdl->dev.nonblocking = !!(options & PAL_OPTION_NONBLOCK);

        ret = DO_SYSCALL(open, uri, PAL_ACCESS_TO_LINUX_OPEN(access)  |
                                    PAL_CREATE_TO_LINUX_OPEN(create)  |
                                    PAL_OPTION_TO_LINUX_OPEN(options) |
                                    O_CLOEXEC,
                         share);
        if (ret < 0) {
            ret = unix_to_pal_error(ret);
            goto fail;
        }

        hdl->dev.realpath = normpath;
        hdl->dev.fd       = ret;

        if (access == PAL_ACCESS_RDONLY) {
            hdl->flags |= PAL_HANDLE_FD_READABLE;
        } else if (access == PAL_ACCESS_WRONLY) {
            hdl->flags |= PAL_HANDLE_FD_WRITABLE;
        } else {
            assert(access == PAL_ACCESS_RDWR);
            hdl->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
        }
    }

    *handle = hdl;
    return 0;
fail:
    free(hdl);
    free(normpath);
    return ret;
}

static int64_t dev_read(PAL_HANDLE handle, uint64_t offset, uint64_t size, void* buffer) {
    if (offset || handle->hdr.type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (!(handle->flags & PAL_HANDLE_FD_READABLE))
        return -PAL_ERROR_DENIED;

    if (handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    int64_t bytes = DO_SYSCALL(read, handle->dev.fd, buffer, size);
    return bytes < 0 ? unix_to_pal_error(bytes) : bytes;
}

static int64_t dev_write(PAL_HANDLE handle, uint64_t offset, uint64_t size, const void* buffer) {
    if (offset || handle->hdr.type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (!(handle->flags & PAL_HANDLE_FD_WRITABLE))
        return -PAL_ERROR_DENIED;

    if (handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    int64_t bytes = DO_SYSCALL(write, handle->dev.fd, buffer, size);
    return bytes < 0 ? unix_to_pal_error(bytes) : bytes;
}

static int dev_close(PAL_HANDLE handle) {
    if (handle->hdr.type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    /* currently we just assign `0`/`1` FDs without duplicating, so close is a no-op for them */
    int ret = 0;
    if (handle->dev.fd != PAL_IDX_POISON && handle->dev.fd != 0 && handle->dev.fd != 1) {
        ret = DO_SYSCALL(close, handle->dev.fd);
        free(handle->dev.realpath);
    }
    handle->dev.fd = PAL_IDX_POISON;
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

static int dev_delete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    if (handle->hdr.type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (delete_mode != PAL_DELETE_ALL)
        return -PAL_ERROR_INVAL;

    if (!handle->dev.realpath)
        return -PAL_ERROR_INVAL;

    int ret = DO_SYSCALL(unlink, handle->dev.realpath);
    return ret < 0 ? unix_to_pal_error(ret) : ret;
}

static int dev_map(PAL_HANDLE handle, void* addr, pal_prot_flags_t prot, uint64_t offset,
                   uint64_t size) {
    if (handle->hdr.type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (!handle->dev.realpath)
        return -PAL_ERROR_INVAL;

    assert(IS_ALLOC_ALIGNED(offset) && IS_ALLOC_ALIGNED(size));

    uint64_t dummy;
    if (__builtin_add_overflow(offset, size, &dummy)) {
        return -PAL_ERROR_INVAL;
    }

    assert(addr >= g_pal_public_state.shared_address_start &&
           (uintptr_t)addr + size < (uintptr_t)g_pal_public_state.shared_address_end);
    void* mapped_addr = (void*)DO_SYSCALL(mmap, addr, size, PAL_PROT_TO_LINUX(prot),
                                          MAP_SHARED | MAP_FIXED, handle->dev.fd, offset);
    if (IS_PTR_ERR(mapped_addr))
        return unix_to_pal_error(PTR_TO_ERR(mapped_addr));

    assert(mapped_addr == addr);
    return 0;
}

static int dev_flush(PAL_HANDLE handle) {
    if (handle->hdr.type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (handle->dev.fd != PAL_IDX_POISON) {
        int ret = DO_SYSCALL(fsync, handle->dev.fd);
        if (ret < 0)
            return unix_to_pal_error(ret);
    }
    return 0;
}

static int dev_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* attr) {
    __UNUSED(uri);

    if (strcmp(type, URI_TYPE_DEV))
        return -PAL_ERROR_INVAL;

    if (!strcmp(uri, "tty")) {
        /* special case of "dev:tty" device which is the standard input + standard output */
        attr->share_flags  = PERM_rw_rw_rw_;
        attr->pending_size = 0;
    } else {
        /* other devices must query the host */
        struct stat stat_buf;
        int ret = DO_SYSCALL(stat, uri, &stat_buf);
        if (ret < 0)
            return unix_to_pal_error(ret);

        attr->share_flags  = stat_buf.st_mode & PAL_SHARE_MASK;
        attr->pending_size = stat_buf.st_size;
    }

    attr->handle_type = PAL_TYPE_DEV;
    attr->nonblocking = false;
    return 0;
}

static int dev_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (handle->hdr.type != PAL_TYPE_DEV || handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_INVAL;

    if (handle->dev.fd == 0 || handle->dev.fd == 1) {
        /* special case of "dev:tty" device which is the standard input + standard output */
        attr->share_flags  = 0;
        attr->pending_size = 0;
    } else {
        /* other devices must query the host */
        struct stat stat_buf;
        int ret = DO_SYSCALL(fstat, handle->dev.fd, &stat_buf);
        if (ret < 0)
            return unix_to_pal_error(ret);

        attr->share_flags  = stat_buf.st_mode & PAL_SHARE_MASK;
        attr->pending_size = stat_buf.st_size;
    }

    attr->handle_type = PAL_TYPE_DEV;
    attr->nonblocking = handle->dev.nonblocking;
    return 0;
}

static int64_t dev_setlength(PAL_HANDLE handle, uint64_t length) {
    if (handle->hdr.type != PAL_TYPE_DEV || handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_INVAL;

    if (!handle->dev.realpath) {
        /* TTY devices opened with O_TRUNC flag */
        if (length != 0)
            return -PAL_ERROR_INVAL;
        return 0;
    }

    int ret = DO_SYSCALL(ftruncate, handle->dev.fd, length);
    return ret < 0 ? unix_to_pal_error(ret) : (int64_t)length;
}

struct handle_ops g_dev_ops = {
    .open           = &dev_open,
    .read           = &dev_read,
    .write          = &dev_write,
    .close          = &dev_close,
    .delete         = &dev_delete,
    .map            = &dev_map,
    .setlength      = &dev_setlength,
    .flush          = &dev_flush,
    .attrquery      = &dev_attrquery,
    .attrquerybyhdl = &dev_attrquerybyhdl,
};

int _PalDeviceIoControl(PAL_HANDLE handle, uint32_t cmd, unsigned long arg, int* out_ret) {
    if (handle->hdr.type != PAL_TYPE_DEV)
        return -PAL_ERROR_INVAL;

    if (handle->dev.fd == PAL_IDX_POISON)
        return -PAL_ERROR_DENIED;

    /* note that if the host returned a negative value (typically means an error, but not always
     * since this is completely device-specific), then we still return success and forward the value
     * as-is to the LibOS and ultimately to the app */
    *out_ret = DO_SYSCALL(ioctl, handle->dev.fd, cmd, arg);
    return 0;
}
