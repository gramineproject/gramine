/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to open, read, write and get attribute of streams.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

/* Stream handler table: this table corresponds to all the handle types supported by PAL. Threads
 * are not streams, so they need no handler. Sockets have their own table. */
extern struct handle_ops g_file_ops;
extern struct handle_ops g_pipe_ops;
extern struct handle_ops g_console_ops;
extern struct handle_ops g_dev_ops;
extern struct handle_ops g_dir_ops;
extern struct handle_ops g_thread_ops;
extern struct handle_ops g_proc_ops;
extern struct handle_ops g_event_ops;
extern struct handle_ops g_eventfd_ops;

const struct handle_ops* g_pal_handle_ops[PAL_HANDLE_TYPE_BOUND] = {
    [PAL_TYPE_FILE]    = &g_file_ops,
    [PAL_TYPE_PIPE]    = &g_pipe_ops,
    [PAL_TYPE_PIPESRV] = &g_pipe_ops,
    [PAL_TYPE_PIPECLI] = &g_pipe_ops,
    [PAL_TYPE_CONSOLE] = &g_console_ops,
    [PAL_TYPE_DEV]     = &g_dev_ops,
    [PAL_TYPE_DIR]     = &g_dir_ops,
    [PAL_TYPE_PROCESS] = &g_proc_ops,
    [PAL_TYPE_THREAD]  = &g_thread_ops,
    [PAL_TYPE_EVENT]   = &g_event_ops,
    [PAL_TYPE_EVENTFD] = &g_eventfd_ops,
};

/* `out_type` is provided by the caller; `out_uri` is the pointer inside `typed_uri` */
static int split_uri_and_find_ops(const char* typed_uri, char* out_type, const char** out_uri,
                                  struct handle_ops** out_ops) {
    if (strstartswith(typed_uri, URI_PREFIX_DIR)) {
        memcpy(out_type, URI_TYPE_DIR, sizeof(URI_TYPE_DIR));
        *out_ops = &g_dir_ops;
        *out_uri = typed_uri + URI_PREFIX_DIR_LEN;
    } else if (strstartswith(typed_uri, URI_PREFIX_DEV)) {
        memcpy(out_type, URI_TYPE_DEV, sizeof(URI_TYPE_DEV));
        *out_ops = &g_dev_ops;
        *out_uri = typed_uri + URI_PREFIX_DEV_LEN;
    } else if (strstartswith(typed_uri, URI_PREFIX_FILE)) {
        memcpy(out_type, URI_TYPE_FILE, sizeof(URI_TYPE_FILE));
        *out_ops = &g_file_ops;
        *out_uri = typed_uri + URI_PREFIX_FILE_LEN;
    } else if (strstartswith(typed_uri, URI_PREFIX_PIPE)) {
        memcpy(out_type, URI_TYPE_PIPE, sizeof(URI_TYPE_PIPE));
        *out_ops = &g_pipe_ops;
        *out_uri = typed_uri + URI_PREFIX_PIPE_LEN;
    } else if (strstartswith(typed_uri, URI_PREFIX_EVENTFD)) {
        memcpy(out_type, URI_TYPE_EVENTFD, sizeof(URI_TYPE_EVENTFD));
        *out_ops = &g_eventfd_ops;
        *out_uri = typed_uri + URI_PREFIX_EVENTFD_LEN;
    } else if (strstartswith(typed_uri, URI_PREFIX_CONSOLE)) {
        memcpy(out_type, URI_TYPE_CONSOLE, sizeof(URI_TYPE_CONSOLE));
        *out_ops = &g_console_ops;
        *out_uri = typed_uri + URI_PREFIX_CONSOLE_LEN;
    } else if (strstartswith(typed_uri, URI_PREFIX_PIPE_SRV)) {
        memcpy(out_type, URI_TYPE_PIPE_SRV, sizeof(URI_TYPE_PIPE_SRV));
        *out_ops = &g_pipe_ops;
        *out_uri = typed_uri + URI_PREFIX_PIPE_SRV_LEN;
    } else {
        /* unknown handle type */
        return -PAL_ERROR_NOTSUPPORT;
    }
    return 0;
}

int _PalStreamOpen(PAL_HANDLE* handle, const char* typed_uri, enum pal_access access,
                   pal_share_flags_t share, enum pal_create_mode create,
                   pal_stream_options_t options) {
    assert(WITHIN_MASK(share,   PAL_SHARE_MASK));
    assert(WITHIN_MASK(options, PAL_OPTION_MASK));

    char type[URI_PREFIX_MAX_LEN + 1];
    const char* uri;
    struct handle_ops* ops;

    int ret = split_uri_and_find_ops(typed_uri, type, &uri, &ops);
    if (ret < 0)
        return ret;

    assert(ops && ops->open);
    return ops->open(handle, type, uri, access, share, create, options);
}

/*
 * Open stream based on uri (prefixed with type), with given access, share, create and options
 * flags. Returns a PAL handle to the opened stream.
 *
 * FIXME: Currently `share` must match 1-1 to Linux open() `mode` argument. This isn't really
 * portable and will cause problems when implementing other PALs.
 */
int PalStreamOpen(const char* typed_uri, enum pal_access access, pal_share_flags_t share,
                  enum pal_create_mode create, pal_stream_options_t options, PAL_HANDLE* handle) {
    *handle = NULL;
    return _PalStreamOpen(handle, typed_uri, access, share, create, options);
}

static int _PalStreamWaitForClient(PAL_HANDLE handle, PAL_HANDLE* client,
                                   pal_stream_options_t options) {
    if (handle->hdr.type >= PAL_HANDLE_TYPE_BOUND)
        return -PAL_ERROR_BADHANDLE;

    const struct handle_ops* ops = HANDLE_OPS(handle);
    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    if (!ops->waitforclient)
        return -PAL_ERROR_NOTSERVER;

    return ops->waitforclient(handle, client, options);
}

int PalStreamWaitForClient(PAL_HANDLE handle, PAL_HANDLE* client, pal_stream_options_t options) {
    *client = NULL;
    return _PalStreamWaitForClient(handle, client, options);
}

int _PalStreamDelete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    const struct handle_ops* ops = HANDLE_OPS(handle);

    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    if (!ops->delete)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->delete(handle, delete_mode);
}

int PalStreamDelete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    assert(handle);

    return _PalStreamDelete(handle, delete_mode);
}

int64_t _PalStreamRead(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buf) {
    const struct handle_ops* ops = HANDLE_OPS(handle);

    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    if (!ops->read)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->read(handle, offset, count, buf);
}

int PalStreamRead(PAL_HANDLE handle, uint64_t offset, size_t* count, void* buffer) {
    if (!handle) {
        return -PAL_ERROR_INVAL;
    }

    int64_t ret = _PalStreamRead(handle, offset, *count, buffer);

    if (ret < 0) {
        return ret;
    }

    *count = ret;
    return 0;
}

int64_t _PalStreamWrite(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buf) {
    const struct handle_ops* ops = HANDLE_OPS(handle);

    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    if (!ops->write)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->write(handle, offset, count, buf);
}

int PalStreamWrite(PAL_HANDLE handle, uint64_t offset, size_t* count, void* buffer) {
    if (!handle) {
        return -PAL_ERROR_INVAL;
    }

    int64_t ret = _PalStreamWrite(handle, offset, *count, buffer);

    if (ret < 0) {
        return ret;
    }

    *count = ret;
    return 0;
}

int _PalStreamAttributesQuery(const char* typed_uri, PAL_STREAM_ATTR* attr) {
    char type[URI_PREFIX_MAX_LEN + 1];
    const char* uri;
    struct handle_ops* ops;

    int ret = split_uri_and_find_ops(typed_uri, type, &uri, &ops);
    if (ret < 0)
        return ret;

    if (!ops->attrquery)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->attrquery(type, uri, attr);
}

int PalStreamAttributesQuery(const char* typed_uri, PAL_STREAM_ATTR* attr) {
    if (!typed_uri || !attr) {
        return -PAL_ERROR_INVAL;
    }

    PAL_STREAM_ATTR attr_buf;

    int ret = _PalStreamAttributesQuery(typed_uri, &attr_buf);

    if (ret < 0) {
        return ret;
    }

    memcpy(attr, &attr_buf, sizeof(PAL_STREAM_ATTR));
    return 0;
}

/* _PalStreamAttributesQueryByHandle for internal use. Query attribute of streams by their
 *  handle */
int _PalStreamAttributesQueryByHandle(PAL_HANDLE hdl, PAL_STREAM_ATTR* attr) {
    const struct handle_ops* ops = HANDLE_OPS(hdl);

    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    if (!ops->attrquerybyhdl)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->attrquerybyhdl(hdl, attr);
}

int PalStreamAttributesQueryByHandle(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (!handle || !attr) {
        return -PAL_ERROR_INVAL;
    }

    return _PalStreamAttributesQueryByHandle(handle, attr);
}

int PalStreamAttributesSetByHandle(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (!handle || !attr) {
        return -PAL_ERROR_INVAL;
    }

    const struct handle_ops* ops = HANDLE_OPS(handle);
    if (!ops) {
        return -PAL_ERROR_BADHANDLE;
    }

    if (!ops->attrsetbyhdl) {
        return -PAL_ERROR_NOTSUPPORT;
    }

    return ops->attrsetbyhdl(handle, attr);
}

int _PalStreamMap(PAL_HANDLE handle, void* addr, pal_prot_flags_t prot, uint64_t offset,
                  uint64_t size) {
    assert(IS_ALLOC_ALIGNED(offset));
    int ret;

    assert(WITHIN_MASK(prot, PAL_PROT_MASK));

    const struct handle_ops* ops = HANDLE_OPS(handle);

    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    if (!ops->map)
        return -PAL_ERROR_NOTSUPPORT;

    if ((ret = ops->map(handle, addr, prot, offset, size)) < 0)
        return ret;

    return 0;
}

int PalStreamMap(PAL_HANDLE handle, void* addr, pal_prot_flags_t prot, uint64_t offset,
                 size_t size) {
    if (!handle) {
        return -PAL_ERROR_INVAL;
    }

    if (!addr) {
        return -PAL_ERROR_INVAL;
    }

    if (!IS_ALLOC_ALIGNED_PTR(addr)) {
        return -PAL_ERROR_INVAL;
    }

    if (!size || !IS_ALLOC_ALIGNED(size) || !IS_ALLOC_ALIGNED(offset)) {
        return -PAL_ERROR_INVAL;
    }

    return _PalStreamMap(handle, addr, prot, offset, size);
}

/* _PalStreamSetLength for internal use. This function truncate the stream to certain length. This
 *  call might not be support for certain streams */
int64_t _PalStreamSetLength(PAL_HANDLE handle, uint64_t length) {
    const struct handle_ops* ops = HANDLE_OPS(handle);

    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    if (!ops->setlength)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->setlength(handle, length);
}

int PalStreamSetLength(PAL_HANDLE handle, uint64_t length) {
    if (!handle) {
        return -PAL_ERROR_INVAL;
    }

    int64_t ret = _PalStreamSetLength(handle, length);

    if (ret < 0) {
        return ret;
    }

    assert((uint64_t)ret == length);
    return 0;
}

/* _PalStreamFlush for internal use. This function sync up the handle with devices. Some streams may
 *  not support this operations. */
int _PalStreamFlush(PAL_HANDLE handle) {
    if (handle->hdr.type >= PAL_HANDLE_TYPE_BOUND)
        return -PAL_ERROR_BADHANDLE;

    const struct handle_ops* ops = HANDLE_OPS(handle);

    if (!ops)
        return -PAL_ERROR_BADHANDLE;

    if (!ops->flush)
        return -PAL_ERROR_NOTSUPPORT;

    return ops->flush(handle);
}

int PalStreamFlush(PAL_HANDLE handle) {
    if (!handle) {
        return -PAL_ERROR_INVAL;
    }

    return _PalStreamFlush(handle);
}

int PalSendHandle(PAL_HANDLE target_process, PAL_HANDLE cargo) {
    if (!target_process || !cargo) {
        return -PAL_ERROR_INVAL;
    }

    return _PalSendHandle(target_process, cargo);
}

int PalReceiveHandle(PAL_HANDLE source_process, PAL_HANDLE* out_cargo) {
    if (!source_process) {
        return -PAL_ERROR_INVAL;
    }

    *out_cargo = NULL;
    return _PalReceiveHandle(source_process, out_cargo);
}

int PalStreamChangeName(PAL_HANDLE hdl, const char* typed_uri) {
    char type[URI_PREFIX_MAX_LEN + 1];
    const char* uri;
    struct handle_ops* ops;

    int ret = split_uri_and_find_ops(typed_uri, type, &uri, &ops);
    if (ret < 0)
        return ret;

    const struct handle_ops* hops = HANDLE_OPS(hdl);
    if (!hops || !hops->rename || hops != ops)
        return -PAL_ERROR_NOTSUPPORT;

    return hops->rename(hdl, type, uri);
}

int PalDebugLog(const void* buffer, size_t size) {
    return _PalDebugLog(buffer, size);
}
