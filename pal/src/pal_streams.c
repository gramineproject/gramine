/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to open, read, write and get attribute of streams.
 */

#include "api.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"

/* Stream handler table: this table corresponds to all the handle type supported by PAL. Threads
 * are not streams, so they need no handler. Sockets have their own table. */
extern struct handle_ops g_file_ops;
extern struct handle_ops g_pipe_ops;
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
    [PAL_TYPE_DEV]     = &g_dev_ops,
    [PAL_TYPE_DIR]     = &g_dir_ops,
    [PAL_TYPE_PROCESS] = &g_proc_ops,
    [PAL_TYPE_THREAD]  = &g_thread_ops,
    [PAL_TYPE_EVENT]   = &g_event_ops,
    [PAL_TYPE_EVENTFD] = &g_eventfd_ops,
};

/* parse_stream_uri scan the uri, seperate prefix and search for
   stream handler which will open or access the stream */
static int parse_stream_uri(const char** uri, char** prefix, struct handle_ops** ops) {
    const char* p;
    const char* u = *uri;

    for (p = u; (*p) && (*p) != ':'; p++)
        ;

    if ((*p) != ':')
        return -PAL_ERROR_INVAL;

    ++p;

    struct handle_ops* hops = NULL;

    switch (p - u) {
        case 4: ;
            static_assert(static_strlen(URI_PREFIX_DIR) == 4, "URI_PREFIX_DIR has unexpected length");
            static_assert(static_strlen(URI_PREFIX_DEV) == 4, "URI_PREFIX_DEV has unexpected length");

            if (strstartswith(u, URI_PREFIX_DIR))
                hops = &g_dir_ops;
            else if (strstartswith(u, URI_PREFIX_DEV))
                hops = &g_dev_ops;
            break;

        case 5: ;
            static_assert(static_strlen(URI_PREFIX_FILE) == 5, "URI_PREFIX_FILE has unexpected length");
            static_assert(static_strlen(URI_PREFIX_PIPE) == 5, "URI_PREFIX_PIPE has unexpected length");

            if (strstartswith(u, URI_PREFIX_FILE))
                hops = &g_file_ops;
            else if (strstartswith(u, URI_PREFIX_PIPE))
                hops = &g_pipe_ops;
            break;

        case 8: ;
            static_assert(static_strlen(URI_PREFIX_EVENTFD) == 8, "URI_PREFIX_EVENTFD has unexpected length");

            if (strstartswith(u, URI_PREFIX_EVENTFD))
                hops = &g_eventfd_ops;
            break;

        case 9: ;
            static_assert(static_strlen(URI_PREFIX_PIPE_SRV) == 9, "URI_PREFIX_PIPE_SRV has unexpected length");

            if (strstartswith(u, URI_PREFIX_PIPE_SRV))
                hops = &g_pipe_ops;
            break;

        default:
            break;
    }

    if (!hops)
        return -PAL_ERROR_NOTSUPPORT;

    *uri = p;

    if (prefix) {
        *prefix = malloc_copy(u, p - u);
        if (!*prefix)
            return -PAL_ERROR_NOMEM;
        /* We don't want ':' in prefix, replacing that with nullbyte which also ends the string. */
        (*prefix)[p - 1 - u] = '\0';
    }

    if (ops)
        *ops = hops;

    return 0;
}

int _PalStreamOpen(PAL_HANDLE* handle, const char* uri, enum pal_access access,
                   pal_share_flags_t share, enum pal_create_mode create,
                   pal_stream_options_t options) {
    struct handle_ops* ops = NULL;
    char* type = NULL;

    assert(WITHIN_MASK(share,   PAL_SHARE_MASK));
    assert(WITHIN_MASK(options, PAL_OPTION_MASK));

    int ret = parse_stream_uri(&uri, &type, &ops);
    if (ret < 0)
        return ret;

    assert(ops && ops->open);
    ret = ops->open(handle, type, uri, access, share, create, options);
    free(type);
    return ret;
}

/* PAL call PalStreamOpen: Open stream based on uri, as given access/share/
 * create/options flags. PalStreamOpen return a PAL_HANDLE to access the
 * stream in `handle` argument.
 *
 * FIXME: Currently `share` must match 1-1 to Linux open() `mode` argument. This isn't really
 * portable and will cause problems when implementing other PALs.
 */
int PalStreamOpen(const char* uri, enum pal_access access, pal_share_flags_t share,
                  enum pal_create_mode create, pal_stream_options_t options, PAL_HANDLE* handle) {
    *handle = NULL;
    return _PalStreamOpen(handle, uri, access, share, create, options);
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

/* _PalStreamAttributesQuery of internal use. The function query attribute of streams by their
 *  URI */
int _PalStreamAttributesQuery(const char* uri, PAL_STREAM_ATTR* attr) {
    struct handle_ops* ops = NULL;
    char* type = NULL;

    int ret = parse_stream_uri(&uri, &type, &ops);
    if (ret < 0)
        return ret;

    if (!ops->attrquery) {
        ret = -PAL_ERROR_NOTSUPPORT;
        goto out;
    }

    ret = ops->attrquery(type, uri, attr);
out:
    free(type);
    return ret;
}

int PalStreamAttributesQuery(const char* uri, PAL_STREAM_ATTR* attr) {
    if (!uri || !attr) {
        return -PAL_ERROR_INVAL;
    }

    PAL_STREAM_ATTR attr_buf;

    int ret = _PalStreamAttributesQuery(uri, &attr_buf);

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

int PalStreamUnmap(void* addr, size_t size) {
    if (!addr || !IS_ALLOC_ALIGNED_PTR(addr) || !size || !IS_ALLOC_ALIGNED(size)) {
        return -PAL_ERROR_INVAL;
    }

    return _PalStreamUnmap(addr, size);
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

int PalStreamChangeName(PAL_HANDLE hdl, const char* uri) {
    struct handle_ops* ops = NULL;
    char* type = NULL;
    int ret;

    if (uri) {
        ret = parse_stream_uri(&uri, &type, &ops);
        if (ret < 0) {
            return ret;
        }
    }

    const struct handle_ops* hops = HANDLE_OPS(hdl);

    if (!hops || !hops->rename || (ops && hops != ops)) {
        ret = -PAL_ERROR_NOTSUPPORT;
        goto out;
    }

    ret = hops->rename(hdl, type, uri);
out:
    free(type);
    return ret;
}

int PalDebugLog(const void* buffer, size_t size) {
    return _PalDebugLog(buffer, size);
}
