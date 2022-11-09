/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This file provides functions for dealing with outgoing IPC connections, mainly sending IPC
 * messages.
 */

#include <stdbool.h>
#include <stdint.h>

#include "api.h"
#include "assert.h"
#include "avl_tree.h"
#include "libos_checkpoint.h"
#include "libos_internal.h"
#include "libos_ipc.h"
#include "libos_lock.h"
#include "libos_refcount.h"
#include "libos_types.h"
#include "libos_utils.h"
#include "pal.h"

struct libos_ipc_connection {
    struct avl_tree_node node;
    IDTYPE vmid;
    int seen_error;
    refcount_t ref_count;
    PAL_HANDLE handle;
    /* This lock guards concurrent accesses to `handle` and `seen_error`. If you need both this lock
     * and `g_ipc_connections_lock`, take the latter first. */
    struct libos_lock lock;
};

static bool ipc_connection_cmp(struct avl_tree_node* _a, struct avl_tree_node* _b) {
    struct libos_ipc_connection* a = container_of(_a, struct libos_ipc_connection, node);
    struct libos_ipc_connection* b = container_of(_b, struct libos_ipc_connection, node);
    return a->vmid <= b->vmid;
}

/* Tree of outgoing IPC connections, to be accessed only with `g_ipc_connections_lock` taken. */
static struct avl_tree g_ipc_connections = { .cmp = ipc_connection_cmp };
static struct libos_lock g_ipc_connections_lock;

struct ipc_msg_waiter {
    struct avl_tree_node node;
    PAL_HANDLE event;
    uint64_t seq;
    IDTYPE dest;
    void* response_data;
};

static bool ipc_msg_waiter_cmp(struct avl_tree_node* _a, struct avl_tree_node* _b) {
    struct ipc_msg_waiter* a = container_of(_a, struct ipc_msg_waiter, node);
    struct ipc_msg_waiter* b = container_of(_b, struct ipc_msg_waiter, node);
    return a->seq <= b->seq;
}

static struct avl_tree g_msg_waiters_tree = { .cmp = ipc_msg_waiter_cmp };
static struct libos_lock g_msg_waiters_tree_lock;

struct libos_ipc_ids g_process_ipc_ids;

int init_ipc(void) {
    if (!create_lock(&g_ipc_connections_lock)) {
        return -ENOMEM;
    }
    if (!create_lock(&g_msg_waiters_tree_lock)) {
        return -ENOMEM;
    }

    return init_ipc_ids();
}

static void get_ipc_connection(struct libos_ipc_connection* conn) {
    refcount_inc(&conn->ref_count);
}

static void put_ipc_connection(struct libos_ipc_connection* conn) {
    refcount_t ref_count = refcount_dec(&conn->ref_count);

    if (!ref_count) {
        PalObjectClose(conn->handle);
        destroy_lock(&conn->lock);
        free(conn);
    }
}

static struct libos_ipc_connection* node2conn(struct avl_tree_node* node) {
    if (!node) {
        return NULL;
    }
    return container_of(node, struct libos_ipc_connection, node);
}

static int ipc_connect(IDTYPE dest, struct libos_ipc_connection** conn_ptr) {
    struct libos_ipc_connection dummy = { .vmid = dest };
    int ret = 0;

    lock(&g_ipc_connections_lock);
    struct libos_ipc_connection* conn = node2conn(avl_tree_find(&g_ipc_connections, &dummy.node));
    if (!conn) {
        conn = calloc(1, sizeof(*conn));
        if (!conn) {
            ret = -ENOMEM;
            goto out;
        }
        if (!create_lock(&conn->lock)) {
            ret = -ENOMEM;
            goto out;
        }

        char uri[PIPE_URI_SIZE];
        if (vmid_to_uri(dest, uri, sizeof(uri)) < 0) {
            log_error("buffer for IPC pipe URI too small");
            BUG();
        }
        do {
            ret = PalStreamOpen(uri, PAL_ACCESS_RDONLY, /*share_flags=*/0, PAL_CREATE_IGNORED,
                                /*options=*/0, &conn->handle);
        } while (ret == -PAL_ERROR_INTERRUPTED);
        if (ret < 0) {
            ret = pal_to_unix_errno(ret);
            goto out;
        }
        ret = write_exact(conn->handle, &g_process_ipc_ids.self_vmid,
                          sizeof(g_process_ipc_ids.self_vmid));
        if (ret < 0) {
            goto out;
        }

        conn->vmid = dest;
        refcount_set(&conn->ref_count, 1);
        avl_tree_insert(&g_ipc_connections, &conn->node);
    }

    get_ipc_connection(conn);
    *conn_ptr = conn;
    conn = NULL;
    ret = 0;

out:
    if (conn) {
        if (lock_created(&conn->lock)) {
            destroy_lock(&conn->lock);
        }
        if (conn->handle) {
            PalObjectClose(conn->handle);
        }
        free(conn);
    }
    unlock(&g_ipc_connections_lock);
    return ret;
}

static void _remove_ipc_connection(struct libos_ipc_connection* conn) {
    assert(locked(&g_ipc_connections_lock));
    avl_tree_delete(&g_ipc_connections, &conn->node);
    put_ipc_connection(conn);
}

int connect_to_process(IDTYPE dest) {
    struct libos_ipc_connection* conn = NULL;
    int ret = ipc_connect(dest, &conn);
    if (ret < 0) {
        return ret;
    }
    put_ipc_connection(conn);
    return 0;
}

void remove_outgoing_ipc_connection(IDTYPE dest) {
    struct libos_ipc_connection dummy = { .vmid = dest };
    lock(&g_ipc_connections_lock);
    struct libos_ipc_connection* conn = node2conn(avl_tree_find(&g_ipc_connections, &dummy.node));
    if (conn) {
        _remove_ipc_connection(conn);
    }
    unlock(&g_ipc_connections_lock);

    lock(&g_msg_waiters_tree_lock);
    struct avl_tree_node* node = avl_tree_first(&g_msg_waiters_tree);
    /* Usually there are no or very few waiters, so linear loop should be fine. If this becomes
     * a problem for some reason, we can make `g_msg_waiters_tree` use `dest` as a part of the key
     * and search for matching entries here. */
    while (node) {
        struct ipc_msg_waiter* waiter = container_of(node, struct ipc_msg_waiter, node);
        if (waiter->dest == dest) {
            waiter->response_data = NULL;
            PalEventSet(waiter->event);
            log_debug("Woke up a thread waiting for a message from a disconnected process");
        }
        node = avl_tree_next(node);
    }
    unlock(&g_msg_waiters_tree_lock);
}

void init_ipc_msg(struct libos_ipc_msg* msg, unsigned char code, size_t size) {
    SET_UNALIGNED(msg->header.size, size);
    SET_UNALIGNED(msg->header.seq, 0ul);
    SET_UNALIGNED(msg->header.code, code);
}

void init_ipc_response(struct libos_ipc_msg* msg, uint64_t seq, size_t size) {
    init_ipc_msg(msg, IPC_MSG_RESP, size);
    SET_UNALIGNED(msg->header.seq, seq);
}

static int ipc_send_message_to_conn(struct libos_ipc_connection* conn, struct libos_ipc_msg* msg) {
    log_debug("Sending ipc message to %u", conn->vmid);

    int ret = 0;
    lock(&conn->lock);
    if (conn->seen_error) {
        ret = conn->seen_error;
        log_debug("returning previously seen error: %s", unix_strerror(ret));
        goto out;
    }

    ret = write_exact(conn->handle, msg,  GET_UNALIGNED(msg->header.size));
    if (ret < 0) {
        log_error("Failed to send IPC msg to %u: %s", conn->vmid, unix_strerror(ret));
        conn->seen_error = ret;
        goto out;
    }

out:
    unlock(&conn->lock);
    return ret;
}

int ipc_send_message(IDTYPE dest, struct libos_ipc_msg* msg) {
    struct libos_ipc_connection* conn = NULL;
    int ret = ipc_connect(dest, &conn);
    if (ret < 0) {
        return ret;
    }

    ret = ipc_send_message_to_conn(conn, msg);
    put_ipc_connection(conn);
    return ret;
}

static int wait_for_response(struct ipc_msg_waiter* waiter) {
    log_debug("Waiting for a response to %lu", waiter->seq);

    int ret = 0;
    do {
        ret = PalEventWait(waiter->event, /*timeout=*/NULL);
    } while (ret == -PAL_ERROR_INTERRUPTED);

    log_debug("Waiting finished: %s", pal_strerror(ret));
    return pal_to_unix_errno(ret);
}

int ipc_send_msg_and_get_response(IDTYPE dest, struct libos_ipc_msg* msg, void** resp) {
    static uint64_t ipc_seq_counter = 1;
    uint64_t seq = __atomic_fetch_add(&ipc_seq_counter, 1, __ATOMIC_RELAXED);
    SET_UNALIGNED(msg->header.seq, seq);

    struct ipc_msg_waiter waiter = {
        .seq = seq,
        .dest = dest,
        .response_data = NULL,
    };
    int ret = PalEventCreate(&waiter.event, /*init_signaled=*/false, /*auto_clear=*/false);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    lock(&g_msg_waiters_tree_lock);
    avl_tree_insert(&g_msg_waiters_tree, &waiter.node);
    unlock(&g_msg_waiters_tree_lock);

    ret = ipc_send_message(dest, msg);
    if (ret < 0) {
        goto out;
    }

    ret = wait_for_response(&waiter);
    if (ret < 0) {
        goto out;
    }

    if (!waiter.response_data) {
        log_warning("IPC recipient %u died while we were waiting for a message response", dest);
        ret = -ESRCH;
    } else {
        if (resp) {
            /* We take the ownership of `waiter.response_data`. */
            *resp = waiter.response_data;
            waiter.response_data = NULL;
        }
        ret = 0;
    }

out:
    lock(&g_msg_waiters_tree_lock);
    avl_tree_delete(&g_msg_waiters_tree, &waiter.node);
    unlock(&g_msg_waiters_tree_lock);
    free(waiter.response_data);
    PalObjectClose(waiter.event);
    return ret;
}

int ipc_response_callback(IDTYPE src, void* data, uint64_t seq) {
    int ret = 0;
    if (!seq) {
        log_error("Got an IPC response without a sequence number");
        ret = -EINVAL;
        goto out;
    }

    lock(&g_msg_waiters_tree_lock);
    struct ipc_msg_waiter dummy = {
        .seq = seq,
    };
    struct avl_tree_node* node = avl_tree_find(&g_msg_waiters_tree, &dummy.node);
    if (!node) {
        log_error("No thread is waiting for a response with seq: %lu", seq);
        ret = -EINVAL;
        goto out_unlock;
    }

    struct ipc_msg_waiter* waiter = container_of(node, struct ipc_msg_waiter, node);
    waiter->response_data = data;
    PalEventSet(waiter->event);
    ret = 0;
    log_debug("Got an IPC response from %u, seq: %lu", src, seq);

out_unlock:
    unlock(&g_msg_waiters_tree_lock);
out:
    if (ret < 0) {
        free(data);
    }
    return ret;
}

int ipc_broadcast(struct libos_ipc_msg* msg, IDTYPE exclude_id) {
    lock(&g_ipc_connections_lock);
    struct libos_ipc_connection* conn = node2conn(avl_tree_first(&g_ipc_connections));

    int main_ret = 0;
    while (conn) {
        if (conn->vmid != exclude_id) {
            int ret = ipc_send_message_to_conn(conn, msg);
            if (!main_ret) {
                main_ret = ret;
            }
        }
        conn = node2conn(avl_tree_next(&conn->node));
    }

    unlock(&g_ipc_connections_lock);
    return main_ret;
}

BEGIN_CP_FUNC(process_ipc_ids) {
    __UNUSED(size);
    __UNUSED(objp);
    assert(size == sizeof(struct libos_ipc_ids));

    struct libos_ipc_ids* ipc_ids = (struct libos_ipc_ids*)obj;

    size_t off = ADD_CP_OFFSET(sizeof(*ipc_ids));
    ADD_CP_FUNC_ENTRY(off);

    *(struct libos_ipc_ids*)(base + off) = *ipc_ids;
}
END_CP_FUNC(process_ipc_ids)

BEGIN_RS_FUNC(process_ipc_ids) {
    __UNUSED(offset);
    __UNUSED(rebase);
    struct libos_ipc_ids* ipc_ids = (void*)(base + GET_CP_FUNC_ENTRY());

    g_process_ipc_ids = *ipc_ids;
}
END_RS_FUNC(process_ipc_ids)
