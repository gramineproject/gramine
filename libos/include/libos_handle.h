/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * Definitions of types and functions for file/handle bookkeeping.
 */

#pragma once

#include <asm/fcntl.h>
#include <asm/resource.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>

#include "libos_defs.h"
#include "libos_fs_mem.h"
#include "libos_lock.h"
#include "libos_pollable_event.h"
#include "libos_refcount.h"
#include "libos_sync.h"
#include "libos_types.h"
#include "linux_socket.h"
#include "list.h"
#include "pal.h"

/* Handle types. Many of these are used by a single filesystem. */
enum libos_handle_type {
    /* Files: */
    TYPE_CHROOT,     /* host files, used by `chroot` filesystem */
    TYPE_CHROOT_ENCRYPTED,
                     /* encrypted host files, used by `chroot_encrypted` filesystem */
    TYPE_DEV,        /* emulated devices, used by `dev` filesystem */
    TYPE_STR,        /* string-based files (with data inside handle), handled by `pseudo_*`
                      * functions */
    TYPE_PSEUDO,     /* pseudo nodes (currently directories), handled by `pseudo_*` functions */
    TYPE_TMPFS,      /* string-based files (with data inside dentry), used by `tmpfs` filesystem */
    TYPE_SYNTHETIC,  /* synthetic files, used by `synthetic` filesystem */
    TYPE_PATH,       /* path to a file (the file is not actually opened) */

    /* Pipes and sockets: */
    TYPE_PIPE,       /* pipes, used by `pipe` filesystem */
    TYPE_SOCK,       /* sockets, used by `socket` filesystem */

    /* Special handles: */
    TYPE_EPOLL,      /* epoll handles, see `libos_epoll.c` */
    TYPE_EVENTFD,    /* eventfd handles, used by `eventfd` filesystem */
};

struct libos_pipe_handle {
    bool ready_for_ops; /* true for pipes, false for FIFOs that were mknod'ed but not open'ed */
    char name[PIPE_URI_SIZE];
};

enum libos_sock_state {
    SOCK_NEW,
    SOCK_BOUND,
    SOCK_CONNECTED,
    SOCK_LISTENING,
};

/*
 * Access to `state`, `remote_addr`, `remote_addrlen`, `local_addr`, `local_addrlen, `last_error`,
 * `sendtimeout_us`, `receivetimeout_us`, `can_be_read`, `can_be_written`, `was_bound`, `reuseaddr`,
 * `reuseport` and `broadcast` are protected by `lock`.
 * `ops`, `domain`, `type` and `protocol` are read-only and do not need any locking.
 * Access to `peek` struct is protected by `recv_lock`. This lock also ensures proper ordering of
 * stream reads (see the comment in `do_recvmsg` in "libos/src/sys/libos_socket.c").
 * Access to `force_nonblocking_users_count` is protected by the lock of the handle wrapping this
 * struct.
 * `pal_handle` should be accessed using atomic operations.
 * If you need to take both `recv_lock` and `lock`, take the former first.
 */
struct libos_sock_handle {
    struct libos_lock lock;
    struct libos_sock_ops* ops;
    /* `pal_handle` can be NULL. Once it's set, it cannot change anymore. All implementations must
     * take into account all necessary settings when instantiating this field, e.g. `handle->flags`,
     * of handle wrapping this struct. */
    PAL_HANDLE pal_handle;
    int domain;
    int type;
    int protocol;
    enum libos_sock_state state;
    struct sockaddr_storage remote_addr;
    size_t remote_addrlen;
    struct sockaddr_storage local_addr;
    size_t local_addrlen;
    struct {
        char* buf;
        size_t buf_size;
        size_t data_size;
    } peek;
    struct libos_lock recv_lock;
    /* This field is only used by UNIX sockets. */
    size_t force_nonblocking_users_count;
    uint64_t sendtimeout_us;
    uint64_t receivetimeout_us;
    unsigned int last_error;
    /* This field denotes whether the socket was ever bound. */
    bool was_bound;
    /* This field indicates if the socket is ready for read-like operations (`recv`/`read` or
     * `accept`, depending on the socket type and state). */
    bool can_be_read;
    /* Same as above but for `send`/`write`. */
    bool can_be_written;
    bool reuseaddr;
    bool reuseport;
    bool broadcast;
};

struct libos_dir_handle {
    /* The first two dentries are always "." and ".." */
    struct libos_dentry** dents;
    size_t count;
};

struct libos_str_handle {
    struct libos_mem_file mem;
};

DEFINE_LISTP(libos_epoll_item);
DEFINE_LISTP(libos_epoll_waiter);
struct libos_epoll_handle {
    /* For details about these fields see `libos_epoll.c`. */
    struct libos_lock lock;
    LISTP_TYPE(libos_epoll_waiter) waiters;
    LISTP_TYPE(libos_epoll_item) items;
    size_t items_count;
    size_t last_returned_index;
};

struct libos_handle {
    enum libos_handle_type type;
    bool is_dir;

    refcount_t ref_count;

    struct libos_fs* fs;
    struct libos_dentry* dentry;

    /*
     * Inode associated with this handle. Currently optional, and only for the use of underlying
     * filesystem (see `libos_inode` in `libos_fs.h`). Eventually, should replace `dentry` fields.
     *
     * This field does not change, so reading it does not require holding `lock`.
     *
     * When taking locks for both handle and inode (`hdl->lock` and `hdl->inode->lock`), you should
     * lock the *inode* first.
     */
    struct libos_inode* inode;

    /* Offset in file. Protected by `pos_lock`. */
    file_off_t pos;

    /* This list contains `libos_epoll_item` objects this handle is part of. All accesses should be
     * protected by `handle->lock`. */
    LISTP_TYPE(libos_epoll_item) epoll_items;
    size_t epoll_items_count;
    /* Only meaningful if the handle is registered in some epoll instance with `EPOLLET` semantics.
     * `false` if it already triggered an `EPOLLIN` event for the current portion of data otherwise
     * `true` and the next `epoll_wait` will consider this handle and report events for it. */
    bool needs_et_poll_in;
    /* Same as above but for `EPOLLOUT` events. */
    bool needs_et_poll_out;

    char* uri; /* PAL URI for this handle (if any). Does not change. */

    PAL_HANDLE pal_handle;

    /* Type-specific fields: when accessing, ensure that `type` field is appropriate first (at least
     * by using assert()) */
    union {
        /* (no data) */                         /* TYPE_CHROOT */
        /* (no data) */                         /* TYPE_CHROOT_ENCRYPTED */
        /* (no data) */                         /* TYPE_DEV */
        struct libos_str_handle str;            /* TYPE_STR */
        /* (no data) */                         /* TYPE_PSEUDO */
        /* (no data) */                         /* TYPE_TMPFS */
        /* (no data) */                         /* TYPE_SYNTHETIC */

        struct libos_pipe_handle pipe;           /* TYPE_PIPE */
        struct libos_sock_handle sock;           /* TYPE_SOCK */

        struct libos_epoll_handle epoll;         /* TYPE_EPOLL */
        struct { bool is_semaphore; } eventfd;   /* TYPE_EVENTFD */
    } info;

    struct libos_dir_handle dir_info;

    /* TODO: the `flags` and `acc_mode` fields contain duplicate information (the access mode).
     * Instead of `flags`, we should have a field with different name (such as `options`) that
     * contain the open flags without access mode (i.e. set it to `flags & ~O_ACCMODE`). */
    int flags; /* Linux' O_* flags */
    int acc_mode;
    struct libos_lock lock;

    /* Lock for handle position (`pos`). Intended for operations that change the position (e.g.
     * `read`, `seek` but not `pread`). This lock should be taken *before* `libos_handle.lock` and
     * `libos_inode.lock`. */
    struct libos_lock pos_lock;

    /* Unique id, works as an identifier for `flock` syscall */
    uint64_t id;
};

/* allocating / manage handle */
struct libos_handle* get_new_handle(void);
void get_handle(struct libos_handle* hdl);
void put_handle(struct libos_handle* hdl);

/* Set handle to non-blocking or blocking mode. */
int set_handle_nonblocking(struct libos_handle* hdl, bool on);

/* file descriptor table */
struct libos_fd_handle {
    uint32_t vfd; /* virtual file descriptor */
    int flags;    /* file descriptor flags, only FD_CLOEXEC */

    struct libos_handle* handle;
};

struct libos_handle_map {
    /* the top of created file descriptors */
    uint32_t fd_size;
    uint32_t fd_top;

    /* refrence count and lock */
    refcount_t ref_count;
    struct libos_lock lock;

    /* An array of file descriptor belong to this mapping */
    struct libos_fd_handle** map;
};

/* allocating file descriptors */
#define FD_NULL                     UINT32_MAX
#define HANDLE_ALLOCATED(fd_handle) ((fd_handle) && (fd_handle)->vfd != FD_NULL)

struct libos_handle* __get_fd_handle(uint32_t fd, int* flags, struct libos_handle_map* map);
struct libos_handle* get_fd_handle(uint32_t fd, int* flags, struct libos_handle_map* map);

/*!
 * \brief Assign new fd to a handle.
 *
 * \param hdl         A handle to be mapped to the new fd.
 * \param flags       Flags assigned to new libos_fd_handle.
 * \param handle_map  Handle map to be used. If NULL is passed, current thread's handle map is used.
 *
 * Creates mapping for the given handle to a new file descriptor which is then returned.
 * Uses the lowest, non-negative available number for the new fd.
 */
int set_new_fd_handle(struct libos_handle* hdl, int fd_flags, struct libos_handle_map* map);
int set_new_fd_handle_by_fd(uint32_t fd, struct libos_handle* hdl, int fd_flags,
                            struct libos_handle_map* map);
int set_new_fd_handle_above_fd(uint32_t fd, struct libos_handle* hdl, int fd_flags,
                               struct libos_handle_map* map);
struct libos_handle* __detach_fd_handle(struct libos_fd_handle* fd, int* flags,
                                        struct libos_handle_map* map);
struct libos_handle* detach_fd_handle(uint32_t fd, int* flags, struct libos_handle_map* map);
void detach_all_fds(void);
void close_cloexec_handles(struct libos_handle_map* map);

/* manage handle mapping */
int dup_handle_map(struct libos_handle_map** new_map, struct libos_handle_map* old_map);
void get_handle_map(struct libos_handle_map* map);
void put_handle_map(struct libos_handle_map* map);
int walk_handle_map(int (*callback)(struct libos_fd_handle*, struct libos_handle_map*),
                    struct libos_handle_map* map);

int init_handle(void);
int init_std_handles(void);
int init_exec_handle(const char* const* argv, char*** out_new_argv);

int open_executable(struct libos_handle* hdl, const char* path);

int get_file_size(struct libos_handle* file, uint64_t* size);

ssize_t do_handle_read(struct libos_handle* hdl, void* buf, size_t count);
ssize_t do_handle_write(struct libos_handle* hdl, const void* buf, size_t count);
