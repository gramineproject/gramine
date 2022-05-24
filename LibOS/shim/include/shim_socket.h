/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "linux_socket.h"
#include "shim_handle.h"

#define SHIM_SOCK_MAX_PENDING_CONNS 4096

struct shim_sock_ops {
    /*!
     * \brief Verify the socket handle and initialize type specific fields.
     *
     * This callback assumes that \p handle is already correctly initialized.
     */
    int (*create)(struct shim_handle* handle);

    /*!
     * \brief Bind the handle to an address.
     *
     * Must be called with `handle->info.sock.lock` taken.
     */
    int (*bind)(struct shim_handle* handle, void* addr, size_t addrlen);

    /*!
     * \brief Set handle into listening mode.
     *
     * Must be called with `handle->info.sock.lock` taken.
     */
    int (*listen)(struct shim_handle* handle, unsigned int backlog);

    /*!
     * \brief Accept a connection on a listening handle.
     *
     * \param handle           Handle in listening mode.
     * \param is_nonblocking   `true` if the new handle is to be set in nonblocking mode.
     * \param[out] client_ptr  On success contains the new handle.
     *
     * This callback is called without any locks and must support concurrent calls.
     */
    int (*accept)(struct shim_handle* handle, bool is_nonblocking, struct shim_handle** out_client);

    /*!
     * \brief Connect the handle to a remote address.
     *
     * Must be called with `handle->info.sock.lock` taken.
     */
    int (*connect)(struct shim_handle* handle, void* addr, size_t addrlen);

    /*!
     * \brief Disconnect a previously connected handle.
     *
     * Must be called with `handle->info.sock.lock` taken.
     */
    int (*disconnect)(struct shim_handle* handle);

    /*!
     * \brief Get a socket option.
     *
     * Must be called with `handle->info.sock.lock` taken.
     */
    int (*getsockopt)(struct shim_handle* handle, int level, int optname, void* optval,
                      size_t* len);

    /*!
     * \brief Set a socket option.
     *
     * Must be called with `handle->info.sock.lock` taken.
     */
    int (*setsockopt)(struct shim_handle* handle, int level, int optname, void* optval,
                      size_t len);

    /*!
     * \brief Send array of buffers as continuous data.
     *
     * \param      handle    Handle.
     * \param      iov       Array of buffers to write from.
     * \param      iov_len   Length of \p iov.
     * \param[out] out_size  On success contains the number of bytes sent.
     * \param      addr      Address to send to. May be NULL.
     * \param      addrlen   Length of \p addr.
     */
    int (*send)(struct shim_handle* handle, struct iovec* iov, size_t iov_len, size_t* out_size,
                void* addr, size_t addrlen);

    /*!
     * \brief Receive continuous data into an array of buffers.
     *
     * \param         handle          Handle.
     * \param         iov             Array of buffers to read to.
     * \param         iov_len         Length of \p iov.
     * \param[out]    out_size        On success contains the number of bytes sent.
     * \param[out]    addr            On success contains the address data was received from. May
     *                                be NULL.
     * \param[in,out] addrlen         Length of \p addr. On success updated to the actual length of
     *                                the address. Bigger than original value indicates that
     *                                truncation has happened.
     * \param         is_nonblocking  If `true` this request should not block. Otherwise just use
     *                                whatever mode the handle is in.
     */
    int (*recv)(struct shim_handle* handle, struct iovec* iov, size_t iov_len, size_t* out_size,
                void* addr, size_t* addrlen, bool is_nonblocking);
};

extern struct shim_sock_ops sock_unix_ops;
extern struct shim_sock_ops sock_ip_ops;

ssize_t do_recvmsg(struct shim_handle* handle, struct iovec* iov, size_t iov_len, void* addr,
                   size_t* addrlen, unsigned int flags);
ssize_t do_sendmsg(struct shim_handle* handle, struct iovec* iov, size_t iov_len, void* addr,
                   size_t addrlen, unsigned int flags);
