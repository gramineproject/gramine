/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Labs */

/*
 * Secret Prov user API:
 *   - secret_provision_start() and secret_provision_get() for attester (SGX enclave, also called
 *     "client") side,
 *   - secret_provision_start_server() for verifier (also called "server") side,
 *   - secret_provision_write(), secret_provision_read() and secret_provision_close() for both
 *     sides.
 */

#pragma once

#include <stdint.h>

/* envvars for client (attester) */
#define SECRET_PROVISION_CONSTRUCTOR    "SECRET_PROVISION_CONSTRUCTOR"
#define SECRET_PROVISION_CA_CHAIN_PATH  "SECRET_PROVISION_CA_CHAIN_PATH"
#define SECRET_PROVISION_SERVERS        "SECRET_PROVISION_SERVERS"
#define SECRET_PROVISION_SECRET_STRING  "SECRET_PROVISION_SECRET_STRING"
#define SECRET_PROVISION_SET_KEY        "SECRET_PROVISION_SET_KEY"
#define SECRET_PROVISION_SET_PF_KEY     "SECRET_PROVISION_SET_PF_KEY"

/* envvars for server (verifier) */
#define SECRET_PROVISION_LISTENING_PORT "SECRET_PROVISION_LISTENING_PORT"

/* internal secret-provisioning protocol message format */
#define SECRET_PROVISION_REQUEST  "SECRET_PROVISION_RA_TLS_REQUEST_V1"
#define SECRET_PROVISION_RESPONSE "SECRET_PROVISION_RA_TLS_RESPONSE_V1:" // 8B secret size follows

#define DEFAULT_SERVERS "localhost:4433"

struct ra_tls_ctx;

typedef int (*verify_measurements_cb_t)(const char* mrenclave, const char* mrsigner,
                                        const char* isv_prod_id, const char* isv_svn);

typedef int (*secret_provision_cb_t)(struct ra_tls_ctx* ctx);

/*!
 * \brief Write arbitrary data in an established RA-TLS session.
 *
 * \param ctx   Established RA-TLS session, obtained from secret_provision_start() or in
 *              secret_provision_cb_t() callback.
 * \param buf   Buffer with arbitrary data to write.
 * \param size  Size of buffer.
 *
 * \returns 0 on success, specific error code (negative int) otherwise.
 *
 * This function can be called after an RA-TLS session is established via client-side call to
 * secret_provision_start() or in the server-side callback secret_provision_cb_t().
 *
 * This function always writes all \p size bytes on success (partial writes are not possible).
 */
int secret_provision_write(struct ra_tls_ctx* ctx, const uint8_t* buf, size_t size);

/*!
 * \brief Read arbitrary data in an established RA-TLS session.
 *
 * \param      ctx   Established RA-TLS session, obtained from secret_provision_start() or in
 *                   secret_provision_cb_t() callback.
 * \param[out] buf   Buffer with arbitrary data to read.
 * \param      size  Size of buffer.
 *
 * \returns 0 on success, specific error code (negative int) otherwise.
 *
 * This function can be called after an RA-TLS session is established via client-side call to
 * secret_provision_start() or in the server-side callback secret_provision_cb_t().
 *
 * This function always reads all \p size bytes on success (partial reads are not possible).
 */
int secret_provision_read(struct ra_tls_ctx* ctx, uint8_t* buf, size_t size);

/*!
 * \brief Close an established RA-TLS session and its associated secret.
 *
 * \param ctx  Established RA-TLS session.
 *
 * \returns 0 on success, specific error code (negative int) otherwise.
 *
 * This function can be called after an RA-TLS session is established via client-side call to
 * secret_provision_start(). Typically, application-specific protocol to provision secrets is
 * implemented via secret_provision_read() and secret_provision_write(), and this function is called
 * to finish secret provisioning.
 *
 * This function zeroes out the memory where provisioned secret is stored and frees it.
 *
 * This function must not be called again even if it returned an error. \p ctx is always freed.
 */
int secret_provision_close(struct ra_tls_ctx* ctx);

/*!
 * \brief Get a copy of the provisioned secret.
 *
 * \param      ctx              Established RA-TLS session.
 * \param[out] out_secret       Pointer to newly allocated buffer with secret.
 * \param[out] out_secret_size  Size of allocated buffer.
 *
 * \returns 0 on success, specific error code (negative int) otherwise.
 *
 * This function is relevant only for clients. Typically, the client would ask for secret
 * provisioning via secret_provision_start() which will obtain the secret from the server and
 * save it in enclave memory. After that, the client can call this function to retrieve the
 * copy of the secret from memory. Content of \p out_secret is dynamically allocated and should be
 * released using `free(*out_secret)`.
 */
int secret_provision_get(struct ra_tls_ctx* ctx, uint8_t** out_secret, size_t* out_secret_size);

/*!
 * \brief Establish an RA-TLS session and retrieve first secret (client-side).
 *
 * \param     in_servers        List of servers (in format "server1:port1;server2:port2;..."). If
 *                              not specified, environment variable `SECRET_PROVISION_SERVERS` is
 *                              used. If the environment variable is also not specified, default
 *                              value is used.
 * \param     in_ca_chain_path  Path to the CA chain to verify the server. If not specified,
 *                              environment variable `SECRET_PROVISION_CA_CHAIN_PATH` is used. If
 *                              the environment variable is also not specified, function returns
 *                              with error code EINVAL.
 * \param[out] out_ctx          Pointer to an established RA-TLS session. Cannot be NULL.
 *
 * \returns 0 on success, specific error code (negative int) otherwise.
 *
 * This function must be called before other functions. It establishes a secure RA-TLS session
 * with the first available server from the \p in_servers list and retrieves the first secret.
 *
 * The user can continue this secure session with the server via secret_provision_read() and
 * secret_provision_write(). The user must finish the session by calling secret_provision_close().
 *
 * The first secret can be retrieved via secret_provision_get(). The secret is destroyed together
 * with the session during secret_provision_close().
 */
int secret_provision_start(const char* in_servers, const char* in_ca_chain_path,
                           struct ra_tls_ctx** out_ctx);

/*!
 * \brief Start a secret provisioning service (server-side).
 *
 * \param secret       First secret (arbitrary binary blob) to send to client after establishing
 *                     RA-TLS session.
 * \param secret_size  Size of first secret.
 * \param port         Listening port of the server.
 * \param cert_path    Path to X.509 certificate of the server.
 * \param key_path     Path to private key of the server.
 * \param m_cb         Callback for user-specific verification of measurements in client's SGX
 *                     quote. If user supplies NULL, then default logic of RA-TLS is invoked.
 * \param f_cb         Callback for user-specific communication with the client, e.g., to send
 *                     more secrets. If user supplies NULL, then only the first secret is sent
 *                     to the client and the RA-TLS session is closed.
 *
 * \returns 0 on success, specific error code (negative int) otherwise.
 *
 * This function starts a multi-threaded secret provisioning server. It listens to client
 * connections on \p port. For each new client, it spawns a new thread in which the RA-TLS
 * mutually-attested session is established. The server provides a normal X.509 certificate to the
 * client (initialized with \p cert_path and \p key_path). The server expects a self-signed RA-TLS
 * certificate from the client. During TLS handshake, the server invokes a user-supplied callback
 * m_cb() for user-specific verification of measurements in client's SGX quote (if user supplied
 * it). After successfuly establishing the RA-TLS session and sending the first secret \p secret,
 * the server invokes a user-supplied callback f_cb() for user-specific communication with the
 * client (if user supplied it).
 *
 * This function is thread-safe and requires pthread library.
 */
int secret_provision_start_server(uint8_t* secret, size_t secret_size, const char* port,
                                  const char* cert_path, const char* key_path,
                                  verify_measurements_cb_t m_cb, secret_provision_cb_t f_cb);
