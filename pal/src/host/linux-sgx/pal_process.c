/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This source file contains functions to create a child process and terminate the running process.
 * Child does not inherit any objects or memory from its parent process. A parent process may not
 * modify the execution of its children. It can wait for a child to exit using its handle. Also,
 * parent and child may communicate through I/O streams provided by the parent to the child at
 * creation.
 */

#include "api.h"
#include "crypto.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_error.h"

/*
 * For SGX, the creation of a child process requires a clean enclave and a secure channel between
 * the parent and child processes (enclaves). The establishment of the secure channel must be
 * resilient to a host-level, root-privilege adversary. Such an adversary can either create
 * arbitrary enclaves, or intercept the handshake protocol between the parent and child enclaves to
 * launch a man-in-the-middle attack.
 *
 * The below protocol combines unauthenticated Diffie-Hellman Key Exchange (DHKE) with the SGX local
 * attestation (this combination provides authenticated DHKE). The protocol is a modified ISO KE
 * protocol (as described in Section 4 of the "SIGMA: the `SIGn-and-MAc` Approach to Authenticated
 * Diffie-Hellman and its Use in the IKE Protocols" paper from Hugo Krawczyk). The ISO KE protocol
 * does not support the "identity protection" feature; this feature is however useless in the SGX
 * local attestation threat model (malicious host knows identities of all running SGX enclaves
 * anyway). The ISO KE protocol is proven to be secure and minimal.
 *
 * One difference of the below protocol from the original ISO KE protocol is the notion of
 * "identity". In SGX local attestation, identity of an enclave is a combination of its
 * measurements: mrenclave, attributes, configsvn, etc. This enclave identity is enclosed in the SGX
 * targetinfo struct as well as in the SGX report. Thus, we use SGX targetinfo and SGX report as
 * identities. Note that in Gramine all child enclaves spawned from one parent enclave have the same
 * SGX targetinfo (same as the parent).
 *
 * One more difference is that instead of calculating SHA256(g_x || g_y) for enclave A and
 * SHA256(g_y || g_x) for enclave B, our protocol calculates SHA256(K_e || tag1) for enclave A and
 * SHA256(K_e || tag2) for enclave B. Note that K_e is the established session key, and tag1/tag2
 * are additional tags to produce different hashes in enclaves A and B. This hashing scheme still
 * introduces assymetry in the protocol (desired to prevent reflection and interleaving attacks),
 * but is more robust to future modifications.
 *
 * Final difference is CMAC used in SGX local attestation for SGX report validation, instead of the
 * signatures in the original ISO KE protocol. This CMAC however provides the same security
 * guarantees because it is generated over the SGX report that contains the target identity of the
 * peer enclave, thus it corresponds to the "directed signature from B to A" in ISO KE.
 *
 * Note that Gramine does *not* use the SIGMA-like protocol (used in e.g. Intel SGX SDK). SIGMA
 * family of protocols is an enhancement over ISO KE to add the "identity protection" feature, which
 * is irrelevant for SGX local attestation. Thus, Gramine chooses a simpler protocol.
 *
 * Prerequisites of a secure channel:
 *
 * (1) A session key needs to be shared only between the parent and child enclaves.
 *
 *       See the implementation in _PalStreamKeyExchange(). When initializing a secure stream, both
 *       ends of the stream needs to use Diffie-Hellman to establish a session key. The hashes over
 *       the established DH session key are used to identify the connection (via SHA256(K_e || tag1)
 *       for parent enclave A and via SHA256(K_e || tag2) for child enclave B to prevent
 *       man-in-the-middle/interleaving attacks) as well as to derive other session keys, e.g., to
 *       encrypt pipes for secure IPC.
 *
 * (2) Both the parent and child enclaves need to be proven by the Intel CPU.
 *
 *       See the implementation in _PalStreamReportRequest() and _PalStreamReportRespond(). The two
 *       ends of the stream need to exchange SGX local attestation reports signed by the Intel CPUs
 *       to prove themselves to be running inside enclaves on the same platform. The local
 *       attestation reports contain no secret information and can be verified cryptographically,
 *       and can be sent on an unencrypted channel.
 *
 *       The flow of local attestation is as follows:
 *         - Child:  Generate report(Child -> Parent) and send to Parent
 *         - Parent: Verify report(Child -> Parent)
 *         - Parent: Generate report(Parent -> Child)
 *         - Child:  Verify report(Parent -> Child)
 *
 *       Note that both Parent and Child have the same SGX target info.
 *
 * (3) Both the parent and child enclaves need to have matching measurements.
 *
 *       All Gramine enclaves with the same configuration (manifest) and same Gramine (LibOS, PAL)
 *       binaries should have the same measurement. During initialization, it's decided based on
 *       input from untrusted PAL, whether a particular enclave will become a leader of a new
 *       Gramine namespace, or will wait on a pipe for some parent enclave connection.
 *
 * (4) The two parties who create the session key need to be the ones proven by the CPU
 *     (for preventing man-in-the-middle attacks).
 *
 *       See the implementation in is_peer_enclave_ok(). The local reports from both sides will
 *       contain a secure hash over the DH session key: SHA256(K_e || tag1) for parent enclave A and
 *       SHA256(K_e || tag2) for child enclave B (the different tags are required to prevent
 *       reflection/interleaving attacks). Because a new DH key exchange protocol is run for each
 *       enclave pair, no report can be reused even from an enclave with the same MR_ENCLAVE.
 */

bool is_peer_enclave_ok(sgx_report_body_t* peer_enclave_info,
                        sgx_report_data_t* expected_data) {
    /* current DH session is tied with SGX local attestation via `report_data` field */
    if (memcmp(&peer_enclave_info->report_data, expected_data, sizeof(*expected_data)))
        return false;

    /* all Gramine enclaves with same config (manifest) should have same enclave information
     * (in the future, we may exclude `config_svn` and `config_id` from this check -- they are set
     * by the app enclave after EINIT and are thus not security-critical) */
    static_assert(offsetof(sgx_report_body_t, report_data) + sizeof(*expected_data) ==
                      sizeof(sgx_report_body_t), "wrong sgx_report_body_t::report_data offset");
    if (memcmp(peer_enclave_info, &g_pal_linuxsgx_state.enclave_info,
               offsetof(sgx_report_body_t, report_data)))
        return false;

    return true;
}

int _PalProcessCreate(const char** args, uintptr_t (*reserved_mem_ranges)[2],
                      size_t reserved_mem_ranges_len, PAL_HANDLE* out_handle) {
    int stream_fd;
    int nargs = 0;

    if (args)
        for (const char** a = args; *a; a++)
            nargs++;

    /*
     * `reserved_mem_ranges` contains virtual addresses of all user memory. We do not consider this
     * a secret information (host OS can most likely learn it anyway), so we pass it directly to the
     * host OS. It serves merely as a hint to the initial memory allocator in PAL, so any malicious
     * host OS modifications are irrelevant (will be detected, if anything overlaps).
     */
    int ret = ocall_create_process(nargs, args, reserved_mem_ranges, reserved_mem_ranges_len,
                                   &stream_fd);
    if (ret < 0)
        return unix_to_pal_error(ret);

    PAL_HANDLE child = calloc(1, HANDLE_SIZE(process));
    if (!child)
        return -PAL_ERROR_NOMEM;

    init_handle_hdr(child, PAL_TYPE_PROCESS);
    child->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;
    child->process.stream      = stream_fd;
    child->process.nonblocking = false;
    child->process.is_server   = true;
    child->process.ssl_ctx     = NULL;

    __sgx_mem_aligned sgx_report_data_t parent_report_data = {0};
    __sgx_mem_aligned sgx_report_data_t child_report_data  = {0};
    ret = _PalStreamKeyExchange(child, &child->process.session_key, &parent_report_data,
                                &child_report_data);
    if (ret < 0)
        goto failed;

    ret = _PalStreamReportRequest(child, &parent_report_data, &child_report_data);
    if (ret < 0)
        goto failed;

    ret = _PalStreamSecureInit(child, child->process.is_server, &child->process.session_key,
                               (LIB_SSL_CONTEXT**)&child->process.ssl_ctx, NULL, 0);
    if (ret < 0)
        goto failed;

    /* securely send the master key to child in the newly established SSL session */
    ret = _PalStreamSecureWrite(child->process.ssl_ctx, (uint8_t*)&g_master_key,
                                sizeof(g_master_key), /*is_blocking=*/!child->process.nonblocking);
    if (ret != sizeof(g_master_key))
        goto failed;

    /* Send this Gramine instance ID. */
    uint64_t instance_id = g_pal_common_state.instance_id;
    ret = _PalStreamSecureWrite(child->process.ssl_ctx, (uint8_t*)&instance_id, sizeof(instance_id),
                                /*is_blocking=*/!child->process.nonblocking);
    if (ret != sizeof(instance_id)) {
        goto failed;
    }

    *out_handle = child;
    return 0;

failed:
    _PalStreamDelete(child, PAL_DELETE_ALL);
    _PalObjectClose(child);
    return ret < 0 ? ret : -PAL_ERROR_DENIED;
}

int init_child_process(int parent_stream_fd, PAL_HANDLE* out_parent_handle,
                       uint64_t* out_instance_id) {
    if (g_pal_linuxsgx_state.enclave_initialized)
        return -PAL_ERROR_DENIED;

    PAL_HANDLE parent = calloc(1, HANDLE_SIZE(process));
    if (!parent)
        return -PAL_ERROR_NOMEM;

    init_handle_hdr(parent, PAL_TYPE_PROCESS);
    parent->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;

    parent->process.stream      = parent_stream_fd;
    parent->process.nonblocking = false;
    parent->process.is_server   = false;
    parent->process.ssl_ctx     = NULL;

    __sgx_mem_aligned sgx_report_data_t child_report_data  = {0};
    __sgx_mem_aligned sgx_report_data_t parent_report_data = {0};
    int ret = _PalStreamKeyExchange(parent, &parent->process.session_key,
                                    &parent_report_data, &child_report_data);
    if (ret < 0)
        goto out_error;

    ret = _PalStreamReportRespond(parent, &child_report_data, &parent_report_data);
    if (ret < 0)
        goto out_error;

    ret = _PalStreamSecureInit(parent, parent->process.is_server, &parent->process.session_key,
                               (LIB_SSL_CONTEXT**)&parent->process.ssl_ctx, NULL, 0);
    if (ret < 0)
        goto out_error;

    /* securely receive the master key from parent in the newly established SSL session */
    ret = _PalStreamSecureRead(parent->process.ssl_ctx, (uint8_t*)&g_master_key,
                               sizeof(g_master_key), /*is_blocking=*/!parent->process.nonblocking);
    if (ret != sizeof(g_master_key))
        goto out_error;

    uint64_t instance_id;
    ret = _PalStreamSecureRead(parent->process.ssl_ctx, (uint8_t*)&instance_id, sizeof(instance_id),
                               /*is_blocking=*/!parent->process.nonblocking);
    if (ret != sizeof(instance_id)) {
        goto out_error;
    }

    *out_parent_handle = parent;
    *out_instance_id = instance_id;
    return 0;

out_error:
    _PalStreamDelete(parent, PAL_DELETE_ALL);
    _PalObjectClose(parent);
    return ret < 0 ? ret : -PAL_ERROR_DENIED;
}

noreturn void _PalProcessExit(int exitcode) {
    if (exitcode)
        log_debug("PalProcessExit: Returning exit code %d", exitcode);
    ocall_exit(exitcode, /*is_exitgroup=*/true);
    /* Unreachable. */
}

static int64_t proc_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    ssize_t bytes;
    if (handle->process.ssl_ctx) {
        bytes = _PalStreamSecureRead(handle->process.ssl_ctx, buffer, count,
                                     /*is_blocking=*/!handle->process.nonblocking);
    } else {
        bytes = ocall_read(handle->process.stream, buffer, count);
        bytes = bytes < 0 ? unix_to_pal_error(bytes) : bytes;
    }

    return bytes;
}

static int64_t proc_write(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buffer) {
    if (offset)
        return -PAL_ERROR_INVAL;

    ssize_t bytes;
    if (handle->process.ssl_ctx) {
        bytes = _PalStreamSecureWrite(handle->process.ssl_ctx, buffer, count,
                                      /*is_blocking=*/!handle->process.nonblocking);
    } else {
        bytes = ocall_write(handle->process.stream, buffer, count);
        bytes = bytes < 0 ? unix_to_pal_error(bytes) : bytes;
    }

    return bytes;
}

static int proc_close(PAL_HANDLE handle) {
    if (handle->process.stream != PAL_IDX_POISON) {
        ocall_close(handle->process.stream);
        handle->process.stream = PAL_IDX_POISON;
    }

    if (handle->process.ssl_ctx) {
        _PalStreamSecureFree((LIB_SSL_CONTEXT*)handle->process.ssl_ctx);
        handle->process.ssl_ctx = NULL;
    }

    return 0;
}

static int proc_delete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    int shutdown;
    switch (delete_mode) {
        case PAL_DELETE_ALL:
            shutdown = SHUT_RDWR;
            break;
        case PAL_DELETE_READ:
            shutdown = SHUT_RD;
            break;
        case PAL_DELETE_WRITE:
            shutdown = SHUT_WR;
            break;
        default:
            return -PAL_ERROR_INVAL;
    }

    if (handle->process.stream != PAL_IDX_POISON)
        ocall_shutdown(handle->process.stream, shutdown);

    return 0;
}

static int proc_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    int ret;

    if (handle->process.stream == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    attr->handle_type  = handle->hdr.type;
    attr->nonblocking  = handle->process.nonblocking;

    /* get number of bytes available for reading */
    ret = ocall_fionread(handle->process.stream);
    if (ret < 0)
        return unix_to_pal_error(ret);

    attr->pending_size = ret;

    return 0;
}

static int proc_attrsetbyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    if (handle->process.stream == PAL_IDX_POISON)
        return -PAL_ERROR_BADHANDLE;

    if (attr->nonblocking != handle->process.nonblocking) {
        int ret = ocall_fsetnonblock(handle->process.stream, handle->process.nonblocking);
        if (ret < 0)
            return unix_to_pal_error(ret);

        handle->process.nonblocking = attr->nonblocking;
    }

    return 0;
}

struct handle_ops g_proc_ops = {
    .read           = &proc_read,
    .write          = &proc_write,
    .close          = &proc_close,
    .delete         = &proc_delete,
    .attrquerybyhdl = &proc_attrquerybyhdl,
    .attrsetbyhdl   = &proc_attrsetbyhdl,
};
