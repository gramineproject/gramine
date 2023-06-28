/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * IPC glue code for filesystem locks.
 */

#include "libos_fs_lock.h"
#include "libos_ipc.h"

int ipc_file_lock_set(const char* path, struct libos_file_lock* file_lock, bool wait) {
    assert(file_lock->family == FILE_LOCK_POSIX || file_lock->family == FILE_LOCK_FLOCK);
    assert(file_lock->family == FILE_LOCK_POSIX ? file_lock->pid : file_lock->handle_id);
    assert(g_process_ipc_ids.leader_vmid);

    struct libos_ipc_file_lock msgin = {
        .family = file_lock->family,
        .type = file_lock->type,
        .start = file_lock->start,
        .end = file_lock->end,
        .pid = file_lock->pid,
        .handle_id = file_lock->handle_id,

        .wait = wait,
    };

    size_t path_len = strlen(path);
    size_t total_msg_size = get_ipc_msg_size(sizeof(msgin) + path_len + 1);
    struct libos_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_FILE_LOCK_SET, total_msg_size);
    memcpy(msg->data, &msgin, sizeof(msgin));

    /* Copy path after message (`msg->data` is unaligned, so we have to compute the offset
     * manually) */
    char* path_ptr = (char*)&msg->data + offsetof(struct libos_ipc_file_lock, path);
    memcpy(path_ptr, path, path_len + 1);

    void* data;
    int ret = ipc_send_msg_and_get_response(g_process_ipc_ids.leader_vmid, msg, &data);
    if (ret < 0)
        return ret;
    int result = *(int*)data;
    free(data);
    return result;
}

int ipc_file_lock_set_send_response(IDTYPE vmid, unsigned long seq, int result) {
    assert(!g_process_ipc_ids.leader_vmid);

    size_t total_msg_size = get_ipc_msg_size(sizeof(result));
    struct libos_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_response(msg, seq, total_msg_size);
    memcpy(msg->data, &result, sizeof(result));
    return ipc_send_message(vmid, msg);
}

int ipc_file_lock_get(const char* path, struct libos_file_lock* file_lock,
                      struct libos_file_lock* out_file_lock) {
    assert(file_lock->family == FILE_LOCK_POSIX || file_lock->family == FILE_LOCK_FLOCK);
    assert(file_lock->family == FILE_LOCK_POSIX ? file_lock->pid : file_lock->handle_id);
    assert(g_process_ipc_ids.leader_vmid);

    struct libos_ipc_file_lock msgin = {
        .family = file_lock->family,
        .type = file_lock->type,
        .start = file_lock->start,
        .end = file_lock->end,
        .pid = file_lock->pid,
        .handle_id = file_lock->handle_id,
    };

    size_t path_len = strlen(path);
    size_t total_msg_size = get_ipc_msg_size(sizeof(msgin) + path_len + 1);
    struct libos_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_FILE_LOCK_GET, total_msg_size);
    memcpy(msg->data, &msgin, sizeof(msgin));

    /* Copy path after message (`msg->data` is unaligned, so we have to compute the offset
     * manually) */
    char* path_ptr = (char*)&msg->data + offsetof(struct libos_ipc_file_lock, path);
    memcpy(path_ptr, path, path_len + 1);

    void* data;
    int ret = ipc_send_msg_and_get_response(g_process_ipc_ids.leader_vmid, msg, &data);
    if (ret < 0)
        return ret;

    struct libos_ipc_file_lock_resp* resp = data;
    int result = resp->result;
    if (resp->result == 0) {
        out_file_lock->family = resp->family,
        out_file_lock->type = resp->type;
        out_file_lock->start = resp->start;
        out_file_lock->end = resp->end;
        out_file_lock->pid = resp->pid;
        out_file_lock->handle_id = resp->handle_id;
    }
    free(data);
    return result;
}

int ipc_file_lock_clear_pid(IDTYPE pid) {
    assert(g_process_ipc_ids.leader_vmid);

    size_t total_msg_size = get_ipc_msg_size(sizeof(pid));
    struct libos_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_msg(msg, IPC_MSG_FILE_LOCK_CLEAR_PID, total_msg_size);
    memcpy(msg->data, &pid, sizeof(pid));

    void* data;
    int ret = ipc_send_msg_and_get_response(g_process_ipc_ids.leader_vmid, msg, &data);
    if (ret < 0)
        return ret;
    int result = *(int*)data;
    free(data);
    return result;
}

int ipc_file_lock_set_callback(IDTYPE src, void* data, unsigned long seq) {
    struct libos_ipc_file_lock* msgin = data;
    struct libos_file_lock file_lock = {
        .family = msgin->family,
        .type = msgin->type,
        .start = msgin->start,
        .end = msgin->end,
        .pid = msgin->pid,
        .handle_id = msgin->handle_id,
    };

    return file_lock_set_from_ipc(msgin->path, &file_lock, msgin->wait, src, seq);
}

int ipc_file_lock_get_callback(IDTYPE src, void* data, unsigned long seq) {
    struct libos_ipc_file_lock* msgin = data;
    struct libos_file_lock file_lock = {
        .family = msgin->family,
        .type = msgin->type,
        .start = msgin->start,
        .end = msgin->end,
        .pid = msgin->pid,
        .handle_id = msgin->handle_id,
    };

    struct libos_file_lock file_lock2 = {0};
    int result = file_lock_get_from_ipc(msgin->path, &file_lock, &file_lock2);
    struct libos_ipc_file_lock_resp msgout = {
        .result = result,
        .family = file_lock2.family,
        .type = file_lock2.type,
        .start = file_lock2.start,
        .end = file_lock2.end,
        .pid = file_lock2.pid,
        .handle_id = file_lock2.handle_id,
    };

    size_t total_msg_size = get_ipc_msg_size(sizeof(msgout));
    struct libos_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_response(msg, seq, total_msg_size);
    memcpy(msg->data, &msgout, sizeof(msgout));
    return ipc_send_message(src, msg);
}

int ipc_file_lock_clear_pid_callback(IDTYPE src, void* data, unsigned long seq) {
    IDTYPE* pid = data;
    int result = file_lock_clear_pid(*pid);

    size_t total_msg_size = get_ipc_msg_size(sizeof(result));
    struct libos_ipc_msg* msg = __alloca(total_msg_size);
    init_ipc_response(msg, seq, total_msg_size);
    memcpy(msg->data, &result, sizeof(result));
    return ipc_send_message(src, msg);
}
