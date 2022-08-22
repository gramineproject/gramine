/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

/*
 * This file contains the implementation of `etc` FS.
 * LibOS assumes that contents of all etc files were already sanitized.
 */

#include "libos_checkpoint.h"
#include "libos_fs.h"
#include "libos_fs_pseudo.h"

static int provide_etc_hostname(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);
    /* Use the string (without null terminator) as file data */
    size_t size = strlen(g_pal_public_state->hostname);
    char* data = malloc(size);
    if (!data)
        return -ENOMEM;
    memcpy(data, g_pal_public_state->hostname, size);
    *out_data = data;
    *out_size = size;
    return 0;
}

int init_etcfs(void) {
    pseudo_add_str(NULL, "etc-passthrough-hostname", &provide_etc_hostname);
    return 0;
}

int init_mount_etcfs(void) {
    int ret;

    if (!g_pal_public_state->passthrough_etc_files)
        return 0;

    ret = mount_fs(&(struct libos_mount_params){
        .type = "pseudo",
        .path = "/etc/hostname",
        .uri = "etc-passthrough-hostname",
    });
    if (ret < 0)
        return ret;

    return 0;
}

BEGIN_CP_FUNC(etc_info) {
    __UNUSED(size);
    __UNUSED(obj);
    __UNUSED(objp);

    /* Propagate hostname */
    size_t off = ADD_CP_OFFSET(sizeof(g_pal_public_state->hostname));
    char* new_hostname = (char*)(base + off);
    memcpy(new_hostname, g_pal_public_state->hostname, sizeof(g_pal_public_state->hostname));

    ADD_CP_FUNC_ENTRY(off);
}
END_CP_FUNC(etc_info)

BEGIN_RS_FUNC(etc_info) {
    __UNUSED(offset);
    __UNUSED(rebase);

    const char* hostname = (const char*)(base + GET_CP_FUNC_ENTRY());
    memcpy(&g_pal_public_state->hostname, hostname, sizeof(g_pal_public_state->hostname));
}
END_RS_FUNC(etc_info)
