/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Labs
 *                    Michael Steiner <michael.steiner@intel.com>
 */

/*!
 * \file
 *
 * This file contains a pseudo-device for an application to inspect the rollback protection state.
 * `/dev/rollback/<path> pseudo-file.
 *
 */

// TODO (MST): also add pseudo file to get hash of the last seen root hash (or, better for
// atomicity, status ahd hash)

#include "api.h"
#include "libos_fs_encrypted.h"
#include "libos_fs_pseudo.h"
#include "pal.h"
#include "toml_utils.h"

static int path_load(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    // TODO (MST): implement me
    // - find volume matching path
    //   - libos/include/libos_fs.h:int walk_mounts(int (*walk)(struct libos_mount* mount, void*
    //     arg), void* arg);
    //   - libos_mount* find_mount_from_uri(const char* uri) path_lookupat(start, path,
    //   - lookup_flags, &dent);
    //
    // - find (relative) path in map
    /*
    struct libos_encrypted_volume_state_map* file_state = NULL;
    lock(&(enc->volume->files_state_map_lock));
    HASH_FIND_STR(enc->volume->files_state_map, norm_path, file_state);
    unlock(&(enc->volume->files_state_map_lock));
    */
    // - prepare outpub buffer with map entry
    /*
   if (is_set) {
        char* buf = malloc(sizeof(pf_key));
        if (!buf)
            return -ENOMEM;
        memcpy(buf, &pf_key, sizeof(pf_key));

        *out_data = buf;
        *out_size = sizeof(pf_key);
    } else {
        *out_data = NULL;
        *out_size = 0;
    }
    */
    __UNUSED(dent);
    __UNUSED(out_data);
    __UNUSED(out_size);
    return 0;
}

int init_rollback(struct pseudo_node* dev) {
    struct pseudo_node* rollback_dir = pseudo_add_dir(dev, "rollback");
    pseudo_add_str(rollback_dir, "file_status", &path_load);

    return 0;
}