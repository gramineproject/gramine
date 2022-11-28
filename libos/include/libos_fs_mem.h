/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * This file defines helper functions for in-memory files. They're used for implementing
 * pseudo-FSes and the `tmpfs` filesystem.
 */

#pragma once

#include "libos_types.h"

struct libos_mem_file {
    char* buf;
    file_off_t size;
    size_t buf_size;
};

void mem_file_init(struct libos_mem_file* mem, char* data, size_t size);
void mem_file_destroy(struct libos_mem_file* mem);

/*
 * The following operations can be used to implement corresponding filesystem callbacks (see
 * `libos_fs.h`). Note that the caller has to pass the file position, and (in case of `read` and
 * `write`) update it themselves after a successful operation.
 */
ssize_t mem_file_read(struct libos_mem_file* mem, file_off_t pos_start, void* buf, size_t size);
ssize_t mem_file_write(struct libos_mem_file* mem, file_off_t pos_start, const void* buf,
                       size_t size);
int mem_file_truncate(struct libos_mem_file* mem, file_off_t size);
int mem_file_poll(struct libos_mem_file* mem, file_off_t pos, int events, int* out_events);
