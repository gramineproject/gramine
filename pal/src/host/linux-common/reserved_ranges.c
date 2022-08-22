/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include <linux/fs.h>

#include "linux_utils.h"
#include "syscall.h"

int create_reserved_mem_ranges_fd(void* reserved_mem_ranges, size_t reserved_mem_ranges_size) {
    int fd = DO_SYSCALL(memfd_create, "reserved_mem_ranges", /*flags=*/0);
    if (fd < 0) {
        return fd;
    }

    int ret = write_all(fd, reserved_mem_ranges, reserved_mem_ranges_size);
    if (ret < 0) {
        goto out;
    }

    ret = DO_SYSCALL(lseek, fd, 0, SEEK_SET);
    if (ret < 0) {
        goto out;
    }

    ret = fd;

out:
    if (ret < 0) {
        DO_SYSCALL(close, fd);
    }
    return ret;
}
