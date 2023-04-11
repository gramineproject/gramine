/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */
#pragma once

/* Types and structures used by various Linux ABIs (e.g. syscalls). */
/* These need to be binary-identical with the ones used by Linux. */

#include <stdint.h>

struct linux_dirent64 {
    uint64_t d_ino;              /* Inode number */
    uint64_t d_off;              /* Offset to next linux_dirent */
    unsigned short int d_reclen; /* Length of this linux_dirent */
    unsigned char d_type;
    char d_name[]; /* File name (null-terminated) */
};

struct linux_dirent {
    unsigned long d_ino;         /* Inode number */
    unsigned long d_off;         /* Offset to next linux_dirent */
    unsigned short int d_reclen; /* Length of this linux_dirent */
    char d_name[];               /* File name (null-terminated) */
};

struct linux_dirent_tail {
    char pad;
    unsigned char d_type;
};

#define LINUX_DT_UNKNOWN 0
#define LINUX_DT_FIFO    1
#define LINUX_DT_CHR     2
#define LINUX_DT_DIR     4
#define LINUX_DT_BLK     6
#define LINUX_DT_REG     8
#define LINUX_DT_LNK     10
#define LINUX_DT_SOCK    12
#define LINUX_DT_WHT     14
