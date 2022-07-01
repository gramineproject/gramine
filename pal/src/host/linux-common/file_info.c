/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation */

#include <asm/stat.h>

#include "linux_utils.h"
#include "pal.h"
#include "stat.h"

int file_stat_type(struct stat* stat) {
    if (S_ISREG(stat->st_mode))
        return PAL_TYPE_FILE;
    if (S_ISDIR(stat->st_mode))
        return PAL_TYPE_DIR;
    if (S_ISCHR(stat->st_mode))
        return PAL_TYPE_DEV;
    if (S_ISFIFO(stat->st_mode))
        return PAL_TYPE_PIPE;
    if (S_ISSOCK(stat->st_mode))
        return PAL_TYPE_DEV;

    return 0;
}

void file_attrcopy(PAL_STREAM_ATTR* attr, struct stat* stat) {
    attr->handle_type  = file_stat_type(stat);
    attr->nonblocking  = false;
    attr->share_flags  = stat->st_mode & PAL_SHARE_MASK;
    attr->pending_size = stat->st_size;
}
