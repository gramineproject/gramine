/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 * Copyright (C) 2021 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This file defines conversions between Linux syscall flags and PAL API flags.
 *
 * For Linux-based PALs there is pal_flag_conv.h in Linux-common, mirroring those conversions.
 */

#pragma once

#include <asm/fcntl.h>
#include <linux/fcntl.h>
#include <linux/mman.h>

#include "api.h"
#include "assert.h"
#include "pal.h"

static inline pal_prot_flags_t LINUX_PROT_TO_PAL(int prot, int map_flags) {
    assert(WITHIN_MASK(prot, PROT_NONE | PROT_READ | PROT_WRITE | PROT_EXEC
                                | PROT_GROWSDOWN | PROT_GROWSUP));
    return (prot & PROT_READ  ? PAL_PROT_READ  : 0) |
           (prot & PROT_WRITE ? PAL_PROT_WRITE : 0) |
           (prot & PROT_EXEC  ? PAL_PROT_EXEC  : 0) |
           (map_flags & MAP_PRIVATE ? PAL_PROT_WRITECOPY : 0);
}

static inline int PAL_PROT_TO_LINUX(pal_prot_flags_t prot) {
    assert(WITHIN_MASK(prot, PAL_PROT_MASK));
    return (prot & PAL_PROT_READ  ? PROT_READ  : 0) |
           (prot & PAL_PROT_WRITE ? PROT_WRITE : 0) |
           (prot & PAL_PROT_EXEC  ? PROT_EXEC  : 0);
}

static inline enum pal_access LINUX_OPEN_FLAGS_TO_PAL_ACCESS(int access) {
    /* FIXME: Currently PAL does not support appending, so O_APPEND is ignored. */
    switch (access & O_ACCMODE) {
        case O_RDONLY:
            return PAL_ACCESS_RDONLY;
        case O_WRONLY:
            return PAL_ACCESS_WRONLY;
        case O_RDWR:
            return PAL_ACCESS_RDWR;
        default:
            BUG();
    }
}

static inline enum pal_create_mode LINUX_OPEN_FLAGS_TO_PAL_CREATE(int flags) {
    if (WITHIN_MASK(O_CREAT | O_EXCL, flags))
        return PAL_CREATE_ALWAYS;
    if (flags & O_CREAT)
        return PAL_CREATE_TRY;
    return PAL_CREATE_NEVER;
}

static inline pal_stream_options_t LINUX_OPEN_FLAGS_TO_PAL_OPTIONS(int flags) {
    return flags & O_NONBLOCK ? PAL_OPTION_NONBLOCK : 0;
}
