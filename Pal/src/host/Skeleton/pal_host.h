/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains definition of PAL host ABI.
 */

#ifndef PAL_HOST_H
#define PAL_HOST_H

#ifndef IN_PAL
#error "cannot be included outside PAL"
#endif

typedef struct {
    /* TSAI: Here we define the internal types of PAL_HANDLE in PAL design, user has not to access
     * the content inside the handle, also there is no need to allocate the internal handles, so we
     * hide the type name of these handles on purpose.
     */
    PAL_HDR hdr;
    uint32_t flags;
}* PAL_HANDLE;

#endif /* PAL_HOST_H */
