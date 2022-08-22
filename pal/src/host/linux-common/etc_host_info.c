/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

/*
 * This file contains the APIs to expose host information.
 */

#include <asm/errno.h>
#include <linux/utsname.h>

#include "etc_host_info.h"

int get_hostname(char* hostname, size_t size) {
    struct new_utsname c_uname;
    int ret;

    assert(hostname != NULL);
    assert(size > 0);

    ret = DO_SYSCALL(uname, &c_uname);
    if (ret < 0)
        return ret;

    size_t len = strlen(c_uname.nodename) + 1;
    memcpy(hostname, &c_uname.nodename,
           len > size ? size : len);
    hostname[size - 1] = '\0';

    return 0;
}
