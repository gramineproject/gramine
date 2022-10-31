/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Invisible Things Lab
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

/*
 * Implementation of system calls `uname`, `sethostname` and `setdomainname`.
 */

#include <errno.h>

#include "api.h"
#include "libos_internal.h"
#include "libos_table.h"

/* This structure is *not* shared between Gramine processes, despite it should. As a result,
 * effects of set{host,domain}name in process A will not be visible in process B.
 * These syscalls are rarely used and are implemented in Gramine mainly to enable LTP to test
 * our `uname` implementation. */
static struct new_utsname g_current_uname = {
    .sysname  = "Linux",
    .nodename = "(none)", /* overwritten by PAL-provided value at startup */
    .release  = "3.10.0",
    .version  = "1",
#ifdef __x86_64__
    .machine  = "x86_64",
#else
#error "Not implemented"
#endif
    .domainname = "(none)", /* this seems to be the default on Linux */
};

long libos_syscall_uname(struct new_utsname* buf) {
    if (!is_user_memory_writable(buf, sizeof(*buf)))
        return -EFAULT;

    memcpy(buf, &g_current_uname, sizeof(g_current_uname));
    return 0;
}

int set_hostname(const char* name, size_t len) {
    if (len >= sizeof(g_current_uname.nodename))
        return -EINVAL;

    memcpy(&g_current_uname.nodename, name, len);
    memset(&g_current_uname.nodename[len], 0, sizeof(g_current_uname.nodename) - len);

    return 0;
}

long libos_syscall_sethostname(char* name, int len) {
    if (len < 0 || (size_t)len >= sizeof(g_current_uname.nodename))
        return -EINVAL;

    if (!is_user_memory_readable(name, len))
        return -EFAULT;

    return set_hostname(name, len);
}

long libos_syscall_setdomainname(char* name, int len) {
    if (len < 0 || (size_t)len >= sizeof(g_current_uname.domainname))
        return -EINVAL;

    if (!is_user_memory_readable(name, len))
        return -EFAULT;

    memcpy(&g_current_uname.domainname, name, len);
    memset(&g_current_uname.domainname[len], 0, sizeof(g_current_uname.domainname) - len);
    return 0;
}
