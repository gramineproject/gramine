/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

/*
 * This file contains the implementation of `etc` FS.
 * LibOS assumes that contents of all data obtained from host were already sanitized.
 */

#include "libos_checkpoint.h"
#include "libos_fs.h"
#include "libos_fs_pseudo.h"

#define OPTION_EDNS0 "options edns0\n"
#define OPTION_INET6 "options inet6\n"
#define OPTION_ROTATE "options rotate\n"
#define OPTION_USE_VC "options use-vc\n"

static int put_string(char** buf, size_t* bufsize, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int ret = vsnprintf(*buf, *bufsize, fmt, ap);
    va_end(ap);
    if (ret < 0)
        return ret;
    if ((size_t)ret >= *bufsize)
        return -EOVERFLOW;
    *bufsize -= ret;
    *buf += ret;

    return 0;
}

static int provide_etc_resolv_conf(struct libos_dentry* dent, char** out_data, size_t* out_size) {
    __UNUSED(dent);

    size_t size = 0;

    /* Estimate the size of buffer: */
    /* nameservers - let's assume all entries will be IPv6 plus a new line */
    size += g_pal_public_state->dns_host.nsaddr_list_count
            * (strlen("nameserver ") + MAX_IPV6_ADDR_LEN + 1);
    /* search - let's assume maximum length of entries, plus a new line and white spaces */
    size += strlen("search");
    size += g_pal_public_state->dns_host.dn_search_count * (PAL_HOSTNAME_MAX + 1);
    size += 1;
    /* and let's add some space for each option */
    size += (g_pal_public_state->dns_host.edns0 ? strlen(OPTION_EDNS0) : 0)
            + (g_pal_public_state->dns_host.inet6 ? strlen(OPTION_INET6) : 0)
            + (g_pal_public_state->dns_host.rotate ? strlen(OPTION_ROTATE) : 0)
            + (g_pal_public_state->dns_host.use_vc ? strlen(OPTION_USE_VC) : 0);

    /* make space for terminating character */
    size += 1;

    char* data = malloc(size);
    if (!data)
        return -ENOMEM;
    memset(data, 0, size);

    /* Generate data: */
    size_t space_left = size;
    char* ptr = data;
    int ret;
    for (size_t i = 0; i < g_pal_public_state->dns_host.nsaddr_list_count; i++) {
        if (!g_pal_public_state->dns_host.nsaddr_list[i].is_ipv6) {
            uint32_t addr = g_pal_public_state->dns_host.nsaddr_list[i].ipv4;
            ret = put_string(&ptr, &space_left, "nameserver %u.%u.%u.%u\n",
                             (addr & 0xFF000000) >> 24, (addr & 0x00FF0000) >> 16,
                             (addr & 0x0000FF00) >> 8, (addr & 0x000000FF));
        } else {
            uint16_t* addrv6 = g_pal_public_state->dns_host.nsaddr_list[i].ipv6;
            ret = put_string(&ptr, &space_left, "nameserver %x:%x:%x:%x:%x:%x:%x:%x\n",
                             addrv6[0], addrv6[1], addrv6[2], addrv6[3], addrv6[4], addrv6[5],
                             addrv6[6], addrv6[7]);
        }
        if (ret < 0)
            goto out;
    }

    if (g_pal_public_state->dns_host.dn_search_count > 0) {
        ret = put_string(&ptr, &space_left, "search");
        if (ret < 0)
            goto out;
        for (size_t i = 0; i < g_pal_public_state->dns_host.dn_search_count; i++) {
            ret = put_string(&ptr, &space_left, " %s", g_pal_public_state->dns_host.dn_search[i]);
            if (ret < 0)
                goto out;
        }
        ret = put_string(&ptr, &space_left, "\n");
        if (ret < 0)
            goto out;
    }
    if (g_pal_public_state->dns_host.edns0) {
        ret = put_string(&ptr, &space_left, OPTION_EDNS0);
        if (ret < 0)
            goto out;
    }
    if (g_pal_public_state->dns_host.inet6) {
        ret = put_string(&ptr, &space_left, OPTION_INET6);
        if (ret < 0)
            goto out;
    }
    if (g_pal_public_state->dns_host.rotate) {
        ret = put_string(&ptr, &space_left, OPTION_ROTATE);
        if (ret < 0)
            goto out;
    }
    if (g_pal_public_state->dns_host.use_vc) {
        ret = put_string(&ptr, &space_left, OPTION_USE_VC);
        if (ret < 0)
            goto out;
    }

    /* Use the string (without null terminator) as file data */
    size_t finalsize = strlen(data);
    char* finalbuf = malloc(finalsize);
    if (!finalbuf) {
        ret = -ENOMEM;
        goto out;
    }
    assert(finalsize < size);
    memcpy(finalbuf, data, finalsize);

    *out_data = finalbuf;
    *out_size = finalsize;

    ret = 0;
out:
    free(data);
    return ret;
}

int init_etcfs(void) {
    pseudo_add_str(NULL, "emulated-etc-resolv-conf", &provide_etc_resolv_conf);
    return 0;
}

int mount_etcfs(void) {
    if (!g_pal_public_state->extra_runtime_domain_names_conf)
        return 0;

    return mount_fs(&(struct libos_mount_params){
        .type = "pseudo",
        .path = "/etc/resolv.conf",
        .uri = "emulated-etc-resolv-conf",
    });
}

BEGIN_CP_FUNC(etc_info) {
    __UNUSED(size);
    __UNUSED(obj);
    __UNUSED(objp);

    /* Propagate DNS configuration */
    size_t off = ADD_CP_OFFSET(sizeof(g_pal_public_state->dns_host));
    struct dns_host* new_dns_host = (struct dns_host*)(base + off);
    memcpy(new_dns_host, &g_pal_public_state->dns_host, sizeof(g_pal_public_state->dns_host));

    ADD_CP_FUNC_ENTRY(off);
}
END_CP_FUNC(etc_info)

BEGIN_RS_FUNC(etc_info) {
    __UNUSED(offset);
    __UNUSED(rebase);

    const struct dns_host* dns_host = (const struct dns_host*)(base + GET_CP_FUNC_ENTRY());
    memcpy(&g_pal_public_state->dns_host, dns_host, sizeof(g_pal_public_state->dns_host));
}
END_RS_FUNC(etc_info)
