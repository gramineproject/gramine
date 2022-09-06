/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

/*
 * This file contains the APIs to expose host information.
 */

#include <asm/errno.h>

#include "api.h"
#include "etc_host_info.h"
#include "linux_utils.h"

#define PAL_MAX_HOSTNAME 255

static void jmp_to_end_of_line(const char** pptr) {
    const char* ptr = *pptr;

    while (*ptr != '\0' && *ptr != '\n')
        ptr++;

    *pptr = ptr;
}

static void skip_whitespace(const char** pptr) {
    const char* ptr = *pptr;

    while (*ptr == ' ' || *ptr == '\t')
        ptr++;

    *pptr = ptr;
}

static bool is_end_of_word(const char ch) {
    return ch == '\0' || ch == '\n' || ch == ' ' || ch == '\t';
}

static bool parse_ip_addr_ipv4(struct pal_dns_host_conf *conf, const char** pptr) {
    long octed;
    const char* ptr = *pptr;
    char* next;
    uint32_t addr = 0;
    int i;

    for (i = 0; i < 4; i++) {
        octed = strtol(ptr, &next, 10);
        if (ptr == next)
            return false;
        if (octed > 255 || octed < 0)
            return false;

        addr = (addr << 8) | octed;

        if (is_end_of_word(*next))
            break;
        if (*next != '.')
            return false;

        ptr = next + 1;
    }
    if (!is_end_of_word(*next))
        return false;
    if (i == 1) {
        /* Address X.Y has to be converted to: X.0.0.Y */
        addr = ((addr & 0xFF00) << 16) | (addr & 0xFF);
    } else if (i == 2) {
        /* Address X.Y.Z has to be converted to: X.0.Y.Z */
        addr = ((addr & 0xFFFF00) << 8) | (addr & 0xFF);
    }

    conf->nsaddr_list[conf->nsaddr_list_count].is_ipv6 = false;
    conf->nsaddr_list[conf->nsaddr_list_count].ipv4 = addr;
    conf->nsaddr_list_count++;
    *pptr = ptr;

    return true;
}

/*
 * Supported notations:
 * Full IPv6 address
 * Abbreviations `::1`, `ff::1:2`
 */
static bool parse_ip_addr_ipv6(struct pal_dns_host_conf* conf, const char** pptr) {
    long part;
    const char* ptr = *pptr;
    char* next;
    int i, twocomas;
    uint16_t addr[8];

    memset(&addr, 0, sizeof(addr));
    twocomas = -1;
    for (i = 0; i < 8; i++) {
        part = strtol(ptr, &next, 16);

        if (ptr == next) {
            if (twocomas == -1 && *ptr == ':') {
                if (i == 0) {
                    if (*(ptr + 1) != ':')
                        return false;
                    ptr++;
                }
                twocomas = i;
                i--;
                ptr++;
                continue;
            }
            if (twocomas != -1 && is_end_of_word(*next))
                break;
            return false;
        }
        if (part < 0 || part > 0xFFFF)
            return false;

        addr[i] = part;

        if (is_end_of_word(*next))
            break;
        if (*next != ':')
            return false;

        ptr = next + 1;
    }
    if (!is_end_of_word(*next))
        return false;
    if (twocomas == -1 && i != 7)
        return false;
    if (twocomas != -1 && i >= 7)
        return false;
    if (twocomas != -1) {
        for (int j = 7; i >= twocomas; j--, i--) {
            addr[j] = addr[i];
            addr[i] = 0;
        }
    }

    conf->nsaddr_list[conf->nsaddr_list_count].is_ipv6 = true;
    memcpy(&conf->nsaddr_list[conf->nsaddr_list_count].ipv6, &addr, sizeof(addr));
    conf->nsaddr_list_count++;
    *pptr = ptr;

    return true;
}

static void resolv_nameserver(struct pal_dns_host_conf* conf, const char** pptr) {
    const char* ptr = *pptr;
    bool ipv6 = false;

    if (conf->nsaddr_list_count >= PAL_MAXNS) {
        log_warning("Host's resolv.conf contains more then %d nameservers, skipping", PAL_MAXNS);
        return;
    }

    /*
     * Check if nameserver os using IPv6 or IPv4.
     * If address contain ':', it is a IPv6 address.
     * If address contain '.', it is a IPv4 address.
     */
    while (!is_end_of_word(*ptr)) {
        if (*ptr == ':') {
            ipv6 = true;
        } else if (*ptr == '.') {
            break;
        }
        ptr++;
    }

    /* If we haven't found ':' nor '.' it means it is IPv4 address. */
    if (ipv6) {
        if (!parse_ip_addr_ipv6(conf, pptr))
            log_warning("Host's resolv.conf has invalid or unsupported notation in nameserver keyword");
    } else {
        if (!parse_ip_addr_ipv4(conf, pptr))
            log_warning("Host's resolv.conf has invalid or unsupported notation in nameserver keyword");
    }
}

static void parse_list(struct pal_dns_host_conf* conf, const char** pptr,
                       void (*setter)(struct pal_dns_host_conf*, const char*, size_t)) {
    const char* ptr       = *pptr;
    const char* namestart = ptr;

    while (*ptr != '\0' && *ptr != '\n' && *ptr != '#') {
        if (*ptr == ' ' || *ptr == '\t') {
            setter(conf, namestart, ptr - namestart);
            skip_whitespace(&ptr);
            namestart = ptr;
            continue;
        }
        ptr++;
    }
    setter(conf, namestart, ptr - namestart);

    *pptr = ptr;
}

static void resolv_search_setter(struct pal_dns_host_conf* conf, const char* ptr, size_t length) {
    if (length >= PAL_MAX_HOSTNAME) {
        log_warning("One of the search domains in host's resolv.conf is to long (larger then %d), "
                    "skipping it", PAL_MAX_HOSTNAME);
        return;
    }
    if (length == 0) {
        return;
    }
    if (conf->dnsrch_count >= PAL_MAXDNSRCH) {
        log_warning("Host's resolv.conf contains too many search domains in single search keyword");
        return;
    }

    memcpy(conf->dnsrch[conf->dnsrch_count], ptr, length);
    conf->dnsrch[conf->dnsrch_count][length] = 0x0;
    conf->dnsrch_count++;
}

static void resolv_search(struct pal_dns_host_conf* conf, const char** pptr) {
    /* Each search keyword overrides previous one. */
    conf->dnsrch_count = 0;
    parse_list(conf, pptr, resolv_search_setter);
}

static void resolv_options_setter(struct pal_dns_host_conf* conf, const char* ptr, size_t length) {
    char option[32];

    if (length == 0)
        return;
    if (length >= sizeof(option))
        return;
    memcpy(option, ptr, length);
    option[length] = '\0';

    if (strcmp(option, "inet6") == 0) {
        conf->inet6 = true;
    } else if (strcmp(option, "rotate") == 0) {
        conf->rotate = true;
    }
}

static void resolv_options(struct pal_dns_host_conf* conf, const char** pptr) {
    parse_list(conf, pptr, resolv_options_setter);
}

static struct {
    const char* keyword;
    void        (*set_option)(struct pal_dns_host_conf* conf, const char** pptr);
} resolv_keys[] = {
    { "nameserver", resolv_nameserver },
    { "search",     resolv_search },
    { "options",    resolv_options },
    { NULL, 0 },
};

static void parse_resolv_conf(struct pal_dns_host_conf* conf, const char* buf) {
    const char* ptr       = buf;
    const char* startline = buf;

    while (*ptr != 0x00) {
        if (*ptr == '\n') {
            ptr++;
            startline = ptr;
            continue;
        } else if (*startline == *ptr && *ptr == '#') {
            /* comment, ignoring whole line */
            jmp_to_end_of_line(&ptr);
            continue;
        } else if ((ptr != startline) && (*ptr == ' ' || *ptr == '\t')) {
            for (size_t i = 0; resolv_keys[i].keyword != NULL; i++) {
                if (strncmp(startline, resolv_keys[i].keyword, ptr - startline - 1) ==
                    0) {
                    /* Because the buffer in strncmp is not ended with 0x00, lets
                     * verify that the length of keywords are the same. */
                    if (resolv_keys[i].keyword[ptr - startline] != 0x00)
                        continue;
                    skip_whitespace(&ptr);
                    resolv_keys[i].set_option(conf, &ptr);
                    break;
                }
            }
            /* Make sure we are at the end of line. */
            jmp_to_end_of_line(&ptr);
            continue;
        }
        ptr++;
    }
}

int get_resolv_conf(struct pal_dns_host_conf* conf) {
    char* buf;
    int ret = read_text_file_to_cstr("/etc/resolv.conf", &buf);
    if (ret < 0) {
        return ret;
    }

    parse_resolv_conf(conf, buf);

    free(buf);
    return 0;
}
