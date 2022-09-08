/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

/*
 * This file contains the APIs to retrieve information from the host:
 *   - parses host file `/etc/resolv.conf` into `struct pal_dns_host_conf`
 */

#include "api.h"
#include "etc_host_info.h"
#include "linux_utils.h"

static void jmp_to_end_of_line(const char** pptr) {
    const char* ptr = *pptr;

    while (*ptr != 0x00 && *ptr != '\n')
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
    return ch == 0x00 || ch == '\n' || ch == ' ' || ch == '\t';
}

static bool parse_ip_addr_ipv4(const char** pptr, uint32_t* out_addr) {
    long long octet;
    const char* ptr = *pptr;
    char* next;
    uint32_t addr[4];
    int i;

    for (i = 0; i < 4; i++) {
        octet = strtoll(ptr, &next, 10);
        if (ptr == next)
            return false;
        if (octet < 0 || octet > UINT32_MAX)
            return false;

        addr[i] = octet;

        if (is_end_of_word(*next))
            break;
        if (*next != '.')
            return false;

        ptr = next + 1;
    }
    if (!is_end_of_word(*next))
        return false;

    uint32_t result = 0;
    if (i == 0) {
        /* Address A has to be converted to: A.A.A.A
         * The value a is interpreted as a 32-bit. */
        result = addr[0];
    } else if (i == 1) {
        /* Address A.B has to be converted to: A.B.B.B
         * Part B is interpreted as a 24-bit. */
        if (addr[0] > 0xFF || addr[1] > 0xFFFFFF) {
            return false;
        }
        result = addr[0] << 24 | addr[1];
    } else if (i == 2) {
        /* Address A.B.C has to be converted to: A.B.C.C
         * Part C is interpreted as a 16-bit value. */
        if (addr[0] > 0xFF || addr[1] > 0xFF || addr[2] > 0xFFFF)
            return false;
        result = addr[0] << 24 | addr[1] << 16 | addr[2];
    } else {
        /* Address A.B.C.D */
        for (i = 0; i < 4; i++) {
            if (addr[i] > 0xFF)
                return false;
            result = result << 8 | addr[i];
        }
    }

    *pptr = ptr;
    *out_addr = result;

    return true;
}

/*
 * Supported notations:
 *  - Full IPv6 address
 *  - Abbreviations `::1`, `ff::1:2`
 */
static bool parse_ip_addr_ipv6(const char** pptr, uint16_t* out_addr) {
    long part;
    const char* ptr = *pptr;
    char* next;
    int i, twocomas = -1;
    uint16_t addr[8];

    memset(&addr, 0, sizeof(addr));
    for (i = 0; i < 8; i++) {
        part = strtol(ptr, &next, 16);

        if (ptr == next) {
            if (twocomas == -1 && *ptr == ':') {
                if (i == 0) {
                    /* The IPv6 address starts with the ':', this means that the next character
                     * has to be also ':' (to support ::something), otherwise it is invalid
                     * (:something). When i > 0 we know already that the previous char was a ':',
                     * or we exited earlier. */
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

    memcpy(out_addr, &addr, sizeof(addr));
    *pptr = ptr;

    return true;
}

static void resolv_nameserver(struct pal_dns_host_conf* conf, const char** pptr) {
    const char* ptr = *pptr;
    bool is_ipv6 = false;

    if (conf->nsaddr_list_count >= PAL_MAX_NAMESPACES) {
        log_error("Host's /etc/resolv.conf contains more than %d nameservers, skipping",
                  PAL_MAX_NAMESPACES);
        return;
    }

    /*
     * Check if nameserver is using IPv6 or IPv4.
     * If address contains ':', it is a IPv6 address.
     * If address contains '.', it is a IPv4 address.
     */
    while (!is_end_of_word(*ptr)) {
        if (*ptr == ':') {
            is_ipv6 = true;
            break;
        } else if (*ptr == '.') {
            break;
        }
        ptr++;
    }

    /* If we haven't found ':' nor '.' it means it is IPv4 address. */
    if (is_ipv6) {
        if (!parse_ip_addr_ipv6(pptr, conf->nsaddr_list[conf->nsaddr_list_count].ipv6)) {
            log_error("Host's /etc/resolv.conf has invalid or unsupported notation in nameserver "
                      "keyword");
            return;
        }
    } else {
        if (!parse_ip_addr_ipv4(pptr, &conf->nsaddr_list[conf->nsaddr_list_count].ipv4)) {
            log_error("Host's /etc/resolv.conf has invalid or unsupported notation in nameserver "
                      "keyword");
            return;
        }
    }

    conf->nsaddr_list[conf->nsaddr_list_count].is_ipv6 = is_ipv6;
    conf->nsaddr_list_count++;
}

static void parse_values_list_in_one_line(struct pal_dns_host_conf* conf, const char** pptr,
                                          void (*setter)(struct pal_dns_host_conf*, const char*, size_t)) {
    const char* ptr = *pptr;
    const char* namestart = ptr;

    while (*ptr != 0x00 && *ptr != '\n' && *ptr != '#') {
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
    if (length >= PAL_HOSTNAME_MAX) {
        log_error("One of the search domains in host's /etc/resolv.conf is too long "
                  "(larger than %d), skipping it", PAL_HOSTNAME_MAX);
        return;
    }
    if (length == 0) {
        return;
    }
    if (conf->dnsrch_count >= PAL_MAX_DN_SEARCH) {
        log_error("Host's /etc/resolv.conf contains too many search domains in single search "
                  "keyword");
        return;
    }

    memcpy(conf->dnsrch[conf->dnsrch_count], ptr, length);
    conf->dnsrch[conf->dnsrch_count][length] = 0x0;
    conf->dnsrch_count++;
}

static void resolv_search(struct pal_dns_host_conf* conf, const char** pptr) {
    /* Each search keyword overrides previous one. */
    conf->dnsrch_count = 0;
    parse_values_list_in_one_line(conf, pptr, resolv_search_setter);
}

static void resolv_options_setter(struct pal_dns_host_conf* conf, const char* ptr, size_t length) {
    char option[32];

    if (length == 0)
        return;
    if (length >= sizeof(option))
        return;
    memcpy(option, ptr, length);
    option[length] = 0x00;

    if (strcmp(option, "inet6") == 0) {
        conf->inet6 = true;
    } else if (strcmp(option, "rotate") == 0) {
        conf->rotate = true;
    }
}

static void resolv_options(struct pal_dns_host_conf* conf, const char** pptr) {
    parse_values_list_in_one_line(conf, pptr, resolv_options_setter);
}

static struct {
    const char* keyword;
    void (*set_value)(struct pal_dns_host_conf* conf, const char** pptr);
} resolv_keys[] = {
    { "nameserver", resolv_nameserver },
    { "search",     resolv_search },
    { "options",    resolv_options },
    { NULL, 0 },
};

static void parse_resolv_buf_conf(struct pal_dns_host_conf* conf, const char* buf) {
    const char* ptr = buf;
    const char* startline = buf;

    while (*ptr != 0x00) {
        if (*ptr == '\n') {
            ptr++;
            startline = ptr;
            continue;
        } else if (startline == ptr && *ptr == '#') {
            /* comment, ignoring whole line */
            jmp_to_end_of_line(&ptr);
            continue;
        } else if ((ptr != startline) && (*ptr == ' ' || *ptr == '\t')) {
            for (size_t i = 0; resolv_keys[i].keyword != NULL; i++) {
                if (strncmp(startline, resolv_keys[i].keyword, ptr - startline - 1) == 0) {
                    /* Because the buffer in strncmp is not ended with 0x00, let's
                     * verify that the length of keywords is the same. */
                    if (resolv_keys[i].keyword[ptr - startline] != 0x00)
                        continue;
                    skip_whitespace(&ptr);
                    resolv_keys[i].set_value(conf, &ptr);
                    break;
                }
            }
            /* Make sure we are at the end of line, even if parsing of this line failed */
            jmp_to_end_of_line(&ptr);
            continue;
        }
        ptr++;
    }
}

int parse_resolv_conf(struct pal_dns_host_conf* conf) {
    char* buf;
    int ret = read_text_file_to_cstr("/etc/resolv.conf", &buf);
    if (ret < 0) {
        return ret;
    }

    parse_resolv_buf_conf(conf, buf);

    free(buf);
    return 0;
}
