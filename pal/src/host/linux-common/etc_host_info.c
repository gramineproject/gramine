/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

/*
 * This file contains the APIs to retrieve information from the host:
 *   - parses host file `/etc/resolv.conf` into `struct pal_dns_host_conf`
 *   - gets host's hostname through uname syscall
 */

#include <asm/errno.h>
#include <linux/utsname.h>

#include "api.h"
#include "etc_host_info.h"
#include "etc_host_info_internal.h"
#include "linux_utils.h"
#include "syscall.h"

static void jmp_to_end_of_line(const char** pptr) {
    const char* ptr = *pptr;

    while (*ptr != 0x00 && *ptr != '\n')
        ptr++;

    *pptr = ptr;
}

static void skip_whitespaces(const char** pptr) {
    const char* ptr = *pptr;

    while (*ptr == ' ' || *ptr == '\t')
        ptr++;

    *pptr = ptr;
}

static bool is_end_of_word(char ch) {
    return ch == 0x00 || ch == '\n' || ch == ' ' || ch == '\t';
}

bool parse_ip_addr_ipv4(const char** pptr, uint32_t* out_addr) {
    const char* ptr = *pptr;
    char* next;
    uint32_t addr[4];
    size_t i;

    for (i = 0; i < 4; i++) {
        /* NOTE: Gramine strtoll/strtol skips white spaces that are before the number, and doesn't
         *       treat this as an error, this behavior is different from glibc.
         */
        if (!isdigit(*ptr))
            return false;
        long long octet = strtoll(ptr, &next, 10);
        if (ptr == next)
            return false;
        if (octet < 0 || octet > UINT32_MAX)
            return false;
        /* strtoll skips a prefix with 0 */
        if (next - ptr > 1 && *ptr == '0')
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
    assert(i < 4);

    uint32_t result = 0;
    if (i == 0) {
        /* Address A has to be converted to A[31:24].A[23:16].A[15:8].A[7:0]
         * The value A is interpreted as a 32-bit. */
        result = addr[0];
    } else if (i == 1) {
        /* Address A.B has to be converted to A.B[23:16].B[15:8].B[7:0]
         * Part B is interpreted as a 24-bit. */
        if (addr[0] > 0xFF || addr[1] > 0xFFFFFF) {
            return false;
        }
        result = addr[0] << 24 | addr[1];
    } else if (i == 2) {
        /* Address A.B.C has to be converted to A.B.C[15:8].C[7:0]
         * Part C is interpreted as a 16-bit value. */
        if (addr[0] > 0xFF || addr[1] > 0xFF || addr[2] > 0xFFFF)
            return false;
        result = addr[0] << 24 | addr[1] << 16 | addr[2];
    } else {
        /* Address A.B.C.D */
        if (addr[0] > 0xFF || addr[1] > 0xFF || addr[2] > 0xFF || addr[3] > 0xFF)
            return false;
        result = addr[0] << 24 | addr[1] << 16 | addr[2] << 8 | addr[3];
    }

    *pptr = ptr;
    *out_addr = result;

    return true;
}

bool parse_ip_addr_ipv6(const char** pptr, uint16_t addr[static 8]) {
    const char* ptr = *pptr;
    ssize_t double_colon_pos = -1;
    size_t parts_seen = 0;

    if (ptr[0] == ':' && ptr[1] == ':') {
        double_colon_pos = 0;
        ptr += 2;
    }

    memset(addr, 0, sizeof(*addr) * 8);
    for (size_t i = 0; i < 8; i++) {
        if (is_end_of_word(ptr[0])) {
            break;
        }

        if (!isxdigit(ptr[0])) {
            return false;
        }

        char* next;
        long val = strtol(ptr, &next, 16);
        if (val < 0 || val > 0xFFFF) {
            return false;
        }
        /* strtol skips 0x prefix, this prefix is invalid in IPv6 */
        if (next - ptr >= 2 && !isxdigit(ptr[1])) {
            return false;
        }
        addr[parts_seen] = val;
        parts_seen++;
        ptr = next;

        if (ptr[0] == ':' && ptr[1] == ':') {
            if (double_colon_pos != -1) {
                return false;
            }

            double_colon_pos = parts_seen;
            ptr += 2;
        } else if (ptr[0] == ':') {
            ptr++;
        } else {
            break;
        }
    }

    if (!is_end_of_word(ptr[0])) {
        return false;
    }
    if (parts_seen > 0 && !isxdigit(*(ptr - 1)) && (ssize_t)parts_seen != double_colon_pos) {
        assert(ptr[-1] == ':');
        return false;
    }

    if (double_colon_pos == -1) {
        if (parts_seen != 8)
            return false;
        /* `addr` already correct. */
    } else {
        if (parts_seen == 8)
            return false;
        if (parts_seen > 0) {
            ssize_t i = parts_seen - 1;
            for (ssize_t j = 7; i >= double_colon_pos; j--, i--) {
                addr[j] = addr[i];
                addr[i] = 0;
            }
        }
    }

    *pptr = ptr;
    return true;
}

#ifndef PARSERS_ONLY
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
     * If we haven't found ':' nor '.' it means it is IPv4 address.
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

static void parse_values_one_line(struct pal_dns_host_conf* conf, const char** pptr,
                                  void (*setter)(struct pal_dns_host_conf*, const char*, size_t)) {
    const char* ptr = *pptr;
    const char* namestart = ptr;

    while (*ptr != 0x00 && *ptr != '\n' && *ptr != '#' && *ptr != ';') {
        if (*ptr == ' ' || *ptr == '\t') {
            setter(conf, namestart, ptr - namestart);
            skip_whitespaces(&ptr);
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
    if (conf->dn_search_count >= PAL_MAX_DN_SEARCH) {
        log_error("Host's /etc/resolv.conf contains too many search domains in single search "
                  "keyword");
        return;
    }

    memcpy(conf->dn_search[conf->dn_search_count], ptr, length);
    conf->dn_search[conf->dn_search_count][length] = 0x0;
    conf->dn_search_count++;
}

static void resolv_search(struct pal_dns_host_conf* conf, const char** pptr) {
    /* Each search keyword overrides previous one. */
    conf->dn_search_count = 0;
    parse_values_one_line(conf, pptr, resolv_search_setter);
}

static void resolv_options_setter(struct pal_dns_host_conf* conf, const char* ptr, size_t length) {
    char option[32];

    if (length == 0)
        return;
    if (length >= sizeof(option))
        return;
    memcpy(option, ptr, length);
    option[length] = 0x00;

    if (strcmp(option, "edns0") == 0) {
        conf->edns0 = true;
    } else if (strcmp(option, "inet6") == 0) {
        conf->inet6 = true;
    } else if (strcmp(option, "rotate") == 0) {
        conf->rotate = true;
    } else if (strcmp(option, "use-vc") == 0) {
        conf->use_vc = true;
    }
}

static void resolv_options(struct pal_dns_host_conf* conf, const char** pptr) {
    parse_values_one_line(conf, pptr, resolv_options_setter);
}

static struct {
    const char* keyword;
    void (*set_value)(struct pal_dns_host_conf* conf, const char** pptr);
} resolv_keys[] = {
    { "nameserver", resolv_nameserver },
    { "search",     resolv_search },
    { "options",    resolv_options },
};

static void parse_resolv_buf_conf(struct pal_dns_host_conf* conf, const char* buf) {
    const char* ptr = buf;

    /*
     * From resolv.conf(5):
     * The keyword and value must appear on a single line, and the keyword (e.g., nameserver) must
     * start the line. The value follows the keyword, separated by white space.
     */
    while (*ptr != 0x00) {
        for (size_t i = 0; i < ARRAY_SIZE(resolv_keys); i++) {
            if (strncmp(ptr, resolv_keys[i].keyword, strlen(resolv_keys[i].keyword)) == 0) {
                ptr += strlen(resolv_keys[i].keyword);
                /* Because the buffer in strncmp is not ended with 0x00, let's
                 * verify that this is end of word. */
                if (!is_end_of_word(*ptr))
                    break;
                skip_whitespaces(&ptr);
                resolv_keys[i].set_value(conf, &ptr);
                break;
            }
        }
        /* Make sure we are at the end of line, even if parsing of this line failed */
        jmp_to_end_of_line(&ptr);
        if (*ptr != 0x00) {
            assert(*ptr == '\n');
            ptr++;
        }
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

int get_hosts_hostname(char* hostname, size_t size) {
    struct new_utsname c_uname;

    int ret = DO_SYSCALL(uname, &c_uname);
    if (ret < 0)
        return ret;

    size_t node_size = strlen(c_uname.nodename) + 1;
    memcpy(hostname, c_uname.nodename, MIN(node_size, size));

    assert(size > 0);
    hostname[size - 1] = 0;

    return 0;
}
#endif /* ifndef PARSERS_ONLY */
