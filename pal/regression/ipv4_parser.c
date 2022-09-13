/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

#include "api.h"
#include "etc_host_info_internal.h"
#include "pal_error.h"
#include "pal_regression.h"

#define TEST(x) \
    if (x < 0)  \
    return 1

/* We define this to not link with many unneeded files, which are required by functions in
 * etc_host_info.c which we don't use here. */
void read_text_file_to_cstr(void);
void read_text_file_to_cstr(void) {}

static int ipv4_valid(const char* buf, uint32_t reference_addr) {
    const char* ptr = buf;
    uint32_t ourparser_addr;

    if (!parse_ip_addr_ipv4(&ptr, &ourparser_addr)) {
        pal_printf("Unable to parse %s\n", buf);
        return -1;
    }

    if (reference_addr != ourparser_addr) {
        pal_printf("Invalid result of parsing %s (expected: %.8x, got: %.8x)\n", buf,
                   reference_addr, ourparser_addr);
        return -1;
    }

    return 0;
}

static int ipv4_invalid(const char* buf) {
    uint32_t addr;
    const char* ptr = buf;

    if (parse_ip_addr_ipv4(&ptr, &addr)) {
        pal_printf("We parsed %s successfully, but it is invalid IPv4 address\n", buf);
        return -1;
    }

    return 0;
}

int main(void) {
    TEST(ipv4_valid("255.255.255.255", 0xffffffff));
    TEST(ipv4_valid("8.8.8.8", 0x08080808));
    TEST(ipv4_valid("8.8.8.8 with suffix", 0x08080808));
    TEST(ipv4_valid("0.0.0.0", 0x00000000));
    TEST(ipv4_valid("8.8.10", 0x0808000a));
    TEST(ipv4_valid("8.8.100", 0x08080064));
    TEST(ipv4_valid("8.243", 0x080000f3));
    TEST(ipv4_valid("8.193000", 0x0802f1e8));
    TEST(ipv4_valid("7", 0x00000007));
    TEST(ipv4_valid("999000123", 0x3b8b883b));

    TEST(ipv4_invalid(""));
    TEST(ipv4_invalid("255.255.255.930"));
    TEST(ipv4_invalid("255.255.300.255"));
    TEST(ipv4_invalid("255.400.255.255"));
    TEST(ipv4_invalid("400.255.255.255"));
    TEST(ipv4_invalid("0.255.255.1000000000"));
    TEST(ipv4_invalid("1000000000000000.255.255.0"));
    TEST(ipv4_invalid("8.8.8.8a"));
    TEST(ipv4_invalid("8.8.8.b8"));
    TEST(ipv4_invalid("8.8.8a.8"));
    TEST(ipv4_invalid("8.8.b8.8"));
    TEST(ipv4_invalid("8.8b.8.8"));
    TEST(ipv4_invalid("8.a8.8.8"));
    TEST(ipv4_invalid("8c.8.8.8"));
    TEST(ipv4_invalid("d8.8.8.8"));
    TEST(ipv4_invalid("8.8.8. 8"));
    TEST(ipv4_invalid("8.8.8."));
    TEST(ipv4_invalid("8.8."));
    TEST(ipv4_invalid("8."));
    TEST(ipv4_invalid("8.8..8"));
    TEST(ipv4_invalid(".8.8.8.8"));
    TEST(ipv4_invalid(".8.8.8"));
    TEST(ipv4_invalid("8:8.8.8"));
    TEST(ipv4_invalid("8.8\r.8.8"));
    TEST(ipv4_invalid("8.8.8.\t8"));
    TEST(ipv4_invalid("8.8.+8.8"));
    TEST(ipv4_invalid("8.8.-8.8"));
    TEST(ipv4_invalid("0x8.8.8.8"));
    TEST(ipv4_invalid("8.8.0x8.8"));
    TEST(ipv4_invalid("0b1.8.8.8"));
    TEST(ipv4_invalid("8.b1.8.8"));
    TEST(ipv4_invalid("8.0b1.8.8"));
    TEST(ipv4_invalid("b1.8.8.8"));
    pal_printf("TEST OK\n");

    return 0;
}
