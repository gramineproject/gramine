/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

#include "api.h"
#include "etc_host_info_internal.h"
#include "pal_error.h"
#include "pal_regression.h"

static int ipv6_valid(const char* buf, uint16_t reference_addr[static 8]) {
    uint16_t addr[8];
    const char* ptr = buf;

    if (!parse_ip_addr_ipv6(&ptr, addr)) {
        pal_printf("Unable to parse \"%s\"\n", buf);
        return -1;
    }

    if (memcmp(reference_addr, addr, sizeof(addr)) != 0) {
        pal_printf(
            "Invalid result of parsing \"%s\" "
            "(expected: %.4x:%.4x:%.4x:%.4x:%.4x:%.4x:%.4x:%.4x, "
            "got: %.4x:%.4x:%.4x:%.4x:%.4x:%.4x:%.4x:%.4x)\n",
            buf, reference_addr[0], reference_addr[1], reference_addr[2], reference_addr[3],
            reference_addr[4], reference_addr[5], reference_addr[6], reference_addr[7],
            addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7]);
        return -1;
    }

    return 0;
}

static int ipv6_invalid(const char* buf) {
    uint16_t addr[8];
    const char* ptr = buf;

    if (parse_ip_addr_ipv6(&ptr, addr)) {
        pal_printf("We parsed \"%s\" successfully, but it's an invalid IPv6 address\n", buf);
        return -1;
    }

    return 0;
}

int main(void) {
    struct {
        const char* str;
        uint16_t addr[8];
    } valid_test_cases[] = {
        {"1::1", {1, 0, 0, 0, 0, 0, 0, 1}},
        {"1337:3333::2137:ffff", {0x1337, 0x3333, 0, 0, 0, 0, 0x2137, 0xFFFF}},
        {"1:2::1", {1, 2, 0, 0, 0, 0, 0, 1}},
        {"1:2:3::1", {1, 2, 3, 0, 0, 0, 0, 1}},
        {"1:2:3:4::1", {1, 2, 3, 4, 0, 0, 0, 1}},
        {"1:2:3:4:5::1", {1, 2, 3, 4, 5, 0, 0, 1}},
        {"1:2:3:4:5:6::1", {1, 2, 3, 4, 5, 6, 0, 1}},
        {"::1", {0, 0, 0, 0, 0, 0, 0, 1}},
        {"::", {0, 0, 0, 0, 0, 0, 0, 0}},
        {"1337:1:2:3:4:5:6:7", {0x1337, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}},
        {"1337:1:2:3:4:5:6:7 suffix", {0x1337, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}},
        {":: suffix", {0, 0, 0, 0, 0, 0, 0, 0}},
        {"::1 suffix", {0, 0, 0, 0, 0, 0, 0, 1}},
        {"1::", {1, 0, 0, 0, 0, 0, 0, 0}},
    };

    for (size_t i = 0; i < ARRAY_SIZE(valid_test_cases); i++) {
        CHECK(ipv6_valid(valid_test_cases[i].str, valid_test_cases[i].addr));
    }

    CHECK(ipv6_invalid("1337:3333:2137"));
    CHECK(ipv6_invalid("1337:1:2:3:4:5:6:7:"));
    CHECK(ipv6_invalid("1337:1:2:3:4:5:6:"));
    CHECK(ipv6_invalid("1337:1:2:3:4:5:"));
    CHECK(ipv6_invalid("1337:1:2:3:4:"));
    CHECK(ipv6_invalid("1337:1:2:3:"));
    CHECK(ipv6_invalid("1337:1:2:"));
    CHECK(ipv6_invalid("1337:1:"));
    CHECK(ipv6_invalid("1337:"));
    CHECK(ipv6_invalid("255.255.255.255"));
    CHECK(ipv6_invalid("1337:1:2:3:4:5:6:0x7"));
    CHECK(ipv6_invalid("1337:1:2:3:4:5:6:-7"));
    CHECK(ipv6_invalid("1337:1:2:3:4:5:6:+7"));
    CHECK(ipv6_invalid("-1337:1:2:3:4:5:6:7"));
    CHECK(ipv6_invalid("+1337:1:2:3:4:5:6:7"));
    CHECK(ipv6_invalid("FFFFF:1:2:3:4:5:6:7"));
    CHECK(ipv6_invalid("FFFF:FFFFF:2:3:4:5:6:7"));
    CHECK(ipv6_invalid("FFFF:FFFF:FFFFF:3:4:5:6:7"));
    CHECK(ipv6_invalid("FFFF:FFFF:FFFF:3:4:5:6:AAAAAA"));
    CHECK(ipv6_invalid("1::\r\r1"));
    CHECK(ipv6_invalid("1:\n:1"));
    CHECK(ipv6_invalid("1::1\r\r:1"));
    CHECK(ipv6_invalid("1::1::"));
    CHECK(ipv6_invalid("::1::1"));
    CHECK(ipv6_invalid("2::1::1"));
    CHECK(ipv6_invalid("2::1::1::3"));
    CHECK(ipv6_invalid("1:::"));
    CHECK(ipv6_invalid("1::::"));
    CHECK(ipv6_invalid("1::0x12"));

    pal_printf("TEST OK\n");

    return 0;
}
