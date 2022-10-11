/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

#include "api.h"
#include "etc_host_info_internal.h"
#include "pal_error.h"
#include "pal_regression.h"

static int ipv4_valid(const char* buf, uint32_t reference_addr) {
    uint32_t addr;
    const char* ptr = buf;

    if (!parse_ip_addr_ipv4(&ptr, &addr)) {
        pal_printf("Unable to parse \"%s\"\n", buf);
        return -1;
    }

    if (reference_addr != addr) {
        pal_printf("Invalid result of parsing \"%s\" (expected: %.8x, got: %.8x)\n", buf,
                   reference_addr, addr);
        return -1;
    }

    return 0;
}

static int ipv4_invalid(const char* buf) {
    uint32_t addr;
    const char* ptr = buf;

    if (parse_ip_addr_ipv4(&ptr, &addr)) {
        pal_printf("We parsed \"%s\" successfully, but it's an invalid IPv4 address\n", buf);
        return -1;
    }

    return 0;
}

int main(void) {
    CHECK(ipv4_valid("255.255.255.255", 0xffffffff));
    CHECK(ipv4_valid("8.8.8.8", 0x08080808));
    CHECK(ipv4_valid("8.8.8.8 with suffix", 0x08080808));
    CHECK(ipv4_valid("0.0.0.0", 0x00000000));
    CHECK(ipv4_valid("8.8.10", 0x0808000a));
    CHECK(ipv4_valid("8.8.100", 0x08080064));
    CHECK(ipv4_valid("8.243", 0x080000f3));
    CHECK(ipv4_valid("8.193000", 0x0802f1e8));
    CHECK(ipv4_valid("7", 0x00000007));
    CHECK(ipv4_valid("999000123", 0x3b8b883b));

    CHECK(ipv4_invalid(""));
    CHECK(ipv4_invalid("255.255.255.930"));
    CHECK(ipv4_invalid("255.255.300.255"));
    CHECK(ipv4_invalid("255.400.255.255"));
    CHECK(ipv4_invalid("400.255.255.255"));
    CHECK(ipv4_invalid("0.255.255.1000000000"));
    CHECK(ipv4_invalid("1000000000000000.255.255.0"));
    CHECK(ipv4_invalid("8.8.8.8a"));
    CHECK(ipv4_invalid("8.8.8.b8"));
    CHECK(ipv4_invalid("8.8.8a.8"));
    CHECK(ipv4_invalid("8.8.b8.8"));
    CHECK(ipv4_invalid("8.8b.8.8"));
    CHECK(ipv4_invalid("8.a8.8.8"));
    CHECK(ipv4_invalid("8c.8.8.8"));
    CHECK(ipv4_invalid("d8.8.8.8"));
    CHECK(ipv4_invalid("8.8.8. 8"));
    CHECK(ipv4_invalid("8.8.8."));
    CHECK(ipv4_invalid("8.8."));
    CHECK(ipv4_invalid("8."));
    CHECK(ipv4_invalid("8.8..8"));
    CHECK(ipv4_invalid(".8.8.8.8"));
    CHECK(ipv4_invalid(".8.8.8"));
    CHECK(ipv4_invalid("8:8.8.8"));
    CHECK(ipv4_invalid("8.8\r.8.8"));
    CHECK(ipv4_invalid("8.8.8.\t8"));
    CHECK(ipv4_invalid("8.8.+8.8"));
    CHECK(ipv4_invalid("8.8.-8.8"));
    CHECK(ipv4_invalid("8.b1.8.8"));
    CHECK(ipv4_invalid("b1.8.8.8"));
    CHECK(ipv4_invalid("8.8.8.018"));
    CHECK(ipv4_invalid("8.0b1.8.8"));
    CHECK(ipv4_invalid("0b1.8.8.8"));

    /* These addresses are valid ones, but (at least for now) we don't want to support other notions
     * than decimal, because other notions are (probably) not used widely.
     */
    CHECK(ipv4_invalid("8.8.0x8.8"));
    CHECK(ipv4_invalid("8.8.8.017"));
    CHECK(ipv4_invalid("0x8.8.8.8"));

    pal_printf("TEST OK\n");
    return 0;
}
