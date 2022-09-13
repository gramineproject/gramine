/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

#pragma once

bool parse_ip_addr_ipv4(const char** pptr, uint32_t* out_addr);
bool parse_ip_addr_ipv6(const char** pptr, uint16_t out_addr[8]);
