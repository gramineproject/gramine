/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

#pragma once

#include "pal.h"

int parse_resolv_conf(struct pal_dns_host_conf* conf);
