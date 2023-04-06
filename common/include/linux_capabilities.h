/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Fortanix Inc
 *                    Nirjhar Roy <nirjhar.roy@fortanix.com> */

#pragma once

#include <stdint.h>

#define GRAMINE_LINUX_CAPABILITY_VERSION_1  0x19980330
#define GRAMINE_LINUX_CAPABILITY_VERSION_2  0x20071026
#define GRAMINE_LINUX_CAPABILITY_VERSION_3  0x20080522
#define GRAMINE_CAP_SETGID 6
#define GRAMINE_CAP_SETUID 7

struct gramine_user_cap_header {
    uint32_t version;
    int pid;
};

struct gramine_user_cap_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};
