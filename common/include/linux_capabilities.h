/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Fortanix
 *                    Nirjhar Roy <nirjhar.roy@fortanix.com>
 */

#pragma once

#include <stdint.h>

/* The values of the following macros are taken from
 * https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/capability.h#L30 */
#define GRAMINE_LINUX_CAPABILITY_VERSION_1  0x19980330
#define GRAMINE_LINUX_CAPABILITY_VERSION_2  0x20071026
#define GRAMINE_LINUX_CAPABILITY_VERSION_3  0x20080522

#define CAP_SETPCAP 8
/* The following definition of struct gramine_user_cap_header and struct gramine_user_cap_data is
 * taken from
 * https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/capability.h#L39
 * and
 * https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/capability.h#L44 */
struct gramine_user_cap_header {
    uint32_t version;
    int pid;
};

struct gramine_user_cap_data {
    uint32_t effective;
    uint32_t permitted;
    uint32_t inheritable;
};
