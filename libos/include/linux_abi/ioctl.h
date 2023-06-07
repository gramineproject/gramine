/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#pragma once

/* Types and structures used by various Linux ABIs (e.g. syscalls). */
/* These need to be binary-identical with the ones used by Linux. */

#include <asm/ioctls.h>

#define SIOCGIFCONF    0x8912  /* get iface list */
#define SIOCGIFHWADDR  0x8927  /* get hardware address */
