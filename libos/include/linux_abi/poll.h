/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#pragma once

/* Types and structures used by various Linux ABIs (e.g. syscalls). */
/* These need to be binary-identical with the ones used by Linux. */

#include <asm/poll.h>
#include <linux/eventpoll.h>

struct linux_fd_set {
    unsigned long fds_bits[1024 / (8 * sizeof(unsigned long))];
};

#ifndef EPOLLNVAL
/* This is not defined in the older kernels e.g. the default kernel on Ubuntu 18.04. */
#define EPOLLNVAL ((uint32_t)0x00000020)
#endif
