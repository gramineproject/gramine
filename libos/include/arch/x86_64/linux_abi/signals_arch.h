/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#pragma once

/* Types and structures used by various Linux ABIs (e.g. syscalls). */
/* These need to be binary-identical with the ones used by Linux. */

#define SIGS_CNT 64
#define SIGRTMIN 32

typedef struct {
    unsigned long __val[SIGS_CNT / (8 * sizeof(unsigned long))];
} __sigset_t;

#define RED_ZONE_SIZE 128
