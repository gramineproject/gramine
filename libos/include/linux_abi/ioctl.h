/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#pragma once

/* Types and structures used by various Linux ABIs (e.g. syscalls). */
/* These need to be binary-identical with the ones used by Linux. */
/* Exclude conflicting `ioctl' function and only include list of `ioctl' requests. */
#ifndef	_SYS_IOCTL_H
#define	_SYS_IOCTL_H 1
#include <bits/ioctls.h>
#endif
