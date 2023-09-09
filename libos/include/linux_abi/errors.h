/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

#pragma once

/* Types and structures used by various Linux ABIs (e.g. syscalls). */
/* These need to be binary-identical with the ones used by Linux. */

#include "linux_abi/errors_arch.h"

#define ERESTARTSYS     512 /* Usual case - restart if SA_RESTART is set. */
#define ERESTARTNOINTR  513 /* Always restart. */
#define ERESTARTNOHAND  514 /* Restart if no signal handler. */
