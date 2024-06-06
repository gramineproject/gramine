/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

/*
 * This file contains a definition for NODISCARD, a macro that wraps
 * the nodiscard attribute introduced in C23. However, because Gramine supports
 * older systems that might not have support for C23, we have to wrap it on our
 * own and change it to a no-op on systems that don't support it.
 * TODO: Remove this after dropping *EL8 and Ubuntu 20.04 support.
 */

#pragma once

#if GRAMINE_HAS_NODISCARD
#define NODISCARD [[nodiscard]]
#else
#define NODISCARD
#endif
