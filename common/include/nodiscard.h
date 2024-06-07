/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

/*
 * This file contains a definition for NODISCARD, a macro that wraps
 * the nodiscard attribute introduced in C23. However, because Gramine supports
 * older systems that might not have support for C23, we have to wrap it on our
 * own and change it to a no-op on systems that don't support it.
 * TODO: Remove the macros and use [[nodiscard]] directly, after dropping *EL8
 *       and Ubuntu 20.04 support.
 */

#pragma once

#if defined(__has_c_attribute)
#if __has_c_attribute(nodiscard)
#define NODISCARD [[nodiscard]]
#endif
#endif

#ifndef NODISCARD
#define NODISCARD
#endif
