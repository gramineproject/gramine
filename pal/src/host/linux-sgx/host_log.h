/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Outer (host) PAL logging interface. This is initialized separately to inner (enclave) PAL, but
 * (once it's initialized) should output at the level and to the file specified in manifest.
 */

#pragma once

extern int g_host_log_level;
extern int g_host_log_fd;

int host_log_init(const char* path);

// TODO(mkow): We should make it cross-object-inlinable, ideally by enabling LTO, less ideally by
// pasting it here and making `inline`, but our current linker scripts prevent both.
void pal_log(int level, const char* file, const char* func, uint64_t line,
             const char* fmt, ...) __attribute__((format(printf, 5, 6)));
