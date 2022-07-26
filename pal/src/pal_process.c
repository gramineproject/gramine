/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This source file contains functions to create a child process and terminate the running process.
 * Child does not inherit any objects or memory from its parent process. A parent process may not
 * modify the execution of its children. It can wait for a child to exit using its handle. Also,
 * parent and child may communicate through I/O streams provided by the parent to the child at
 * creation.
 */

#include "pal.h"
#include "pal_internal.h"

int PalProcessCreate(const char** args, uintptr_t (*reserved_mem_ranges)[2],
                     size_t reserved_mem_ranges_len, PAL_HANDLE* out_handle) {
    *out_handle = NULL;
    return _PalProcessCreate(args, reserved_mem_ranges, reserved_mem_ranges_len, out_handle);
}

noreturn void PalProcessExit(int exitcode) {
    _PalProcessExit(exitcode);
}
