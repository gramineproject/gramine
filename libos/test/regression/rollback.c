/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation
 *                    Michael Steiner <michael.steiner@intel.com>
 */

/* Test for setting and reading encrypted files keys (/dev/attestation/keys). */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "rw_file.h"

// TODO (MST): implement me
// - tests
//   - handles correctly paths which are not encryped files
//   - reports correctly presence/absence of files
//   - for existing files, reports correct state (one for each state)

int main(int argc, char** argv) {
    return 0;
}
