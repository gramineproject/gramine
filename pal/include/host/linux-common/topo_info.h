/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 */

#pragma once

#include "pal.h"

/* Reads up to count bytes from the file into the buf passed.
 * Returns 0 or number of bytes read on success and UNIX error code on failure.
 */
ssize_t read_file_buffer(const char* filename, char* buf, size_t count);

/* Fills topo_info with CPU and NUMA topology from the host */
int get_topology_info(struct pal_topo_info* topo_info);
