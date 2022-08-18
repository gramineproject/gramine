/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

#pragma once

#include "pal.h"

/* Function to fetch the hostname */
int get_hostname(char* hostname, size_t size);
