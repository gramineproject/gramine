/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

/* We have to add a function declaration to avoid warnings.
 * This function is used with NASM, so creating a header is pointless.
 */
int gramine_strcmp(const char* orig, const char* new);

int gramine_strcmp(const char* orig, const char* new) {
    if (orig == new)
        return 0;

    while (*orig != '\0' && *new != '\0' && *orig == *new) {
        orig++;
        new++;
    }

    return *orig != *new;
}
