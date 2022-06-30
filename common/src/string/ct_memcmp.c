/* SPDX-License-Identifier: Apache-2.0 */
/* Adapted from Mbed TLS v3.1.0.
 * Copyright (C) 2021, The Mbed TLS Contributors
 *               2022, Intel Corporation
 */

#include "api.h"

int ct_memcmp(const void* lhs, const void* rhs, size_t count) {
    size_t i;
    volatile const unsigned char *l = (volatile const unsigned char *) lhs;
    volatile const unsigned char *r = (volatile const unsigned char *) rhs;
    volatile unsigned char diff = 0;

    for (i = 0; i < count; i++) {
        /* Read volatile data in order before computing diff to avoid the warning:
         * 'the order of volatile accesses is undefined ..' */
        unsigned char x = l[i], y = r[i];
        diff |= x ^ y;
    }

    return (int)diff;
}
