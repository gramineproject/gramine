/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Kailun Qin <kailun.qin@intel.com>
 */

#include <stdint.h>
#include <stddef.h>

#include "api.h"

int parse_size_str(const char* str, uint64_t* out_val) {
    const char* endptr = NULL;
    unsigned long size;
    int ret = str_to_ulong(str, 10, &size, &endptr);
    if (ret < 0)
        return -1;

    unsigned long unit = 1;
    if (*endptr == 'G' || *endptr == 'g') {
        unit = 1024 * 1024 * 1024;
        endptr++;
    } else if (*endptr == 'M' || *endptr == 'm') {
        unit = 1024 * 1024;
        endptr++;
    } else if (*endptr == 'K' || *endptr == 'k') {
        unit = 1024;
        endptr++;
    }

    if (__builtin_mul_overflow(size, unit, &size))
        return -1;

    if (*endptr != '\0')
        return -1; /* garbage found after the size string */

    if (OVERFLOWS(__typeof__(*out_val), size))
        return -1;

    *out_val = size;
    return 0;
}

int str_to_ulong(const char* str, unsigned int base, unsigned long* out_value,
                 const char** out_end) {
    if (base == 16 && str[0] == '0' && str[1] == 'x')
        str += 2;

    unsigned long value = 0;
    const char* s = str;
    while (*s != '\0') {
        int digit;

        if (*s >= '0' && *s <= '9') {
            digit = *s - '0';
        } else if (*s >= 'a' && *s <= 'z') {
            digit = *s - 'a' + 10;
        } else if (*s >= 'A' && *s <= 'Z') {
            digit = *s - 'A' + 10;
        } else {
            break;
        }
        if (digit >= (int)base)
            break;

        if (__builtin_mul_overflow(value, base, &value))
            return -1;

        if (__builtin_add_overflow(value, digit, &value))
            return -1;

        s++;
    }

    if (s == str)
        return -1;

    *out_value = value;
    *out_end = s;
    return 0;
}
