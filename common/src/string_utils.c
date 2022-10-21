/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Invisible Things Lab
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 * Copyright (C) 2020 Intel Corporation
 */

#include <stdint.h>
#include <stddef.h>

#ifdef USE_STDLIB
#include <string.h>
#else
#include "api.h"
#endif

#include "string_utils.h"

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

    uint64_t value = 0;
    if (__builtin_add_overflow(size, 0, &value))
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
        int digit = parse_digit(*s, base);
        if (digit == -1)
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

bool strstartswith(const char* str, const char* prefix) {
    size_t prefix_len = strlen(prefix);
    size_t str_len = strnlen(str, prefix_len);

    if (str_len < prefix_len) {
        return false;
    }

    return !memcmp(str, prefix, prefix_len);
}

bool strendswith(const char* str, const char* suffix) {
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);

    if (str_len < suffix_len) {
        return false;
    }

    return !memcmp(&str[str_len - suffix_len], suffix, suffix_len);
}

int parse_digit(char c, int base) {
    int digit;

    if (c >= '0' && c <= '9') {
        digit = c - '0';
    } else if (c >= 'a' && c <= 'z') {
        digit = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'Z') {
        digit = c - 'A' + 10;
    } else {
        return -1;
    }
    if (digit >= base)
        return -1;
    return digit;
}
