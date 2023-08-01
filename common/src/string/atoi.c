/* Copyright (C) 2021 Intel Corporation
 *                    Vijay Dhanraj <vijay.dhanraj@intel.com>
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "api.h"

static void begin_number(const char* str, int base, const char** out_s, int* out_base,
                         int* out_sign) {
    const char* s = str;

    // gobble initial whitespace
    while (*s == ' ' || *s == '\t') {
        s++;
    }

    // plus/minus sign
    int sign = 1;
    if (*s == '+') {
        s++;
    } else if (*s == '-') {
        s++;
        sign = -1;
    }

    // hex or octal base prefix
    if ((base == 0 || base == 16) && (s[0] == '0' && s[1] == 'x')) {
        s += 2;
        base = 16;
    } else if (base == 0 && s[0] == '0') {
        s++;
        base = 8;
    } else if (base == 0) {
        base = 10;
    }

    *out_s = s;
    *out_base = base;
    *out_sign = sign;
}

long strtol(const char* str, char** out_end, int base) {
    bool nothing_parsed = true;
    const char* s;
    int sign;

    int original_base = base;
    begin_number(str, base, &s, &base, &sign);

    long value = 0;
    while (*s != '\0') {
        int digit = parse_digit(*s, base);
        if (digit == -1) {
            break;
        }

        if (__builtin_mul_overflow(value, base, &value)) {
            return sign > 0 ? LONG_MAX : LONG_MIN;
        }

        if (__builtin_add_overflow(value, digit * sign, &value)) {
            return sign > 0 ? LONG_MAX : LONG_MIN;
        }

        s++;
        nothing_parsed = false;
    }

    if (nothing_parsed && original_base == 0 && base == 8) {
        /* corner case of parsing strtol("+0", .., 0) -- the only digit '0' was eaten by
         * begin_number() which considered it an octal-base prefix, revert it */
        nothing_parsed = false;
        value = 0;
    }

    if (out_end)
        *out_end = (char*)(nothing_parsed ? str : s);
    return value;
}

#ifdef __LP64__
/* long int == long long int on targets with data model LP64 */
long long strtoll(const char* s, char** endptr, int base) {
    return (long long)strtol(s, endptr, base);
}
#else
#error "Unsupported architecture (only support data model LP64)"
#endif

/* Convert a string to an int (without error checking). */
int atoi(const char* str) {
    return (int)atol(str);
}

/* Convert a string to a long int (without error checking). */
long int atol(const char* str) {
    const char* s;
    int sign;
    int base;
    begin_number(str, 10, &s, &base, &sign);
    assert(base == 10);

    long value = 0;
    while (*s != '\0') {
        int digit = parse_digit(*s, 10);
        if (digit == -1)
            break;

        value *= 10;
        value += digit * sign;

        s++;
    }
    return value;
}
