/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#pragma once

#include <assert.h>
#include <err.h>

#define OVERFLOWS(type, val)                        \
    ({                                              \
        type __dummy;                               \
        __builtin_add_overflow((val), 0, &__dummy); \
    })

#define CHECK(x) ({                                         \
    __typeof__(x) _x = (x);                                 \
    if (_x == -1) {                                         \
        err(1, "error at %s (line %d): %m", #x, __LINE__);  \
    }                                                       \
    _x;                                                     \
})

#define SAME_TYPE(a, b) __builtin_types_compatible_p(__typeof__(a), __typeof__(b))
#define IS_STATIC_ARRAY(a) (!SAME_TYPE(a, &*(a)))

#define ARRAY_LEN(arr) ({                                       \
    static_assert(IS_STATIC_ARRAY(arr), "not a static array");  \
    sizeof(arr) / sizeof(arr[0]);                               \
})

/* We need this artificial assignment in READ_ONCE because of a GCC bug:
 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=99258
 */
#define READ_ONCE(x) ({ __typeof__(x) y = *(volatile __typeof__(x)*)&(x); y;})

#define WRITE_ONCE(x, y) do { *(volatile __typeof__(x)*)&(x) = (y); } while (0)

#define COMPILER_BARRIER() ({ __asm__ __volatile__("" ::: "memory"); })
