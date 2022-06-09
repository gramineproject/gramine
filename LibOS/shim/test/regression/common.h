/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

#ifndef COMMON_H_
#define COMMON_H_

#include "err.h"

#define OVERFLOWS(type, val)                        \
    ({                                              \
        type __dummy;                               \
        __builtin_add_overflow((val), 0, &__dummy); \
    })

#define CHECK(x) ({                                     \
    __typeof__(x) _x = (x);                             \
    if (_x == -1) {                                     \
        err(1, "error at %s (line %d)", #x, __LINE__);  \
    }                                                   \
    _x;                                                 \
})

#endif /* COMMON_H_ */
