/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation */

#ifndef PAL_REGRESSION_H
#define PAL_REGRESSION_H

#include "pal.h"

void __attribute__((format(printf, 1, 2))) pal_printf(const char* fmt, ...);
void __attribute__((format(printf, 2, 3))) _log(int level, const char* fmt, ...);

#define CHECK(x) ({                                                 \
    __typeof__(x) _x = (x);                                         \
    if (_x < 0) {                                                   \
        pal_printf("Error at %s (line %d): %d\n", #x, __LINE__, x); \
        DkProcessExit(1);                                           \
    }                                                               \
    _x;                                                             \
})

#endif /* PAL_REGRESSION_H */
