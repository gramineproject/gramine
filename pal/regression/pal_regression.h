/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation */

#pragma once

#include "pal.h"
#include "pal_error.h"

void __attribute__((format(printf, 1, 2))) pal_printf(const char* fmt, ...);

#define CHECK(x) ({                                                     \
    __typeof__(x) _x = (x);                                             \
    if (_x < 0) {                                                       \
        pal_printf("Error at %s (line %d): %d\n", #x, __LINE__, _x);    \
        PalProcessExit(1);                                              \
    }                                                                   \
    _x;                                                                 \
})

#define FAIL(fmt...) ({ \
    pal_printf(fmt);    \
    pal_printf("\n");   \
    PalProcessExit(1);  \
})

#define SAME_TYPE(a, b) __builtin_types_compatible_p(__typeof__(a), __typeof__(b))
#define IS_STATIC_ARRAY(a) (!SAME_TYPE(a, &*(a)))

#define ARRAY_LEN(arr) ({                                       \
    static_assert(IS_STATIC_ARRAY(arr), "not a static array");  \
    sizeof(arr) / sizeof(arr[0]);                               \
})

void init_memory_management(void);
int mem_bkeep_alloc(size_t size, uintptr_t* out_addr);
int mem_bkeep_free(uintptr_t addr, size_t size);
int memory_alloc(size_t size, pal_prot_flags_t prot, void** out_addr);
int memory_free(void* addr, size_t size);
