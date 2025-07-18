/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation */

/* Least-recently used cache with composite key, used by the trusted file implementation
   for optimizing data access */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct lruc_composite_key {
    uint64_t id;
    uint64_t chunk_number;
};

struct lruc_composite_key_context;

struct lruc_composite_key_context* lruc_composite_key_create(void);
void lruc_composite_key_destroy(struct lruc_composite_key_context* context);
bool lruc_composite_key_add(struct lruc_composite_key_context* context,
                            struct lruc_composite_key* key, void* data);
void* lruc_composite_key_get(struct lruc_composite_key_context* context,
                             struct lruc_composite_key* key);
void* lruc_composite_key_find(struct lruc_composite_key_context* context,
                              struct lruc_composite_key* key);
size_t lruc_composite_key_size(struct lruc_composite_key_context* context);
void* lruc_composite_key_get_first(struct lruc_composite_key_context* context);
void* lruc_composite_key_get_next(struct lruc_composite_key_context* context);
void* lruc_composite_key_get_last(struct lruc_composite_key_context* context);
void lruc_composite_key_remove_last(struct lruc_composite_key_context* context);
