/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2024 Intel Corporation */

#include "assert.h"
#include "list.h"
#include "lru_composite_key_cache.h"

#ifdef IN_TOOLS

#include <stdio.h>
#include <stdlib.h>

#define uthash_fatal(msg)                            \
    do {                                             \
        fprintf(stderr, "uthash error: %s\n", msg);  \
        exit(-1);                                    \
    } while(0)

#else

#include "api.h"

#define uthash_fatal(msg)                            \
    do {                                             \
        log_error("uthash error: %s", msg);          \
        abort();                                     \
    } while(0)

#endif

#include "uthash.h"

DEFINE_LIST(lruc_composite_key_list_node);
struct lruc_composite_key_list_node {
    LIST_TYPE(lruc_composite_key_list_node) list;
    struct lruc_composite_key key;
};
DEFINE_LISTP(lruc_composite_key_list_node);

struct lruc_composite_key_map_node {
    struct lruc_composite_key key;
    void* data;
    struct lruc_composite_key_list_node* list_ptr;
    UT_hash_handle hh;
};

struct lruc_composite_key_context {
    /* list and map both contain the same objects (list contains keys, map contains actual data).
     * They're kept in sync so that map is used for fast lookups and list is used for fast LRU.
     */
    LISTP_TYPE(lruc_composite_key_list_node) list;
    struct lruc_composite_key_map_node* map;
    struct lruc_composite_key_list_node* current; /* current head of the cache */
};

struct lruc_composite_key_context* lruc_composite_key_create(void) {
    struct lruc_composite_key_context* lruc = calloc(1, sizeof(*lruc));
    if (!lruc)
        return NULL;

    INIT_LISTP(&lruc->list);
    lruc->map     = NULL;
    lruc->current = NULL;
    return lruc;
};

static struct lruc_composite_key_map_node* get_map_node(struct lruc_composite_key_context* lruc,
                                                        struct lruc_composite_key key) {
    struct lruc_composite_key_map_node* mn = NULL;
    HASH_FIND(hh, lruc->map, &key, sizeof(struct lruc_composite_key), mn);
    return mn;
}

void lruc_composite_key_destroy(struct lruc_composite_key_context* lruc) {
    struct lruc_composite_key_list_node* ln;
    struct lruc_composite_key_list_node* tmp;
    struct lruc_composite_key_map_node* mn;

    LISTP_FOR_EACH_ENTRY_SAFE(ln, tmp, &lruc->list, list) {
        mn = get_map_node(lruc, ln->key);
        if (mn) {
            HASH_DEL(lruc->map, mn);
            free(mn);
        }
        LISTP_DEL(ln, &lruc->list, list);
        free(ln);
    }

    assert(LISTP_EMPTY(&lruc->list));
    assert(HASH_COUNT(lruc->map) == 0);
    free(lruc);
}

bool lruc_composite_key_add(struct lruc_composite_key_context* lruc,
                            struct lruc_composite_key* key, void* data) {
    if (get_map_node(lruc, *key))
        return false;

    struct lruc_composite_key_map_node* map_node = calloc(1, sizeof(*map_node));
    if (!map_node)
        return false;

    struct lruc_composite_key_list_node* list_node = calloc(1, sizeof(*list_node));
    if (!list_node) {
        free(map_node);
        return false;
    }

    list_node->key = *key;
    map_node->key = *key;
    LISTP_ADD(list_node, &lruc->list, list);
    map_node->data     = data;
    map_node->list_ptr = list_node;
    HASH_ADD(hh, lruc->map, key, sizeof(struct lruc_composite_key), map_node);
    return true;
}

void* lruc_composite_key_find(struct lruc_composite_key_context* lruc,
                              struct lruc_composite_key* key) {
    struct lruc_composite_key_map_node* mn = get_map_node(lruc, *key);
    if (mn)
        return mn->data;
    return NULL;
}

void* lruc_composite_key_get(struct lruc_composite_key_context* lruc,
                             struct lruc_composite_key* key) {
    struct lruc_composite_key_map_node* mn = get_map_node(lruc, *key);
    if (!mn)
        return NULL;
    struct lruc_composite_key_list_node* ln = mn->list_ptr;
    assert(ln != NULL);
    // move node to the front of the list
    LISTP_DEL(ln, &lruc->list, list);
    LISTP_ADD(ln, &lruc->list, list);
    return mn->data;
}

size_t lruc_composite_key_size(struct lruc_composite_key_context* lruc) {
    return HASH_COUNT(lruc->map);
}

void* lruc_composite_key_get_first(struct lruc_composite_key_context* lruc) {
    if (LISTP_EMPTY(&lruc->list))
        return NULL;

    lruc->current = LISTP_FIRST_ENTRY(&lruc->list, /*unused*/ 0, list);
    struct lruc_composite_key_map_node* mn = get_map_node(lruc, lruc->current->key);
    assert(mn != NULL);
    return mn ? mn->data : NULL;
}

void* lruc_composite_key_get_next(struct lruc_composite_key_context* lruc) {
    if (LISTP_EMPTY(&lruc->list) || !lruc->current)
        return NULL;

    lruc->current = LISTP_NEXT_ENTRY(lruc->current, &lruc->list, list);
    if (!lruc->current)
        return NULL;

    struct lruc_composite_key_map_node* mn = get_map_node(lruc, lruc->current->key);
    assert(mn != NULL);
    return mn ? mn->data : NULL;
}

void* lruc_composite_key_get_last(struct lruc_composite_key_context* lruc) {
    if (LISTP_EMPTY(&lruc->list))
        return NULL;

    struct lruc_composite_key_list_node* ln = LISTP_LAST_ENTRY(&lruc->list, /*unused*/ 0, list);
    struct lruc_composite_key_map_node* mn = get_map_node(lruc, ln->key);
    assert(mn != NULL);
    return mn ? mn->data : NULL;
}

void lruc_composite_key_remove_last(struct lruc_composite_key_context* lruc) {
    if (LISTP_EMPTY(&lruc->list))
        return;

    struct lruc_composite_key_list_node* ln = LISTP_LAST_ENTRY(&lruc->list, /*unused*/ 0, list);
    LISTP_DEL(ln, &lruc->list, list);
    struct lruc_composite_key_map_node* mn = get_map_node(lruc, ln->key);
    assert(mn != NULL);
    if (mn)
        HASH_DEL(lruc->map, mn);
    free(ln);
    free(mn);
}
