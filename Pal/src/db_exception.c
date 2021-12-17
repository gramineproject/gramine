/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains APIs to set up handlers of exceptions issued by the host, and the methods to
 * pass the exceptions to the upcalls.
 */

#include <errno.h>
#include <stdatomic.h>

#include "api.h"
#include "list.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_internal.h"
#include "spinlock.h"

static spinlock_t g_handler_lock = INIT_SPINLOCK_UNLOCKED;

static pal_event_handler_t g_handlers[PAL_EVENT_NUM_BOUND] = {0};

pal_event_handler_t _DkGetExceptionHandler(enum pal_event event) {
    pal_event_handler_t handler;

    spinlock_lock(&g_handler_lock);
    handler = g_handlers[event];
    spinlock_unlock(&g_handler_lock);

    return handler;
}

void DkSetExceptionHandler(pal_event_handler_t handler, enum pal_event event) {
    assert(handler && event != PAL_EVENT_NO_EVENT && event < ARRAY_SIZE(g_handlers));

    spinlock_lock(&g_handler_lock);
    g_handlers[event] = handler;
    spinlock_unlock(&g_handler_lock);
}

/* The below function is used by stack protector's __stack_chk_fail(), _FORTIFY_SOURCE's *_chk()
 * functions and by assert.h's assert() defined in the common library. Thus it might be called by
 * any PAL thread. */
noreturn void pal_abort(void) {
    _DkProcessExit(ENOTRECOVERABLE);
}

const char* pal_event_name(enum pal_event event) {
    switch (event) {
        case PAL_EVENT_ARITHMETIC_ERROR:
            return "arithmetic exception";

        case PAL_EVENT_MEMFAULT:
            return "memory fault";

        case PAL_EVENT_ILLEGAL:
            return "illegal instruction";

        case PAL_EVENT_QUIT:
            return "signal from external program";

        case PAL_EVENT_INTERRUPTED:
            return "interrupted operation";

        default:
            return "unknown exception";
    }
}
