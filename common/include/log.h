/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation */

#pragma once

#include "callbacks.h"

enum {
    LOG_LEVEL_NONE    = 0,
    LOG_LEVEL_ERROR   = 1,
    LOG_LEVEL_WARNING = 2,
    LOG_LEVEL_DEBUG   = 3,
    LOG_LEVEL_TRACE   = 4,
    LOG_LEVEL_ALL     = 5,
};

/*
 * __FILE_NAME__ was introduced in GCC12 and clang9.
 * If it's not defined we have to do our own magic.
 */
#ifndef __FILE_NAME__
static inline const char* truncate_file_name(const char* filename) {
    const char* ret = filename;

    while (*filename != '\0') {
        if (*filename == '/') {
            ret = filename + 1;
        }
        filename++;
    }

    return ret;
}

#define __FILE_NAME__ (truncate_file_name(__FILE__))
#endif

/* All of them implicitly append a newline at the end of the message. */
#define log_always(fmt...)   _log(LOG_LEVEL_NONE, __FILE_NAME__, __func__, __LINE__, fmt)
#define log_error(fmt...)    _log(LOG_LEVEL_ERROR, __FILE_NAME__, __func__, __LINE__, fmt)
#define log_warning(fmt...)  _log(LOG_LEVEL_WARNING, __FILE_NAME__, __func__, __LINE__, fmt)
#define log_debug(fmt...)    _log(LOG_LEVEL_DEBUG, __FILE_NAME__, __func__, __LINE__, fmt)

#define log_trace(fmt...)    _log(LOG_LEVEL_TRACE, __FILE_NAME__, __func__, __LINE__, fmt)
