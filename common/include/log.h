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

#ifndef __FILE_NAME__
/*
 * __FILE_NAME__ was introduced in GCC12 and clang9. If it's not defined then use clunky __FILE__.
 *
 * (Previously we had a function that emulated __FILE_NAME__ by truncating the file name in a loop
 * but it led to unnecessary calls to this func even when logs were disabled, ultimately resulting
 * in perf overhead).
 */
#define __FILE_NAME__ __FILE__
#endif

/* All of them implicitly append a newline at the end of the message. */
#define log_always(fmt...)   _log(LOG_LEVEL_NONE, __FILE_NAME__, __func__, __LINE__, fmt)
#define log_error(fmt...)    _log(LOG_LEVEL_ERROR, __FILE_NAME__, __func__, __LINE__, fmt)
#define log_warning(fmt...)  _log(LOG_LEVEL_WARNING, __FILE_NAME__, __func__, __LINE__, fmt)
#define log_debug(fmt...)    _log(LOG_LEVEL_DEBUG, __FILE_NAME__, __func__, __LINE__, fmt)

#define log_trace(fmt...)    _log(LOG_LEVEL_TRACE, __FILE_NAME__, __func__, __LINE__, fmt)
