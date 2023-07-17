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
#ifndef __OPTIMIZE__
/* __FILE_NAME__ was introduced in GCC12 and clang9. If it's not defined we do our own magic. */
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
#else  // ifndef __OPTIMIZE__
/* Below macro will be optimized at compile-time, incurring no perf overhead at runtime. */
#define TRUNCATE_FILE_NAME(s) \
    (sizeof(s) > 2 && (s)[sizeof(s)-2] == '/' ? (s) + sizeof(s) - 1 : \
     sizeof(s) > 3 && (s)[sizeof(s)-3] == '/' ? (s) + sizeof(s) - 2 : \
     sizeof(s) > 4 && (s)[sizeof(s)-4] == '/' ? (s) + sizeof(s) - 3 : \
     sizeof(s) > 5 && (s)[sizeof(s)-5] == '/' ? (s) + sizeof(s) - 4 : \
     sizeof(s) > 6 && (s)[sizeof(s)-6] == '/' ? (s) + sizeof(s) - 5 : \
     sizeof(s) > 7 && (s)[sizeof(s)-7] == '/' ? (s) + sizeof(s) - 6 : \
     sizeof(s) > 8 && (s)[sizeof(s)-8] == '/' ? (s) + sizeof(s) - 7 : \
     sizeof(s) > 9 && (s)[sizeof(s)-9] == '/' ? (s) + sizeof(s) - 8 : \
     sizeof(s) > 10 && (s)[sizeof(s)-10] == '/' ? (s) + sizeof(s) - 9 : \
     sizeof(s) > 11 && (s)[sizeof(s)-11] == '/' ? (s) + sizeof(s) - 10 : \
     sizeof(s) > 12 && (s)[sizeof(s)-12] == '/' ? (s) + sizeof(s) - 11 : \
     sizeof(s) > 13 && (s)[sizeof(s)-13] == '/' ? (s) + sizeof(s) - 12 : \
     sizeof(s) > 14 && (s)[sizeof(s)-14] == '/' ? (s) + sizeof(s) - 13 : \
     sizeof(s) > 15 && (s)[sizeof(s)-15] == '/' ? (s) + sizeof(s) - 14 : \
     sizeof(s) > 16 && (s)[sizeof(s)-16] == '/' ? (s) + sizeof(s) - 15 : \
     sizeof(s) > 17 && (s)[sizeof(s)-17] == '/' ? (s) + sizeof(s) - 16 : \
     sizeof(s) > 18 && (s)[sizeof(s)-18] == '/' ? (s) + sizeof(s) - 17 : \
     sizeof(s) > 19 && (s)[sizeof(s)-19] == '/' ? (s) + sizeof(s) - 18 : \
     sizeof(s) > 20 && (s)[sizeof(s)-20] == '/' ? (s) + sizeof(s) - 19 : \
     sizeof(s) > 21 && (s)[sizeof(s)-21] == '/' ? (s) + sizeof(s) - 20 : \
     sizeof(s) > 22 && (s)[sizeof(s)-22] == '/' ? (s) + sizeof(s) - 21 : \
     sizeof(s) > 23 && (s)[sizeof(s)-23] == '/' ? (s) + sizeof(s) - 22 : \
     sizeof(s) > 24 && (s)[sizeof(s)-24] == '/' ? (s) + sizeof(s) - 23 : \
     sizeof(s) > 25 && (s)[sizeof(s)-25] == '/' ? (s) + sizeof(s) - 24 : \
     sizeof(s) > 26 && (s)[sizeof(s)-26] == '/' ? (s) + sizeof(s) - 25 : \
     sizeof(s) > 27 && (s)[sizeof(s)-27] == '/' ? (s) + sizeof(s) - 26 : \
     sizeof(s) > 28 && (s)[sizeof(s)-28] == '/' ? (s) + sizeof(s) - 27 : \
     sizeof(s) > 29 && (s)[sizeof(s)-29] == '/' ? (s) + sizeof(s) - 28 : \
     sizeof(s) > 30 && (s)[sizeof(s)-30] == '/' ? (s) + sizeof(s) - 29 : \
     sizeof(s) > 31 && (s)[sizeof(s)-31] == '/' ? (s) + sizeof(s) - 30 : \
     sizeof(s) > 32 && (s)[sizeof(s)-32] == '/' ? (s) + sizeof(s) - 31 : \
     sizeof(s) > 33 && (s)[sizeof(s)-33] == '/' ? (s) + sizeof(s) - 32 : \
     sizeof(s) > 34 && (s)[sizeof(s)-34] == '/' ? (s) + sizeof(s) - 33 : \
     sizeof(s) > 35 && (s)[sizeof(s)-35] == '/' ? (s) + sizeof(s) - 34 : (s))
#define __FILE_NAME__ (TRUNCATE_FILE_NAME(__FILE__))
#endif // ifndef __OPTIMIZE__
#endif // #ifndef __FILE_NAME__

/* All of them implicitly append a newline at the end of the message. */
#define log_always(fmt...)   _log(LOG_LEVEL_NONE, __FILE_NAME__, __func__, __LINE__, fmt)
#define log_error(fmt...)    _log(LOG_LEVEL_ERROR, __FILE_NAME__, __func__, __LINE__, fmt)
#define log_warning(fmt...)  _log(LOG_LEVEL_WARNING, __FILE_NAME__, __func__, __LINE__, fmt)
#define log_debug(fmt...)    _log(LOG_LEVEL_DEBUG, __FILE_NAME__, __func__, __LINE__, fmt)

#define log_trace(fmt...)    _log(LOG_LEVEL_TRACE, __FILE_NAME__, __func__, __LINE__, fmt)
