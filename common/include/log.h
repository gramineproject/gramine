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
#else // ifndef __OPTIMIZE__
/* Below macros will be optimized at compile-time, incurring no perf overhead at runtime. */
#define TRY_TRUNCATE_FILE_NAME_AT_LOC(s, loc) \
    (sizeof(s) >= (loc) && (s)[sizeof(s)-(loc)] == '/') ? ((s) + sizeof(s) - (loc) + 1)
#define TRUNCATE_FILE_NAME(s) \
    (TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 1)  : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 2)  : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 3)  : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 4)  : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 5)  : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 6)  : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 7)  : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 8)  : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 9)  : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 10) : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 11) : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 12) : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 13) : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 14) : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 15) : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 16) : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 17) : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 18) : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 19) : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 20) : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 21) : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 22) : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 23) : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 24) : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 25) : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 26) : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 27) : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 28) : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 29) : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 30) : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 31) : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 32) : \
     TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 33) : TRY_TRUNCATE_FILE_NAME_AT_LOC(s, 34) : (s))
#define __FILE_NAME__ (TRUNCATE_FILE_NAME(__FILE__))
#endif // ifndef __OPTIMIZE__
#endif // #ifndef __FILE_NAME__

/* All of them implicitly append a newline at the end of the message. */
#define log_always(fmt...)   _log(LOG_LEVEL_NONE, __FILE_NAME__, __func__, __LINE__, fmt)
#define log_error(fmt...)    _log(LOG_LEVEL_ERROR, __FILE_NAME__, __func__, __LINE__, fmt)
#define log_warning(fmt...)  _log(LOG_LEVEL_WARNING, __FILE_NAME__, __func__, __LINE__, fmt)
#define log_debug(fmt...)    _log(LOG_LEVEL_DEBUG, __FILE_NAME__, __func__, __LINE__, fmt)

#define log_trace(fmt...)    _log(LOG_LEVEL_TRACE, __FILE_NAME__, __func__, __LINE__, fmt)
