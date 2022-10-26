/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#pragma once

#include <stdbool.h>
#include <stdint.h>

/*!
 * \brief Parse a size (number with optional "G"/"M"/"K" suffix) into an uint64_t.
 *
 * \param      str      A string containing a non-negative, decimal number. The string may end with
 *                      "G"/"g" suffix denoting value in GBs, "M"/"m" for MBs, or "K"/"k" for KBs.
 * \param[out] out_val  Parsed size (in bytes).
 *
 * \returns 0 on success, negative if string cannot be parsed into a size (e.g., suffix is wrong).
 */
int parse_size_str(const char* str, uint64_t* out_val);

/*!
 * \brief Convert a string to number.
 *
 * \param      str        Input string.
 * \param      base       Digit base, between 2 and 36.
 * \param[out] out_value  On success, set to the parsed number.
 * \param[out] out_end    On success, set to the rest of string.
 *
 * \returns 0 on success, negative on failure.
 *
 * Parses a number from the beginning of a string. The number should be non-empty, consist of digits
 * only (no `+`/`-` signs), and not overflow the `unsigned long` type. For base 16, the "0x" prefix
 * is allowed but not required.
 */
int str_to_ulong(const char* str, unsigned int base, unsigned long* out_value,
                 const char** out_end);

bool strstartswith(const char* str, const char* prefix);

bool strendswith(const char* str, const char* suffix);

int parse_digit(char c, int base);
