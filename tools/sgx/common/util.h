/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Rafal Wojdyla <omeg@invisiblethingslab.com>
 */

#pragma once

#define _GNU_SOURCE

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Miscellaneous helper functions */

/*! Order of bytes for hex strings (display and parsing) */
typedef enum _endianness_t {
    ENDIAN_LSB,
    ENDIAN_MSB,
} endianness_t;

extern int g_stdout_fd;
extern int g_stderr_fd;
extern bool g_verbose;
extern endianness_t g_endianness;

/* Print functions */
#define DBG(fmt, ...)                                 \
    do {                                              \
        if (g_verbose)                                \
            dprintf(g_stdout_fd, fmt, ##__VA_ARGS__); \
    } while (0)

#define INFO(fmt, ...)                            \
    do {                                          \
        dprintf(g_stdout_fd, fmt, ##__VA_ARGS__); \
    } while (0)

#define ERROR(fmt, ...)                                                \
    do {                                                               \
        dprintf(g_stderr_fd, "%s: " fmt, __FUNCTION__, ##__VA_ARGS__); \
    } while (0)

/*! Set verbosity level */
void set_verbose(bool verbose);

/*! Get verbosity level */
bool get_verbose(void);

/*! Set endianness for hex strings */
void set_endianness(endianness_t endianness);

/*! Get endianness for hex strings */
endianness_t get_endianness(void);

/*! Set stdout/stderr descriptors */
void util_set_fd(int stdout_fd, int stderr_fd);

/*! Get file size, return (uint64_t)-1 on error */
uint64_t get_file_size(int fd);

/*!
 * \brief Read file contents.
 *
 * \param         path    Path to the file.
 * \param[in,out] size    On entry, number of bytes to read. 0 means to read the entire file.
 *                        On exit, number of bytes read. Unchanged on failure.
 * \param         buffer  Buffer to read data to. If NULL, this function allocates one.
 *
 * \returns On success, pointer to the data buffer. If \p buffer was NULL, caller should free it.
 *          On failure, NULL.
 *
 * If \p buffer is not NULL, \p size must contain valid buffer size.
 */
void* read_file(const char* path, size_t* size, void* buffer);

/*! Write buffer to file */
int write_file(const char* path, size_t size, const void* buffer);

/*! Append buffer to file */
int append_file(const char* path, size_t size, const void* buffer);

/*! Print memory as hex to buffer */
int hexdump_mem_to_buffer(const void* data, size_t size, char* buffer, size_t buffer_size);

/*! Print memory as hex */
void hexdump_mem(const void* data, size_t size);

/*! Print variable as hex */
#define HEXDUMP(x) hexdump_mem((const void*)&(x), sizeof(x))

/*!
 * \brief Parse hex string to buffer
 *
 * \param hex          Hex string to be parsed.
 * \param buffer       Output buffer.
 * \param buffer_size  Size of the buffer.
 * \param mask         If non-NULL, this string will be used in error messages instead of the input
 *                     hexstring itself. Use when parsing sensitive data.
 *
 * \returns 0 on success, otherwise -1.
 *
 * Unless the string contains exactly 2 * buffer_size hexdigits, an error will be raised.
 */
int parse_hex(const char* hex, void* buffer, size_t buffer_size, const char* mask);

/*!
 * \brief Returns normalized path
 *
 * \param path        Input path to be normalized.
 * \param buf         Output buffer with normalized path.
 * \param inout_size  Before call, `*inout_size` should hold the size of buf. After call, it holds
 *                    number of bytes actually written to it (including the ending '\0'). This
 *                    number is never greater than the size of the input path.
 *
 * \returns 0 on success, otherwise -1.
 */
int get_norm_path(const char* path, char* buf, size_t* inout_size);
