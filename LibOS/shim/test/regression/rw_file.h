/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation */

#ifndef RW_FILE_H_
#define RW_FILE_H_

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

/* Opens file `path`, reads/writes at most `bytes` bytes into/from buffer `buf`, and closes the
 * file. Uses POSIX functions: open, read/write, close.
 * Returns the number of bytes read/written on success, -1 (with set errno) on failure. */
ssize_t rw_file_posix(const char* path, char* buf, size_t bytes, bool do_write);

/* Opens file `path`, reads/writes at most `bytes` bytes into/from buffer `buf`, and closes the
 * file. Uses stdio functions: fopen, fread/fwrite, fclose.
 * Returns the number of bytes read/written on success, -1 (with set errno) on failure. */
ssize_t rw_file_stdio(const char* path, char* buf, size_t bytes, bool do_write);

/* Reads/writes at most `bytes` bytes into/from buffer `buf`. Uses POSIX functions: open,
 * read/write, close.
 * Returns the number of bytes read/written on success, -1 (with set errno) on failure. */
ssize_t rw_file_posix_fd(int fd, char* buf, size_t bytes, bool do_write);

#endif /* RW_FILE_H_ */
