/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation */

#ifndef RW_FILE_H_
#define RW_FILE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

/* All functions below return the number of bytes read/written on success or -1 (with set errno) on
 * failure. All functions restart read/write syscall in case of EINTR. */

/* Open file `path`, read/write at most `count` bytes into/from buffer `buf`, and close the file.
 * Use POSIX functions: open, read/write, close. */
ssize_t posix_file_read(const char* path, char* buf, size_t count);
ssize_t posix_file_write(const char* path, char* buf, size_t count);

/* Open file `path`, read/write at most `count` bytes into/from buffer `buf`, and close the file.
 * Use stdio functions: fopen, fread/fwrite, fclose. */
ssize_t stdio_file_read(const char* path, char* buf, size_t count);
ssize_t stdio_file_write(const char* path, char* buf, size_t count);

/* Read/write at most `count` bytes into/from buffer `buf`. Use POSIX functions: read/write. */
ssize_t posix_fd_read(int fd, char* buf, size_t count);
ssize_t posix_fd_write(int fd, char* buf, size_t count);

/* Read/write at most `count` bytes into/from buffer `buf`. Use stdio functions: fread/fwrite. */
ssize_t stdio_fd_read(FILE* f, char* buf, size_t count);
ssize_t stdio_fd_write(FILE* f, char* buf, size_t count);

#endif /* RW_FILE_H_ */
