/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2021 Intel Corporation */

#include "rw_file.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

ssize_t rw_file_posix(const char* path, char* buf, size_t bytes, bool do_write) {
    ssize_t rv = 0;
    ssize_t ret = 0;

    int fd = open(path, do_write ? O_WRONLY : O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "opening %s failed\n", path);
        return fd;
    }

    while (bytes > rv) {
        if (do_write)
            ret = write(fd, buf + rv, bytes - rv);
        else
            ret = read(fd, buf + rv, bytes - rv);

        if (ret > 0) {
            rv += ret;
        } else if (ret == 0) {
            /* end of file */
            if (rv == 0)
                fprintf(stderr, "%s failed: unexpected end of file\n", do_write ? "write" : "read");
            break;
        } else {
            if (ret < 0 && (errno == EAGAIN || errno == EINTR)) {
                continue;
            } else {
                fprintf(stderr, "%s failed: %s\n", do_write ? "write" : "read", strerror(errno));
                goto out;
            }
        }
    }

out:
    if (ret < 0) {
        /* error path */
        close(fd);
        return ret;
    }

    ret = close(fd);
    if (ret < 0) {
        fprintf(stderr, "closing %s failed\n", path);
        return ret;
    }
    return rv;
}

ssize_t rw_file_stdio(const char* path, char* buf, size_t bytes, bool do_write) {
    size_t rv = 0;
    size_t ret = 0;

    FILE* f = fopen(path, do_write ? "w" : "r");
    if (!f) {
        fprintf(stderr, "opening %s failed\n", path);
        return -1;
    }

    while (bytes > rv) {
        if (do_write)
            ret = fwrite(buf + rv, /*size=*/1, /*nmemb=*/bytes - rv, f);
        else
            ret = fread(buf + rv, /*size=*/1, /*nmemb=*/bytes - rv, f);

        if (ret > 0) {
            rv += ret;
        } else {
            if (feof(f)) {
                if (rv) {
                    /* read some bytes from file, success */
                    break;
                }
                assert(rv == 0);
                fprintf(stderr, "%s failed: unexpected end of file\n", do_write ? "write" : "read");
                fclose(f);
                return -1;
            }

            assert(ferror(f));

            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }

            fprintf(stderr, "%s failed: %s\n", do_write ? "write" : "read", strerror(errno));
            fclose(f);
            return -1;
        }
    }

    int close_ret = fclose(f);
    if (close_ret) {
        fprintf(stderr, "closing %s failed\n", path);
        return -1;
    }
    return rv;
}

ssize_t rw_file_posix_fd(int fd, char* buf, size_t bytes, bool do_write) {
    ssize_t rv = 0;
    ssize_t ret;

    while (bytes > rv) {
        if (do_write)
            ret = write(fd, buf + rv, bytes - rv);
        else
            ret = read(fd, buf + rv, bytes - rv);

        if (ret > 0) {
            rv += ret;
        } else {
            if (ret < 0 && (errno == EAGAIN || errno == EINTR)) {
                continue;
            } else {
                fprintf(stderr, "%s failed:%s\n", do_write ? "write" : "read", strerror(errno));
                return ret;
            }
        }
    }

    return rv;
}
