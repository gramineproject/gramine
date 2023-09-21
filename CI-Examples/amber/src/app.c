/*
 *  Copyright (C) 2022, Intel, All Rights Reserved
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>

int read_to_buffer(const char* fn, char buf[], size_t bufsz);
int write_from_buffer(const char* fn, const char buf[], size_t bufsz);

#define AMBER_TOKEN_DEVFILE "/dev/amber/token"
#define AMBER_SECRET_DEVFILE "/dev/amber/secret"
#define AMBER_USERDATA_DEVFILE "/dev/amber/userdata"
#define AMBER_STATUS_DEVFILE "/dev/amber/status"
#define BUF_SZ 8096

int main(void) {
    int ret;
    char buf[BUF_SZ] = {0};
    size_t user_data_sz;

    /* Example 1 : get Amber token by passing user data in json format,
     * that includes the public key.
     * Amber token will have the claim "amber_runtime",
     * which matches to the user data.
     */
    const char *user_data_json = "{\"type\":\"RSA\", \"key\":\"RHVtbXkga2V5IChkb250IHVzZSBpdCkK\"}";
    user_data_sz = strlen(user_data_json);
    // supply the user data
    ret = write_from_buffer(AMBER_USERDATA_DEVFILE,
                            user_data_json, user_data_sz);
    if (ret == 0) {
        printf("Write to %s: \n%s\nuser data size: %ld\n",
        AMBER_USERDATA_DEVFILE, user_data_json, user_data_sz);
    } else {
        printf("Failed to write to %s: %d\n", AMBER_USERDATA_DEVFILE, ret);
    }

    // read the amber token
    ret = read_to_buffer(AMBER_TOKEN_DEVFILE, buf, BUF_SZ);
    if (ret == 0) {
        printf("Read from %s: \n%s\n", AMBER_TOKEN_DEVFILE, buf);
    } else {
        printf("Failed to read from %s: %d\n", AMBER_TOKEN_DEVFILE, ret);
    }

    // read the status
    ret = read_to_buffer(AMBER_STATUS_DEVFILE, buf, BUF_SZ);
    if (ret == 0) {
        printf("Read from %s: \n%s\n", AMBER_STATUS_DEVFILE, buf);
    } else {
        printf("Failed to read from %s: %d\n", AMBER_STATUS_DEVFILE, ret);
    }

    /* Example 2 - [Deprecated]: get Amber token by passing user data in string format,
     * Amber token will have the claim "amber_tee_held_data",
     * which matches to the user data.
     */
    const char *user_data_string = "a dummy public key here";
    user_data_sz = strlen(user_data_string);
    // supply the user data
    ret = write_from_buffer(AMBER_USERDATA_DEVFILE,
                            user_data_string, user_data_sz);
    if (ret == 0) {
        printf("Write to %s: \n%s\nuser data size: %ld\n",
        AMBER_USERDATA_DEVFILE, user_data_string, user_data_sz);
    } else {
        printf("Failed to write to %s: %d\n", AMBER_USERDATA_DEVFILE, ret);
    }

    // read the amber token
    ret = read_to_buffer(AMBER_TOKEN_DEVFILE, buf, BUF_SZ);
    if (ret == 0) {
        printf("Read from %s: \n%s\n", AMBER_TOKEN_DEVFILE, buf);
    } else {
        printf("Failed to read from %s: %d\n", AMBER_TOKEN_DEVFILE, ret);
    }

    // read the status
    ret = read_to_buffer(AMBER_STATUS_DEVFILE, buf, BUF_SZ);
    if (ret == 0) {
        printf("Read from %s: \n%s\n", AMBER_STATUS_DEVFILE, buf);
    } else {
        printf("Failed to read from %s: %d\n", AMBER_STATUS_DEVFILE, ret);
    }

    return ret;
}

/*
 * this function is used to read the content of a file to a buffer
 */
int read_to_buffer(const char* fn, char buf[], size_t bufsz) {
    int ret;
    ssize_t cnt;
    int fd = open(fn, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[error] cannot open '%s'\n"
                        "Please make sure this app is running with Gramine-SGX\n", fn);
        return -1;
    }

    ssize_t bytes_read = 0;
    while (1) {
        cnt = read(fd, buf + bytes_read, bufsz - bytes_read);
        if (cnt > 0) {
            bytes_read += cnt;
        } else if (cnt == 0) {
            /* end of file */
            buf[bytes_read] = '\0';
            break;
        } else if (errno == EAGAIN || errno == EINTR) {
            continue;
        } else {
            fprintf(stderr, "[error] cannot read '%s'\n", fn);
            close(fd);
            return -1;
        }
    }

    ret = close(fd);
    if (ret < 0) {
        fprintf(stderr, "[error] cannot close '%s'\n", fn);
        return -1;
    }

    return ret;
}

/*
 * this function is used to write a buffer to a file
 */
int write_from_buffer(const char* fn, const char buf[], size_t bufsz) {
    int ret;
    ssize_t cnt;
    int fd = open(fn, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "[error] cannot open '%s'\n"
                        "Please make sure this app is running with Gramine-SGX\n", fn);
        return -1;
    }
    off_t offset = 0;
    while (bufsz > 0) {
        cnt = write(fd, buf + offset, bufsz);
        if (cnt < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            fprintf(stderr, "[error] cannot write '%s'\n", fn);
            close(fd);
            return -1;
        }
        bufsz -= cnt;
        offset += cnt;
    }

    ret = close(fd);
    if (ret < 0) {
        fprintf(stderr, "[error] cannot close '%s'\n", fn);
        return -1;
    }

    return ret;
}
