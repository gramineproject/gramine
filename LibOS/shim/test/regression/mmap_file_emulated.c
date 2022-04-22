/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Paweł Marczewski <pawel@invisiblethingslab.com>
 */

/*
 * Test file mapping emulated by Gramine (encrypted: tmpfs): try reading and writing a file through
 * a mapping.
 */

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "rw_file.h"

/* NOTE: these two messages should have equal length */
#define MESSAGE1 "hello world\n  "
#define MESSAGE2 "goodbye world\n"
#define MESSAGE_LEN (sizeof(MESSAGE1) - 1)

int main(int argc, char** argv) {
    ssize_t ret;
    int fd;

    if (argc != 2)
        errx(1, "Usage: %s path", argv[0]);

    const char* path = argv[1];

    setbuf(stdout, NULL);

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size < 0)
        err(1, "sysconf");

    size_t mmap_size = page_size;
    assert(MESSAGE_LEN + 1 <= mmap_size);

    /* Create a new file */

    fd = open(path, O_WRONLY | O_CREAT, 0666);
    if (fd < 0)
        err(1, "open");

    ret = posix_fd_write(fd, MESSAGE1, MESSAGE_LEN);
    if (ret < 0)
        err(1, "failed to write file");
    if ((size_t)ret < MESSAGE_LEN)
        err(1, "not enough bytes written");

    ret = close(fd);
    if (ret < 0)
        err(1, "close");

    printf("CREATE OK\n");

    /* Open and map it */

    fd = open(path, O_RDWR, 0);
    if (fd == -1)
        err(1, "open");


    void* addr = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED)
        err(1, "mmap");

    if (memcmp(addr, MESSAGE1, MESSAGE_LEN))
        errx(1, "wrong mapping content (%s)", (char*)addr);

    for (size_t i = MESSAGE_LEN; i < mmap_size; i++) {
        if (((char*)addr)[i] != 0)
            errx(1, "unexpected non-zero byte at position %zu", i);
    }

    printf("MAP OK\n");

    /* Write new message through mmap, then close it */

    strcpy(addr, MESSAGE2);

    ret = munmap(addr, mmap_size);
    if (ret < 0)
        err(1, "munmap");

    ret = close(fd);
    if (ret == -1)
        err(1, "close");

    printf("WRITE OK\n");

    /* Check if the file contains new message */

    char buf[MESSAGE_LEN];

    ret = posix_file_read(path, buf, sizeof(buf));
    if ((size_t)ret < MESSAGE_LEN)
        err(1, "not enough bytes read");

    if (memcmp(buf, MESSAGE2, MESSAGE_LEN))
        errx(1, "wrong file content");

    printf("TEST OK\n");

    return 0;
}
