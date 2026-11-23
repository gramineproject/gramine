/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * Checks that errors returned by the host reach the application with the same error codes as on
 * Linux.
 *
 * Usage: host_errno <dir>, where <dir> is a host-backed directory that contains only `loop`, a
 * symbolic link to itself. Must be run with a host limit on open files lower than RLIMIT_NOFILE
 * inside Gramine, so that the host runs out of file descriptors first.
 */

#define _GNU_SOURCE
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#include "common.h"

#define MAX_FDS 1024

static void check_error(const char* desc, int ret, int expected_errno) {
    if (ret != -1 || errno != expected_errno)
        errx(1, "%s returned %d with errno %d, expected -1 with errno %d", desc, ret, errno,
             expected_errno);
}

int main(int argc, char** argv) {
    if (argc != 2)
        errx(1, "usage: %s <dir>", argv[0]);

    const char* dir = argv[1];
    char file[256];
    char loop[256];
    snprintf(file, sizeof(file), "%s/file", dir);
    snprintf(loop, sizeof(loop), "%s/loop", dir);

    int fd = CHECK(open(file, O_WRONLY | O_CREAT | O_EXCL, 0644));
    CHECK(close(fd));

    check_error("rmdir(non-empty directory)", rmdir(dir), ENOTEMPTY);
    check_error("unlinkat(non-empty directory, AT_REMOVEDIR)",
                unlinkat(AT_FDCWD, dir, AT_REMOVEDIR), ENOTEMPTY);

    check_error("open(symbolic link to itself)", open(loop, O_RDONLY), ELOOP);

    /* listing the directory must not fail because of `loop` */
    DIR* dirp = opendir(dir);
    if (!dirp)
        err(1, "opendir");
    errno = 0;
    while (readdir(dirp))
        ;
    if (errno)
        err(1, "readdir");
    CHECK(closedir(dirp));

    static int fds[MAX_FDS];
    size_t count = 0;
    while ((fd = open(file, O_RDONLY)) >= 0) {
        if (count == MAX_FDS)
            errx(1, "opened %d files without an error", MAX_FDS);
        fds[count++] = fd;
    }
    check_error("open() with no host fd left", fd, EMFILE);

    int pipefds[2];
    check_error("pipe() with no host fd left", pipe(pipefds), EMFILE);

    for (size_t i = 0; i < count; i++)
        CHECK(close(fds[i]));

    CHECK(unlink(file));
    puts("TEST OK");
    return 0;
}
