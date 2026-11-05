/* SPDX-License-Identifier: LGPL-3.0-or-later */

/* Checks that lseek() on stdin fails with ESPIPE when stdin is a pipe on the host. */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main(void) {
    errno     = 0;
    off_t ret = lseek(STDIN_FILENO, 0, SEEK_CUR);
    if (ret != -1 || errno != ESPIPE)
        errx(1, "lseek(stdin) returned %ld with errno %d, expected -1 with ESPIPE", (long)ret,
             errno);

    puts("TEST OK");
    return 0;
}
