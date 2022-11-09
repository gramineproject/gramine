#define _GNU_SOURCE /* for loff_t */
#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "rw_file.h"

#include "gramine_test_dev_ioctl.h" /* currently unused */

#define STRING_READWRITE      "Hello world via read/write\n"

int main(void) {
    int devfd = CHECK(open("/dev/gramine_test_dev", O_RDWR));

    ssize_t bytes = posix_fd_write(devfd, STRING_READWRITE, sizeof(STRING_READWRITE));
    if (bytes != sizeof(STRING_READWRITE))
        CHECK(-1);

    CHECK(close(devfd));
    puts("TEST OK");
    return 0;
}
