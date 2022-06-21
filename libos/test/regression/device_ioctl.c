#include <alloca.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include "rw_file.h"

#define STRING_READWRITE      "Hello world via read/write\n"
#define STRING_IOCTL          "Hello world via ioctls\n"
#define STRING_IOCTL_REPLACED "He$$0 w0r$d via i0ct$s\n"

struct gramine_test_dev_ioctl_write {
    size_t buf_size;        /* in */
    const char* buf;        /* in */
    ssize_t off;            /* in/out -- updated after write */
    ssize_t copied;         /* out -- how many bytes were actually written */
};

struct gramine_test_dev_ioctl_read {
    size_t buf_size;        /* in */
    char* buf;              /* out */
    ssize_t off;            /* in/out -- updated after read */
    ssize_t copied;         /* out -- how many bytes were actually read */
};

struct gramine_test_dev_ioctl_replace_char {
    char src;               /* in */
    char dst;               /* in */
    char pad[6];
};

struct gramine_test_dev_ioctl_replace_arr {
    /* array of replacements, e.g. replacements_cnt == 2 and [`l` -> `$`, `o` -> `0`] */
    size_t replacements_cnt;
    struct gramine_test_dev_ioctl_replace_char* replacements_arr;
};

struct gramine_test_dev_ioctl_replace_list {
    /* list of replacements, e.g. [`l` -> `$`, next points to `o` -> `0`, next points to NULL] */
    struct gramine_test_dev_ioctl_replace_char replacement;
    struct gramine_test_dev_ioctl_replace_list* next;
};

#define GRAMINE_TEST_DEV_IOCTL_BASE 0x81

#define GRAMINE_TEST_DEV_IOCTL_REWIND        _IO(GRAMINE_TEST_DEV_IOCTL_BASE, 0x00)
#define GRAMINE_TEST_DEV_IOCTL_WRITE       _IOWR(GRAMINE_TEST_DEV_IOCTL_BASE, 0x01, \
                                                 struct gramine_test_dev_ioctl_write)
#define GRAMINE_TEST_DEV_IOCTL_READ        _IOWR(GRAMINE_TEST_DEV_IOCTL_BASE, 0x02, \
                                                 struct gramine_test_dev_ioctl_read)
#define GRAMINE_TEST_DEV_IOCTL_GETSIZE       _IO(GRAMINE_TEST_DEV_IOCTL_BASE, 0x03)
#define GRAMINE_TEST_DEV_IOCTL_CLEAR         _IO(GRAMINE_TEST_DEV_IOCTL_BASE, 0x04)
#define GRAMINE_TEST_DEV_IOCTL_REPLACE_ARR  _IOW(GRAMINE_TEST_DEV_IOCTL_BASE, 0x05, \
                                                 struct gramine_test_dev_ioctl_replace_arr)
#define GRAMINE_TEST_DEV_IOCTL_REPLACE_LIST _IOW(GRAMINE_TEST_DEV_IOCTL_BASE, 0x06, \
                                                 struct gramine_test_dev_ioctl_replace_list)

int main(int argc, char* argv[]) {
    int ret;
    ssize_t bytes;
    char buf[64];

    int devfd = open("/dev/gramine_test_dev", O_RDWR);
    if (devfd < 0)
        err(1, "/dev/gramine_test_dev open");

    /* test 1 -- use write() and read() syscalls */
    bytes = posix_fd_write(devfd, STRING_READWRITE, sizeof(STRING_READWRITE));
    if (bytes < 0)
        return EXIT_FAILURE;

    /* lseek() doesn't work in Gramine because it is fully emulated in LibOS and therefore lseek()
     * is not aware of device-specific semantics; instead we use a device-specific ioctl() */
    off_t offset = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_REWIND);
    if (offset < 0)
        err(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_REWIND)");
    if (offset > 0)
        errx(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_REWIND) didn't return 0 "
                "(returned: %ld)", offset);

    memset(&buf, 0, sizeof(buf));
    bytes = posix_fd_read(devfd, buf, sizeof(buf) - 1);
    if (bytes < 0)
        return EXIT_FAILURE;

    if (strcmp(buf, STRING_READWRITE))
        errx(1, "read `%s` from /dev/gramine_test_dev but expected `%s`", buf, STRING_READWRITE);

    ssize_t devfd_size = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_GETSIZE);
    if (devfd_size < 0)
        err(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_GETSIZE)");
    if (devfd_size != sizeof(STRING_READWRITE))
        errx(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_GETSIZE) didn't return %lu "
                "(returned: %ld)", sizeof(STRING_READWRITE), devfd_size);

    /* test 2 -- use ioctl(GRAMINE_TEST_DEV_IOCTL_WRITE) and ioctl(GRAMINE_TEST_DEV_IOCTL_READ)
     *           syscalls */
    ret = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_CLEAR);
    if (ret < 0)
        err(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_CLEAR)");

    struct gramine_test_dev_ioctl_write write_arg = {
        .buf_size = sizeof(STRING_IOCTL),
        .buf      = STRING_IOCTL,
        .off      = 0
    };
    ret = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_WRITE, &write_arg);
    if (ret < 0)
        err(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_WRITE)");
    if (write_arg.off != sizeof(STRING_IOCTL))
        errx(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_WRITE) didn't update offset "
                "to %lu (returned: %ld)", sizeof(STRING_IOCTL), write_arg.off);
    if (write_arg.copied != sizeof(STRING_IOCTL))
        errx(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_WRITE) didn't copy %lu bytes "
                "(returned: %ld)", sizeof(STRING_IOCTL), write_arg.copied);

    memset(buf, 0, sizeof(buf));
    struct gramine_test_dev_ioctl_read read_arg = {
        .buf_size = sizeof(buf) - 1,
        .buf      = buf,
        .off      = 0
    };
    ret = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_READ, &read_arg);
    if (ret < 0)
        err(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_READ)");
    if (read_arg.off != sizeof(STRING_IOCTL))
        errx(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_READ) didn't update offset "
                "to %lu (returned: %ld)", sizeof(STRING_IOCTL), read_arg.off);
    if (read_arg.copied != sizeof(STRING_IOCTL))
        errx(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_READ) didn't copy %lu bytes "
                "(returned: %ld)", sizeof(STRING_IOCTL), read_arg.copied);

    if (strcmp(buf, STRING_IOCTL))
        errx(1, "read `%s` from /dev/gramine_test_dev but expected `%s`", buf, STRING_IOCTL);

    devfd_size = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_GETSIZE);
    if (devfd_size < 0)
        err(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_GETSIZE)");
    if (devfd_size != sizeof(STRING_IOCTL))
        errx(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_GETSIZE) didn't return %lu "
                "(returned: %ld)", sizeof(STRING_IOCTL), devfd_size);

    /* test 3 -- use complex ioctl(GRAMINE_TEST_DEV_IOCTL_REPLACE_ARR) syscall */
    struct gramine_test_dev_ioctl_replace_char replace_chars[] = {
        { .src = 'l', .dst = '$' },
        { .src = 'o', .dst = '0' }
    };
    struct gramine_test_dev_ioctl_replace_arr replace_arr = {
        .replacements_cnt = 2,
        .replacements_arr = replace_chars
    };
    ret = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_REPLACE_ARR, &replace_arr);
    if (ret < 0)
        err(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_REPLACE_ARR)");

    memset(buf, 0, sizeof(buf));
    read_arg.off = 0;
    ret = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_READ, &read_arg);
    if (ret < 0)
        err(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_READ)");
    if (strcmp(buf, STRING_IOCTL_REPLACED))
        errx(1, "read `%s` from /dev/gramine_test_dev but expected `%s`", buf,
             STRING_IOCTL_REPLACED);

    /* test 4 -- use complex ioctl(GRAMINE_TEST_DEV_IOCTL_REPLACE_LIST) syscall */
    struct gramine_test_dev_ioctl_replace_list replace_list_2 = {
        .replacement = { .src = '0', .dst = 'o' },
        .next = NULL
    };
    struct gramine_test_dev_ioctl_replace_list replace_list = {
        .replacement = { .src = '$', .dst = 'l' },
        .next = &replace_list_2
    };

    ret = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_REPLACE_LIST, &replace_list);
    if (ret < 0)
        err(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_REPLACE_LIST)");

    memset(buf, 0, sizeof(buf));
    read_arg.off = 0;
    ret = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_READ, &read_arg);
    if (ret < 0)
        err(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_READ)");
    if (strcmp(buf, STRING_IOCTL))
        errx(1, "read `%s` from /dev/gramine_test_dev but expected `%s`", buf, STRING_IOCTL);

    ret = close(devfd);
    if (ret < 0)
        err(1, "/dev/gramine_test_dev close");

    puts("TEST OK");
    return 0;
}
