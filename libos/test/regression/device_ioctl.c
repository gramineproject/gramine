#define _GNU_SOURCE /* for loff_t */
#include <err.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "common.h"
#include "rw_file.h"

#include "gramine_test_dev_ioctl.h"

#define STRING_READWRITE      "Hello world via read/write\n"
#define STRING_IOCTL          "Hello world via ioctls\n"
#define STRING_IOCTL_REPLACED "He$$0 w0r$d via i0ct$s\n"

int main(void) {
    ssize_t bytes;
    char buf[64];

    int devfd = CHECK(open("/dev/gramine_test_dev", O_RDWR));

    /* test 1 -- use write() and read() syscalls */
    bytes = posix_fd_write(devfd, STRING_READWRITE, sizeof(STRING_READWRITE));
    if (bytes != sizeof(STRING_READWRITE))
        CHECK(-1);

    /* lseek() doesn't work in Gramine because it is fully emulated in LibOS and therefore lseek()
     * is not aware of device-specific semantics; instead we use a device-specific ioctl() */
    off_t offset = CHECK(ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_REWIND));
    if (offset != 0)
        errx(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_REWIND) didn't return 0 "
                "(returned: %ld)", offset);

    memset(&buf, 0, sizeof(buf));
    bytes = posix_fd_read(devfd, buf, sizeof(buf) - 1);
    if (bytes != sizeof(STRING_READWRITE))
        CHECK(-1);

    if (strcmp(buf, STRING_READWRITE))
        errx(1, "read `%s` from /dev/gramine_test_dev but expected `%s`", buf, STRING_READWRITE);

    ssize_t devfd_size = CHECK(ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_GETSIZE));
    if (devfd_size != sizeof(STRING_READWRITE))
        errx(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_GETSIZE) didn't return %lu "
                "(returned: %ld)", sizeof(STRING_READWRITE), devfd_size);

    /* test 2 -- use ioctl(GRAMINE_TEST_DEV_IOCTL_WRITE) and ioctl(GRAMINE_TEST_DEV_IOCTL_READ)
     *           syscalls */
    CHECK(ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_CLEAR));

    devfd_size = CHECK(ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_GETSIZE));
    if (devfd_size != 0)
        errx(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_GETSIZE) didn't return 0 "
                "(returned: %ld)", devfd_size);

    struct gramine_test_dev_ioctl_write write_arg = {
        .buf_size = sizeof(STRING_IOCTL),
        .buf      = STRING_IOCTL,
        .off      = 0
    };
    CHECK(ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_WRITE, &write_arg));
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
    CHECK(ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_READ, &read_arg));
    if (read_arg.off != sizeof(STRING_IOCTL))
        errx(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_READ) didn't update offset "
                "to %lu (returned: %ld)", sizeof(STRING_IOCTL), read_arg.off);
    if (read_arg.copied != sizeof(STRING_IOCTL))
        errx(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_READ) didn't copy %lu bytes "
                "(returned: %ld)", sizeof(STRING_IOCTL), read_arg.copied);

    if (strcmp(buf, STRING_IOCTL))
        errx(1, "read `%s` from /dev/gramine_test_dev but expected `%s`", buf, STRING_IOCTL);

    devfd_size = CHECK(ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_GETSIZE));
    if (devfd_size != sizeof(STRING_IOCTL))
        errx(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_GETSIZE) didn't return %lu "
                "(returned: %ld)", sizeof(STRING_IOCTL), devfd_size);

    /* test 3 -- use ioctl(GRAMINE_TEST_DEV_IOCTL_REPLACE_ARR) syscall with a complex struct as an
     *           argument */
    struct gramine_test_dev_ioctl_replace_char replace_chars[] = {
        { .src = 'l', .dst = '$' },
        { .src = 'o', .dst = '0' }
    };
    struct gramine_test_dev_ioctl_replace_arr replace_arr = {
        .replacements_cnt = ARRAY_LEN(replace_chars),
        .replacements_arr = replace_chars
    };
    CHECK(ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_REPLACE_ARR, &replace_arr));

    memset(buf, 0, sizeof(buf));
    read_arg = (struct gramine_test_dev_ioctl_read){
        .buf_size = sizeof(buf) - 1,
        .buf      = buf,
        .off      = 0
    };
    CHECK(ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_READ, &read_arg));
    if (strcmp(buf, STRING_IOCTL_REPLACED))
        errx(1, "read `%s` from /dev/gramine_test_dev but expected `%s`", buf,
             STRING_IOCTL_REPLACED);

    /* test 4 -- use ioctl(GRAMINE_TEST_DEV_IOCTL_REPLACE_LIST) syscall with a complex struct as an
     *           argument */
    struct gramine_test_dev_ioctl_replace_list replace_list_2 = {
        .replacement = { .src = '0', .dst = 'o' },
        .next = NULL
    };
    struct gramine_test_dev_ioctl_replace_list replace_list = {
        .replacement = { .src = '$', .dst = 'l' },
        .next = &replace_list_2
    };

    CHECK(ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_REPLACE_LIST, &replace_list));

    memset(buf, 0, sizeof(buf));
    read_arg = (struct gramine_test_dev_ioctl_read){
        .buf_size = sizeof(buf) - 1,
        .buf      = buf,
        .off      = 0
    };
    CHECK(ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_READ, &read_arg));
    if (strcmp(buf, STRING_IOCTL))
        errx(1, "read `%s` from /dev/gramine_test_dev but expected `%s`", buf, STRING_IOCTL);

    /* test 5 -- use ioctl(GRAMINE_TEST_DEV_IOCTL_GET_SET_SIZE) syscall to test `onlyif` syntax */
    struct gramine_test_dev_ioctl_get_set_size get_set_size = {
        .do_set = 0,          /* get size */
        .size   = UINT64_MAX  /* will be overwritten by ioctl result */
    };
    CHECK(ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_GET_SET_SIZE, &get_set_size));
    if (get_set_size.size != sizeof(STRING_IOCTL))
        errx(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_GET_SET_SIZE) didn't return "
                " size %lu (returned: %lu)", sizeof(STRING_IOCTL), get_set_size.size);

    /* use a static const variable so that it is put into the .rodata section and thus protected
     * against writes -- this is to catch bugs if Gramine IOCTL logic tries to write into it */
    static const struct gramine_test_dev_ioctl_get_set_size const_set_size = {
        .do_set = 1, /* set size to zero */
        .size   = 0
    };
    CHECK(ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_GET_SET_SIZE, &const_set_size));
    devfd_size = CHECK(ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_GETSIZE));
    if (devfd_size != 0)
        errx(1, "/dev/gramine_test_dev ioctl(GRAMINE_TEST_DEV_IOCTL_GETSIZE) didn't return 0 "
                "(returned: %ld)", devfd_size);

    CHECK(close(devfd));
    puts("TEST OK");
    return 0;
}
