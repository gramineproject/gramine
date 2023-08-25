#define _GNU_SOURCE /* for loff_t */
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "common.h"

#include "gramine_test_dev_ioctl.h"

int main(void) {
    int ret;

    int devfd = CHECK(open("/dev/gramine_test_dev", O_RDWR));

    /* test 1: no corresponding struct found */
    errno = 0;
    ret = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_REWIND);
    if (ret != -1 || errno != EINVAL)
        errx(1, "ioctl(GRAMINE_TEST_DEV_IOCTL_REWIND) didn't fail on parsing "
                "(returned: %d, errno: %d)", ret, errno);

    /* test 2: sub-region is not a TOML table */
    errno = 0;
    ret = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_GETSIZE);
    if (ret != -1 || errno != EINVAL)
        errx(1, "ioctl(GRAMINE_TEST_DEV_IOCTL_GETSIZE) didn't fail on parsing "
                "(returned: %d, errno: %d)", ret, errno);

    /* test 3: negative size specified */
    errno = 0;
    ret = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_CLEAR);
    if (ret != -1 || errno != EINVAL)
        errx(1, "ioctl(GRAMINE_TEST_DEV_IOCTL_CLEAR) didn't fail on parsing "
                "(returned: %d, errno: %d)", ret, errno);

    /* test 4: buffer detected before the size of this buffer was detected */
    errno = 0;
    ret = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_WRITE);
    if (ret != -1 || errno != EINVAL)
        errx(1, "ioctl(GRAMINE_TEST_DEV_IOCTL_WRITE) didn't fail on parsing "
                "(returned: %d, errno: %d)", ret, errno);

    /* test 5: pointer of size not 8 (which is mandated on x86-64) */
    errno = 0;
    ret = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_READ);
    if (ret != -1 || errno != EINVAL)
        errx(1, "ioctl(GRAMINE_TEST_DEV_IOCTL_READ) didn't fail on parsing "
                "(returned: %d, errno: %d)", ret, errno);

    /* test 6: `alignment` keyword specified not in the first sub-region; note that we need the
     * struct arg because the parser tries to collect the first sub-region */
    errno = 0;
    struct gramine_test_dev_ioctl_replace_arr replace_arr = { 0 };
    ret = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_REPLACE_ARR, &replace_arr);
    if (ret != -1 || errno != EINVAL)
        errx(1, "ioctl(GRAMINE_TEST_DEV_IOCTL_REPLACE_ARR) didn't fail on parsing "
                "(returned: %d, errno: %d)", ret, errno);

    /* test 7: unrecognized string in `direction` keyword */
    errno = 0;
    ret = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_REPLACE_LIST);
    if (ret != -1 || errno != EINVAL)
        errx(1, "ioctl(GRAMINE_TEST_DEV_IOCTL_REPLACE_LIST) didn't fail on parsing "
                "(returned: %d, errno: %d)", ret, errno);

    /* test 8: bad expression in `onlyif` field */
    errno = 0;
    ret = ioctl(devfd, GRAMINE_TEST_DEV_IOCTL_GET_SET_SIZE);
    if (ret != -1 || errno != EINVAL)
        errx(1, "ioctl(GRAMINE_TEST_DEV_IOCTL_GET_SET_SIZE) didn't fail on parsing "
                "(returned: %d, errno: %d)", ret, errno);

    CHECK(close(devfd));
    puts("TEST OK");
    return 0;
}
