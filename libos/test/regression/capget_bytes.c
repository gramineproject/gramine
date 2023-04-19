/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Fortanix Inc
 *                    Nirjhar Roy <nirjhar.roy@fortanix.com> */

/* Test description: this test only tests whether 32 bits of the capabilities header and data file
 * get modified with _LINUX_CAPABILITY_VERSION_1 and 64 bits get modified with
 * _LINUX_CAPABILITY_VERSION_3 */

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <sys/capability.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"

#define ROOT_USER_ID 0
#define MAGIC_NUM 0xdeadbeef

int main(void) {
    int pid = getpid();
    struct __user_cap_header_struct cap_header;
    struct __user_cap_data_struct cap_data[3];

    /* Checking if only 64 bits of each field of cap_data is modified
     * when cap_header.version != _LINUX_CAPABILITY_VERSION_1 */

    cap_header.version = _LINUX_CAPABILITY_VERSION_3;
    cap_header.pid = pid;

    for(size_t i = 0; i < 3; i++) {
        cap_data[i].effective = MAGIC_NUM;
        cap_data[i].permitted = MAGIC_NUM;
        cap_data[i].inheritable = MAGIC_NUM;
    }
    CHECK(capget(&cap_header, cap_data));
    for(size_t i = 0; i < 3; i++) {
        if (i < 2) {
            if (cap_data[i].effective == MAGIC_NUM)
                errx(1, "effective value is not modified for index = %ld and header version 3",
                     i);
            if (cap_data[i].permitted == MAGIC_NUM)
                errx(1, "permitted value is not modified for index = %ld and header version 3",
                     i);
            if (cap_data[i].inheritable == MAGIC_NUM)
                errx(1, "inheritable value is not modified for index = %ld and header version 3",
                     i);
        } else {
            if (cap_data[i].effective != MAGIC_NUM) {
                errx(1, "effective value is incorrectly modified for index = %ld"
                     " and header version 3", i);
            }
            if (cap_data[i].permitted != MAGIC_NUM) {
                errx(1, "permitted value is incorrectly modified for index = %ld"
                     " and header version 3", i);
            }
            if (cap_data[i].inheritable != MAGIC_NUM) {
                errx(1, "inheritable value incorrectly modified for index = %ld"
                     " and header version 3", i);
            }
        }
    }

    /* Checking if only 32 bits of each field of cap_data is modified
     * when cap_header.version = _LINUX_CAPABILITY_VERSION_1 */
    cap_header.version = _LINUX_CAPABILITY_VERSION_1;
    cap_header.pid = pid;
    for(size_t i = 0; i < 3; i++){
        cap_data[i].effective = MAGIC_NUM;
        cap_data[i].permitted = MAGIC_NUM;
        cap_data[i].inheritable = MAGIC_NUM;
    }
    CHECK(capget(&cap_header, cap_data));
    for(size_t i = 0; i < 3; i++) {
        if (i < 1) {
            if (cap_data[i].effective == MAGIC_NUM)
                errx(1, "effective value is not modified for index = %ld and header version 1",
                     i);
            if (cap_data[i].permitted == MAGIC_NUM)
                errx(1, "permitted value is not modified for index = %ld and header version 1",
                     i);
            if (cap_data[i].inheritable == MAGIC_NUM)
                errx(1, "inheritable value is not modified for index = %ld and header version 1",
                     i);
        } else {
            if (cap_data[i].effective != MAGIC_NUM) {
                errx(1, "effective value is incorrectly modified for index = %ld"
                     " and header version 1", i);
            }
            if (cap_data[i].permitted != MAGIC_NUM) {
                errx(1, "permitted value is incorrectly modified for index = %ld"
                     " and header version 1", i);
            }
            if (cap_data[i].inheritable != MAGIC_NUM) {
                errx(1, "inheritable value is incorrectly modified for index = %ld"
                     " and header version 1", i);
            }
        }
    }
    puts("TEST OK");
    return 0;
}
