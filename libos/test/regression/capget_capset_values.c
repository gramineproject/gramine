/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Fortanix Inc
 *                    Nirjhar Roy <nirjhar.roy@fortanix.com> */

/* Test description: this test tests return values of capget and capset system call with various
 * inputs. */
#define _GNU_SOURCE
#include <assert.h>
#include <pthread.h>
#include <sys/capability.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"

#define ROOT_USER_ID 0
#define KERNEL_POINTER 0xffff000000000000

static bool test_efault(void) {
    bool success = true;
    struct __user_cap_header_struct header = {
        .pid = getpid(),
        .version = _LINUX_CAPABILITY_VERSION_3,
    };
    for (size_t i = 0; i < 5; i++) {
        int ret = capget(&header, (cap_user_data_t) KERNEL_POINTER);
        if (ret != -1 || errno != EFAULT) {
            if (ret != -1)
                success = false;
            else
                success = false;
        }
    }
    return success;
}

static void *check_capabilities_for_different_thread(void *ptr) {
    struct __user_cap_data_struct  mod_caps = *(struct __user_cap_data_struct *)ptr;
    struct __user_cap_header_struct cap_header;
    struct __user_cap_data_struct cap_data;
    cap_header.pid = gettid() ;
    cap_header.version = _LINUX_CAPABILITY_VERSION_1;
    CHECK(capget(&cap_header, &cap_data));

    if (mod_caps.effective != cap_data.effective)
        errx(1, "effective capabilities is not modified in child thread");
    if (mod_caps.permitted != cap_data.permitted)
        errx(1, "permitted capabilities is not modified in child thread");
    if (mod_caps.inheritable != cap_data.inheritable)
        errx(1, "inheritable capabilities is not modified in child thread");
    return NULL;
}

int main(void) {
    int cap_mask = 0;
    int pid = getpid();
    int euid= geteuid();
    int ret = 0;

    struct __user_cap_header_struct cap_header;
    struct __user_cap_data_struct cap_data;
    struct __user_cap_data_struct cap_data_mod;
    struct __user_cap_data_struct cap_data2;

    if (euid != ROOT_USER_ID) {
        puts("TEST IN NON-ROOT MODE");
    } else {
        puts("TEST IN ROOT MODE");
    }

    cap_header.pid = pid ;
    cap_header.version = _LINUX_CAPABILITY_VERSION_1;
    if (euid != ROOT_USER_ID) {
        CHECK(capget(&cap_header, &cap_data));
    }
    cap_mask = (1 << CAP_AUDIT_WRITE);
    cap_mask |= (1 << CAP_CHOWN);
    cap_data_mod.effective = cap_mask;
    cap_data_mod.permitted = cap_mask;
    cap_data_mod.inheritable = 0;
    ret = capset(&cap_header, &cap_data_mod);
    if (ret != (euid == ROOT_USER_ID ? 0 : -1))
        errx(1, "capset failed at line number %d with value = %d", __LINE__, ret);
    if (euid != ROOT_USER_ID) {
        if (errno != EPERM) {
            err(1, "Invalid errno for capset failure");
        }
    }

    /* Making sure that the failed setcap call didn't change anything when euid != 0
     * and whether the getcap data matches with setcap data for euid = 0 */
    CHECK(capget(&cap_header, &cap_data2));
    if (cap_data2.effective != (euid == ROOT_USER_ID ? cap_data_mod.effective : cap_data.effective))
        errx(1, "failed capset() call modified effective capabilities");
    if (cap_data2.permitted != (euid == ROOT_USER_ID ? cap_data_mod.permitted : cap_data.permitted))
        errx(1, "failed capset() call modified permitted capabilities");
    if (cap_data2.inheritable != (euid == ROOT_USER_ID ?
        cap_data_mod.inheritable : cap_data.inheritable))
        errx(1, "failed capset() call modified inheritable capabilities");

    if (euid == ROOT_USER_ID) {
        /* No point in checking with non-root user as capset will fail with non-root user
         * and hence the capabilities of the parent thread won't be modified
         */
        pthread_t thread[1];
        CHECK(pthread_create(&thread[0], NULL, check_capabilities_for_different_thread,
              &cap_data_mod));
        pthread_join(thread[0], NULL);
    }

    /* setting pid to some non-existant pid (with datap != NULL). Right now anything except 0 or
     * current thread id will return ESRCH.
     */
    cap_header.pid = INT_MAX;
    ret = capget(&cap_header, &cap_data);
    if (ret != -1)
        errx(1, "capget has incorrectly succeded at line %d", __LINE__);
    if (errno != ESRCH)
        errx(1, "capget has failed with wrong errno(-%d) at line %d", errno, __LINE__);

    /* setting pid to some non-existant pid (with datap == NULL). */
    cap_header.pid = INT_MAX;
    CHECK(capget(&cap_header, NULL));
    cap_header.pid = INT_MAX;
    ret = capset(&cap_header, NULL);
    if (ret != -1)
        errx(1, "capget has incorrectly succeded at line %d", __LINE__);

    /* checking behavior with only header pointer as NULL */
    ret = capget(NULL, &cap_data);
    if (ret != -1)
        errx(1, "capget has incorrectly succeded at line %d", __LINE__);
    if (errno != EFAULT)
        errx(1, "capget has failed with wrong errno(-%d) at line %d", errno, __LINE__);
    ret = capset(NULL, &cap_data);
    if (ret != -1)
        errx(1, "capset has incorrectly succeded at line %d", __LINE__);
    if (errno != EFAULT)
        errx(1, "capset has failed with wrong errno(-%d) at line %d", errno, __LINE__);

    /* checking behavior with only data pointer pointer as NULL */
    cap_header.version = _LINUX_CAPABILITY_VERSION_1;
    cap_header.pid = getpid();
    CHECK(capget(&cap_header, NULL));
    ret = capset(&cap_header, NULL);
    if (ret != -1)
        errx(1, "capset has incorrectly succeded at line %d", __LINE__);
    if (errno != EFAULT)
        errx(1, "capset has failed with wrong errno(-%d) at line %d", errno, __LINE__);

    /* checking behavior with both data and header pointer as NULL */
    ret = capget(NULL, NULL);
    if (ret != -1)
        errx(1, "capget has incorrectly succeded at line %d", __LINE__);
    if (errno != EFAULT)
        errx(1, "capget has failed with wrong errno(-%d) at line %d", errno, __LINE__);
    ret = capset(NULL, NULL);
    if (ret != -1)
        errx(1, "capset has incorrectly succeded at line %d", __LINE__);
    if (errno != EFAULT)
        errx(1, "capset has failed with wrong errno(-%d) at line %d", errno, __LINE__);

    /* Passing invalid version numbers with cap_data != NULL */
    cap_header.version = 1;
    cap_header.pid = getpid();
    ret = capget(&cap_header, &cap_data);
    if (ret != -1)
        errx(1, "capget has incorrectly succeded at line %d", __LINE__);
    if ((cap_header.version != _LINUX_CAPABILITY_VERSION_1 &&
         cap_header.version != _LINUX_CAPABILITY_VERSION_2 &&
         cap_header.version != _LINUX_CAPABILITY_VERSION_3 ))
        err(1, "incorrect version number for header is obtained from capget at line = %d",
            __LINE__);
    if (errno != EINVAL)
        err(1, "Incorrect errno at line = %d", __LINE__);

    cap_header.version = 1;
    cap_header.pid = getpid();
    cap_data_mod.effective = cap_mask;
    cap_data_mod.permitted = cap_mask;
    cap_data_mod.inheritable = 0;
    ret = capset(&cap_header, &cap_data);
    if (ret != -1)
        errx(1, "capset has incorrectly succeded at line %d", __LINE__);
    if ((cap_header.version != _LINUX_CAPABILITY_VERSION_1 &&
         cap_header.version != _LINUX_CAPABILITY_VERSION_2 &&
         cap_header.version != _LINUX_CAPABILITY_VERSION_3 ))
        err(1, "incorrect version number for header is obtained from capset at line = %d",
            __LINE__);
    if (errno != EINVAL)
        err(1, "Invalid errno for capset at line = %d", __LINE__);

    /* Passing invalid version numbers with cap_data = NULL */
    cap_header.version = 1;
    cap_header.pid = getpid();
    CHECK(capget(&cap_header, NULL));
    if ((cap_header.version != _LINUX_CAPABILITY_VERSION_1 &&
         cap_header.version != _LINUX_CAPABILITY_VERSION_2 &&
         cap_header.version != _LINUX_CAPABILITY_VERSION_3 ))
        err(1, "incorrect version number for header is obtained from capset at line = %d",
            __LINE__);
    if (errno != EINVAL)
        err(1, "Invalid errno for capget at line = %d", __LINE__);

    cap_header.version = 1;
    cap_header.pid = getpid();
    cap_data_mod.effective = cap_mask;
    cap_data_mod.permitted = cap_mask;
    cap_data_mod.inheritable = 0;
    ret = capset(&cap_header, NULL);
    if (ret != -1)
        errx(1, "capset has incorrectly succeded at line %d", __LINE__);
    if ((cap_header.version != _LINUX_CAPABILITY_VERSION_1 &&
         cap_header.version != _LINUX_CAPABILITY_VERSION_2 &&
         cap_header.version != _LINUX_CAPABILITY_VERSION_3 ))
        err(1, "incorrect header value is obtained from capset at line = %d", __LINE__);
    if (errno != EINVAL)
        err(1, "Invalid errno for capset at line = %d", __LINE__);

    bool success = test_efault();
    if (!success)
        errx(1, "capget test case with kernel pointer failed");
    puts("TEST OK");
    return 0;
}
