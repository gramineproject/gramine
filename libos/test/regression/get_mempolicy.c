/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Fortanix
 *                    Nirjhar Roy <nirjhar.roy@fortanix.com>
 */
#define _GNU_SOURCE

#include <stdbool.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "common.h"
#include "limits.h"

#define KERNEL_POINTER ((void*)0xffff000000000000)
/* Explicity defining the following linux constants so that we don't need to use libnuma library */
#define MPOL_F_NODE	(1<<0)	/* return next IL mode instead of node mask */
#define MPOL_F_ADDR	(1<<1)	/* look up vma using address */
#define MPOL_F_MEMS_ALLOWED (1<<2) /* return allowed memories */

static int get_numa_max_node(void) {
    int num_nodes = 0;
    while (true) {
        char path[64] = {0, };
        snprintf(path, sizeof path, "/sys/devices/system/node/node%d", num_nodes);
        struct stat sb;
        int ret = stat(path, &sb);
        if (ret == -1 && errno != ENOENT)
            err(1, "Failed to open %s", path);
        if (ret != 0)
            return num_nodes;
        else
            num_nodes += 1;
    }
}

int main(void) {
    int var;
    int mode;
    unsigned long nodemask;
    int max_possible_node = get_numa_max_node();
    printf("Max possible node is %d\n", max_possible_node); // will remove it before merging the PR

    struct test_cases {
        int flags;
        int expected_errno;
        int max_node;
        void* addr;
        unsigned long* nodemask;
        int* mode;
    } tc[] = {
        { .flags = MPOL_F_ADDR, .max_node = max_possible_node, .addr = &var,
          .expected_errno = 0, .nodemask = &nodemask, .mode = &mode}, // Test case 0

        { .flags = MPOL_F_ADDR, .max_node = max_possible_node, .addr = &var, .mode = &mode,
          .expected_errno = EFAULT, .nodemask = (void*) KERNEL_POINTER}, // Test case 1

        {.flags = MPOL_F_ADDR, .max_node = max_possible_node - 1, .addr = &var,
         .expected_errno = EINVAL, .nodemask = &nodemask, .mode = &mode}, // Test case 2

        {.flags = ~(MPOL_F_NODE | MPOL_F_ADDR), .max_node = max_possible_node, .addr = &var,
         .expected_errno = EINVAL, .nodemask = &nodemask, .mode = &mode}, // Test case 3

        {.flags = MPOL_F_ADDR, .max_node = max_possible_node, .addr = NULL,
         .expected_errno = EFAULT, .nodemask = &nodemask, .mode = &mode}, // Test case 4

        {.flags = MPOL_F_NODE, .max_node = max_possible_node, .addr = &var,
         .expected_errno = EINVAL, .nodemask = &nodemask, .mode = &mode}, // Test case 5

        {.flags = MPOL_F_NODE | MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = &var,
         .expected_errno = EINVAL, .nodemask = &nodemask, .mode = &mode}, // Test case 6

        {.flags = MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = &var,
         .expected_errno = EINVAL, .nodemask = &nodemask, .mode = &mode}, // Test case 7

        {.flags = 0, .max_node = max_possible_node, .addr = &var,
         .expected_errno = EINVAL, .nodemask = NULL, .mode = &mode}, // Test case 8

        {.flags = 0, .max_node = max_possible_node, .addr = &var,
         .expected_errno = EINVAL, .nodemask = &nodemask, .mode = NULL}, // Test case 9

        {.flags = 0, .max_node = max_possible_node, .addr = &var,
         .expected_errno = EINVAL, .nodemask = KERNEL_POINTER, .mode = &mode}, // Test case 10

        {.flags = 0, .max_node = max_possible_node, .addr = &var,
         .expected_errno = EINVAL, .nodemask = &nodemask, .mode = KERNEL_POINTER}, // Test case 11

        {.flags = MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = &var,
         .expected_errno = 0, .nodemask = &nodemask, .mode = NULL}, // Test case 12

        {.flags = MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = &var,
         .expected_errno = 0, .nodemask = NULL, .mode = &mode}, // Test case 13

        {.flags = MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = &var,
         .expected_errno = 0, .nodemask = NULL, .mode = NULL}, // Test case 14

        {.flags = MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = &var,
         .expected_errno = EFAULT, .nodemask = &nodemask, .mode = KERNEL_POINTER}, // Test case 15

        {.flags = MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = &var,
         .expected_errno = EFAULT, .nodemask = KERNEL_POINTER, .mode = &mode}, // Test case 16

        // Test case 17
        {.flags = MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = &var,
         .expected_errno = EFAULT, .nodemask = KERNEL_POINTER, .mode = KERNEL_POINTER},

        {.flags = MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = NULL,
         .expected_errno = 0, .nodemask = &nodemask, .mode = NULL}, // Test case 18

        {.flags = MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = NULL,
         .expected_errno = 0, .nodemask = NULL, .mode = &mode}, // Test case 19

        {.flags = MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = NULL,
         .expected_errno = 0, .nodemask = NULL, .mode = NULL}, // Test case 20

        {.flags = MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = NULL,
         .expected_errno = EFAULT, .nodemask = &nodemask, .mode = KERNEL_POINTER}, // Test case 21

        {.flags = MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = NULL,
         .expected_errno = EFAULT, .nodemask = KERNEL_POINTER, .mode = &mode}, // Test case 22

        // Test case 23
        {.flags = MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = NULL,
         .expected_errno = EFAULT, .nodemask = KERNEL_POINTER, .mode = KERNEL_POINTER},
    };

    for (size_t i = 0; i < ARRAY_LEN(tc); i++) {
        errno = 0;
        int ret = syscall(SYS_get_mempolicy, tc[i].mode, tc[i].nodemask, tc[i].max_node, tc[i].addr,
                          tc[i].flags);
        if (errno != tc[i].expected_errno || (tc[i].expected_errno == 0 && ret != 0)
            || (tc[i].expected_errno != 0 && ret == 0)) {
            errx(1, "test case %lu failed with incorrect errno or return value. Expected errno is "
                 "%d (%s), received errno %d (%s), expected return value is %d, received %d", i,
                 tc[i].expected_errno, strerror(tc[i].expected_errno), errno, strerror(errno),
                 tc[i].expected_errno == 0 ? 0 : -1, ret);
        }
        printf("Test case %lu passed\n", i);

    }
    puts("TEST OK");
}