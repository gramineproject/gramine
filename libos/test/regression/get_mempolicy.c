/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Fortanix
 *                    Nirjhar Roy <nirjhar.roy@fortanix.com>
 */

#include <err.h>
#include <errno.h>
#include <numa.h>
#include <numaif.h>
#include <stdio.h>

#include "common.h"

#define KERNEL_POINTER 0xffff000000000000

int main(void) {
    int var;
    int mode;
    unsigned long nodemask;
    int max_possible_node = numa_num_configured_nodes();
    printf("Max possible node is %d\n", max_possible_node);

    struct test_cases {
        int flags;
        int expected_errno;
        int max_node;
        void* addr;
        unsigned long* nodemask;
    } tc[] = {
        { .flags = MPOL_F_ADDR, .max_node = max_possible_node, .addr = &var,
          .expected_errno = 0, .nodemask = &nodemask}, // Test case 0

        { .flags = MPOL_F_ADDR, .max_node = max_possible_node, .addr = &var,
          .expected_errno = EFAULT, .nodemask = (void*) KERNEL_POINTER}, // Test case 1

        {.flags = MPOL_F_ADDR, .max_node = max_possible_node - 1, .addr = &var,
         .expected_errno = EINVAL, .nodemask = &nodemask}, // Test case 2

        {.flags = ~(MPOL_F_NODE | MPOL_F_ADDR), .max_node = max_possible_node, .addr = &var,
         .expected_errno = EINVAL, .nodemask = &nodemask}, // Test case 3

        {.flags = MPOL_F_ADDR, .max_node = max_possible_node, .addr = NULL,
         .expected_errno = EFAULT, .nodemask = &nodemask}, // Test case 4

        {.flags = MPOL_F_NODE, .max_node = max_possible_node, .addr = &var,
         .expected_errno = EINVAL, .nodemask = &nodemask}, // Test case 5

        {.flags = MPOL_F_NODE | MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = &var,
         .expected_errno = EINVAL, .nodemask = &nodemask}, // Test case 6

        {.flags = MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED, .max_node = max_possible_node, .addr = &var,
         .expected_errno = EINVAL, .nodemask = &nodemask}, // Test case 7
    };

    for (size_t i = 0; i < ARRAY_LEN(tc); i++) {
        errno = 0;
        int ret = get_mempolicy(&mode, tc[i].nodemask, tc[i].max_node, tc[i].addr, tc[i].flags);
        if (errno != tc[i].expected_errno || (tc[i].expected_errno == 0 && ret != 0) ||
            (tc[i].expected_errno != 0 && ret == 0)) {
            errx(1, "test case %lu failed with incorrect errno or return value. Expected errno is "
                 "%d (%s), received errno %d (%s), expected return value is %d, received %d", i,
                 tc[i].expected_errno, strerror(tc[i].expected_errno), errno, strerror(errno),
                 tc[i].expected_errno == 0 ? 0 : -1, ret);
        }
        printf("Test case %lu passed\n", i);

    }

    puts("TEST OK");
}