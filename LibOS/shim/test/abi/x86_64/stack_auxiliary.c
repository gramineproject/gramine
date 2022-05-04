/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

#include <elf/elf.h>

/*
 * We have to add a function declaration to avoid warnings.
 * This function is used with NASM, so creating a header is pointless.
 */
int verify_auxiliary(Elf64_auxv_t *auxv);

struct {
    uint64_t type;
    int exists;
} auxv_gramine_defaults[] = {
    { AT_PHDR, 0 },
    { AT_PHNUM, 0 },
    { AT_PAGESZ, 0 },
    { AT_ENTRY, 0 },
    { AT_BASE, 0 },
    { AT_RANDOM, 0 },
    { AT_PHENT, 0 },
    { AT_SYSINFO_EHDR, 0 },
};

int verify_auxiliary(Elf64_auxv_t *auxv) {
    uint64_t count = sizeof(auxv_gramine_defaults) / sizeof(auxv_gramine_defaults[0]);
    uint64_t i;

    for (; auxv->a_type != AT_NULL; auxv++) {
        for (i = 0; i < count; i++) {
            if (auxv_gramine_defaults[i].type == auxv->a_type) {
                /* Check for duplicates */
                if (auxv_gramine_defaults[i].exists) {
                    return 1;
                }
                auxv_gramine_defaults[i].exists = 1;
            }
        }
    }

    for (i = 0; i < count; i++) {
        if (!auxv_gramine_defaults[i].exists) {
            return 1;
        }
    }

    return 0;
}
