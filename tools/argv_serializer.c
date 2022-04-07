/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

/* Helper tool for protected argv ("loader.argv_src_file" manifest option). See Gramine
 * documentation for usage.
 */

#include <stdio.h>
#include <string.h>

static void usage(const char* exec) {
    printf("Usage: %s \"executable name\" [\"arg1\"]...\n", exec);
}

int main(int argc, char* argv[]) {
    if (argc < 2 || !strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
        usage(argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++)
        if (fwrite(argv[i], strlen(argv[i]) + 1, 1, stdout) != 1)
            return 1;
    return 0;
}
