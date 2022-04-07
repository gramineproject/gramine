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
    printf("Usage: %s [\"arg0\"] [\"arg1\"]...\n", exec);
    printf("       Typically, \"arg0\" is your application name followed by\n");
    printf("       other command-line parameters but these strings can be\n");
    printf("       empty as well based on your application requirements.\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    for (int i = 1; i < argc; i++)
        if (fwrite(argv[i], strlen(argv[i]) + 1, 1, stdout) != 1)
            return 1;
    return 0;
}
