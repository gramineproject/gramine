/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2020 Invisible Things Lab
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 */

/* Helper tool for protected argv ("loader.argv_src_file" manifest option). See Gramine
 * documentation for usage.
 */

#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

struct option g_options[] = {
    { "help", no_argument, 0, 'h' },
    { 0, 0, 0, 0 }
};

static void usage(const char* exec) {
    printf("Usage: %s <command line arguments seperated by space>\n", exec);
    printf("Available options:\n");
    printf("  --help, -h  Display this help\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        usage(argv[0]);
        return -1;
    }

    int option = 0;
    // parse command line
    while (true) {
        option = getopt_long(argc, argv, "h", g_options, NULL);
        if (option == -1)
            break;

        switch (option) {
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                usage(argv[0]);
                return -1;
        }
    }

    for (int i = 1; i < argc; i++)
        if (fwrite(argv[i], strlen(argv[i]) + 1, 1, stdout) != 1)
            return 1;
    return 0;
}
