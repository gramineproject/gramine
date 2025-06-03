/* SPDX-License-Identifier: LGPL-3.0-or-later */

/*
 * The program is introduced to allow later versions of LTP (version after 20220527) can be
 * tested via command: gramine-{direct|sgx} testltp <TEST_BINARY>
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        errx(1, "Usage - testltp <ltp testcase(s)>");
    }

    for (int i=1; i < argc; i++) {
        pid_t pid = fork();
        if (pid < 0) {
	    err(1, "fork");
        } else if (pid == 0) {
            execl(argv[i], argv[i], NULL);
	    err(1, "execl failed");
        } else {
            waitpid(pid, NULL, 0);
        }
    }
    return 0;
}
