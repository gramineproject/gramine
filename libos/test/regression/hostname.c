#define _DEFAULT_SOURCE BSD /* This is required for gethostname */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static void test_fork(const char* tag, const char* expected_name,
                      void (*f)(const char*, const char*)) {
    int status;

    pid_t pid = fork();
    if (pid == -1) {
        err(1, "Unable to fork %s", tag);
    }

    if (pid == 0) {
        f(tag, expected_name);
        exit(0);
    }

    if (wait(&status) == -1) {
        err(1, "Wait failed %s", tag);
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        err(1, "Test failed %s", tag);
    }
}

static void test_gethostname(const char* tag, const char* expected_name) {
    char buf[512] = {0};

    if (gethostname(buf, sizeof(buf)) != 0) {
        err(1, "%s gethostname: failed", tag);
    }

    if (strcmp(buf, expected_name) != 0) {
        errx(1, "%s gethostname result doesn't match hostname (expected: %s, got: %s)",
             tag, expected_name, buf);
    }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        printf("Usage: %s [hostname]\n", argv[0]);
        return 1;
    }

    test_gethostname("normal", argv[1]);
    test_fork("fork gethostname", argv[1], test_gethostname);

    printf("TEST OK\n");
    return 0;
}
