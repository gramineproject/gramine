#define _DEFAULT_SOURCE BSD /* This is required for gethostname */

#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "rw_file.h"

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

static void test_etc_hostname(const char* tag, const char* expected_name) {
    char buf[512] = {0};
    int fd;

    fd = open("/etc/hostname", O_RDONLY);

    /*
     * If the etc expected name was not provided, assume that /etc/hostname shouldn't exist.
     */
    if (strcmp(expected_name, "") == 0) {
        if (fd != -1 || errno != ENOENT) {
            err(1, "The etc file shouldn't exist, but exists");
        }
        return;
    }

    if (fd == -1) {
        err(1, "Unable to open /etc/hostname in %s", tag);
    }

    if (posix_fd_read(fd, buf, sizeof(buf)) < 0)
        err(1, "Unable to read /etc/hostname in %s", tag);

    /*
     * Sometimes /etc/hostname might have a trailing '\n', Gramine is removing it,
     * do the same in the test.
     */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }

    if (strcmp(buf, expected_name) != 0) {
        err(1, "%s /etc/hostname don't have a expected value (expected: %s, got: %s)",
            tag, expected_name, buf);
    }
}

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s [hostname] [etc_hostname]\n", argv[0]);
        return 1;
    }

    test_gethostname("normal", argv[1]);
    test_etc_hostname("normal etc", argv[2]);
    test_fork("fork gethostname", argv[1], test_gethostname);
    test_fork("fork etc_hostname", argv[2], test_etc_hostname);

    printf("TEST OK\n");
    return 0;
}
