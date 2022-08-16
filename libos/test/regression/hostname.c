#define _DEFAULT_SOURCE BSD /* This is required for gethostname */

#include <sys/wait.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void test_fork(const char* tag, const char* name, void (*f)(const char*, const char*)) {
    int status;

    pid_t pid = fork();
    if (pid == -1) {
        printf("Unable to fork %s\n", tag);
        exit(1);
    }

    if (pid == 0) {
        f(tag, name);
        exit(0);
    }

    if (wait(&status) == -1) {
        printf("Wait failed %s\n", tag);
        exit(1);
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        printf("Test failed %s\n", tag);
        exit(1);
    }
}

static void test_gethostname(const char* tag, const char* name) {
    char buf[512] = {0};

    if (gethostname(buf, sizeof(buf)) != 0) {
        printf("%sgethostname: failed %d\n", tag, errno);
        exit(1);
    }

    if (strcmp(buf, name) != 0) {
        printf("%sgethostname dosen't match hostname (expected: %s, got: %s)\n",
               tag, name, buf);
        exit(1);
    }
}

static void test_etc_hostname(const char* tag, const char* name) {
    char buf[512] = {0};
    int fd;

    fd = open("/etc/hostname", O_RDONLY);

    /*
     * If the etc hostname was not provided, assume that etc shouldn't exists.
     */
    if (strcmp(name, "") == 0) {
        if (fd != -1 || errno != ENOENT) {
            printf("The etc file shouldn't exists, but exists\n");
            exit(1);
        }
        return;
    }

    if (fd == -1) {
        printf("Unable to open /etc/hostname in %s\n", tag);
        exit(1);
    }

    int ret = read(fd, buf, sizeof(buf));
    if (ret <= 0) {
        printf("Unable to read /etc/hostname in %s\n", tag);
        exit(1);
    }

    /*
     * Sometimes etc hostname might have a trailing '\n', gramine is romving it,
     * do the same in the test.
     */
    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    }

    if (strcmp(buf, name) != 0) {
        printf("%s etc don't have a expected value (expected: %s, got: %s)\n",
               tag, name, buf);
        exit(1);
    }
}

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s [hostname] [etc_hostname]\n", argv[0]);
        return 1;
    }

    test_gethostname("", argv[1]);
    test_etc_hostname("", argv[2]);
    test_fork("fork gethostname", argv[1], test_gethostname);
    test_fork("fork etc gethostname", argv[2], test_etc_hostname);

    printf("hostname test passed\n");
    return 0;
}
