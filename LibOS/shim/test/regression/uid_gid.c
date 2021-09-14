#include <err.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char** argv) {
    uid_t uid = getuid();
    uid_t euid = geteuid();

    if(uid != 80085 && euid != 80085) {
        errx(EXIT_FAILURE, "UID is not equal to the value in the the manifest");
    }

    uid_t gid = getgid();
    uid_t egid = getegid();

    if(gid != 1337 && egid != 1337) {
        errx(EXIT_FAILURE, "GID is not equal to the value in the the manifest");
    }

    puts("TEST OK");
    return 0;
}
