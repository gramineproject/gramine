#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


int main(int argc, char** argv) {
    int r;
    struct stat buffer;
    struct stat* buf = &buffer;

    uid_t uid  = getuid();
    uid_t euid = geteuid();

    if (uid != 1338 || euid != 1338) {
        errx(EXIT_FAILURE, "UID/effective UID are not equal to the value in the manifest");
    }

    uid_t gid  = getgid();
    uid_t egid = getegid();

    if (gid != 1337 || egid != 1337) {
        errx(EXIT_FAILURE, "GID/effective GID are not equal to the value in the manifest");
    }

    // check stat uid and gid
    r = stat(argv[0], buf);
    if (r != 0) {
        errx(EXIT_FAILURE, "Something unexpected went wrong in stat function. Error code: %d", r);
    }

    if (buf->st_uid != 1338) {
        errx(EXIT_FAILURE, "UID is not equal to the value in the manifest");
    }

    if (buf->st_gid != 1337) {
        errx(EXIT_FAILURE, "GID is not equal to the value in the manifest");
    }

    puts("TEST OK");
    return 0;
}
