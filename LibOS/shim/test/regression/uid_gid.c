#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char** argv) {
    int ret;
    struct stat buf;

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

    ret = stat(argv[0], &buf);
    if (ret < 0) {
        err(EXIT_FAILURE, "chroot stat failed");
    }

    if (buf.st_uid != 1338) {
        errx(EXIT_FAILURE, "UID from chroot stat() is not equal to the value in the manifest");
    }

    if (buf.st_gid != 1337) {
        errx(EXIT_FAILURE, "GID from chroot stat() is not equal to the value in the manifest");
    }

    char file[] = "/tmp/file1";
    ret = open(file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (ret < 0) {
        err(EXIT_FAILURE, "open failed");
    }

    ret = stat(file, &buf);
    if (ret < 0) {
        err(EXIT_FAILURE, "tmpfs stat failed");
    }

    if (buf.st_uid != 1338) {
        errx(EXIT_FAILURE, "UID from tmpfs stat() is not equal to the value in the manifest");
    }

    if (buf.st_gid != 1337) {
        errx(EXIT_FAILURE, "GID from tmpfs stat() is not equal to the value in the manifest");
    }

    puts("TEST OK");
    return 0;
}
