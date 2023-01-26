#include "common.h"

static void chmod_stat(const char* file_path) {
    struct stat st;
    uint32_t perm, expected_perm;

    int fd = open_output_fd(file_path, /*rdwr*/true);

    if (stat(file_path, &st) != 0)
        fatal_error("Failed to stat file %s: %s\n", file_path, strerror(errno));

    perm = st.st_mode & ACCESSPERMS;
    expected_perm = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
    if (perm != expected_perm)
        fatal_error("File permission is different (expected: %o, actual: %o)\n", expected_perm, perm);

    if (chmod(file_path, (st.st_mode & ~S_IWUSR)))
        fatal_error("chmod failed\n");

    if (stat(file_path, &st) != 0)
        fatal_error("Failed to stat file %s: %s\n", file_path, strerror(errno));

    perm = st.st_mode & ACCESSPERMS;
    expected_perm = S_IRUSR | S_IRGRP | S_IROTH;
    if (perm != expected_perm)
        fatal_error("File permission is different (expected: %o, actual: %o)\n", expected_perm, perm);

    close_fd(file_path, fd);

    printf("TEST OK\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2)
        fatal_error("Usage: %s <file_path>\n", argv[0]);

    setup();

    chmod_stat(argv[1]);
}