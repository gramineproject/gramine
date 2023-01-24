#include "common.h"

static void read_perm(struct stat* st, char* perm) {
    int flags[9] = {
        S_IRUSR, S_IWUSR, S_IXUSR,
        S_IRGRP, S_IWGRP, S_IXGRP,
        S_IROTH, S_IWOTH, S_IXOTH,
    };
    char modes[3] = {'r', 'w', 'x'};

    perm[0] = S_ISDIR(st->st_mode) ? 'd' : '-';

    for (int i = 0; i < 9; i++)
        perm[i+1] = (st->st_mode & flags[i]) ? modes[i % 3] : '-';
}

static void chmod_stat(const char* file_path) {
    struct stat st;
    char perm[11] = { 0, };

    int fd = open_output_fd(file_path, /*rdwr*/true);
    printf("open(%s) RW OK\n", file_path);

    if (stat(file_path, &st) != 0)
        fatal_error("Failed to stat file %s: %s\n", file_path, strerror(errno));

    read_perm(&st, perm);
    if (memcmp(perm, "-rw-r--r--", 10))
        fatal_error("File permission is different (expected: %s, actual: %s)\n", "-rw-r--r--", perm);

    printf("read_perm(%s) %s OK\n", file_path, perm);

    if (chmod(file_path, (st.st_mode & ~S_IWUSR)))
        fatal_error("chmod failed\n");

    if (stat(file_path, &st) != 0)
        fatal_error("Failed to stat file %s: %s\n", file_path, strerror(errno));

    read_perm(&st, perm);
    if (memcmp(perm, "-r--r--r--", 10))
        fatal_error("File permission is different (expected: %s, actual: %s)\n", "-r--r--r--", perm);

    printf("read_perm(%s) %s OK\n", file_path, perm);

    close_fd(file_path, fd);
    printf("close(%s) RW OK\n", file_path);
}

int main(int argc, char* argv[]) {
    if (argc < 2)
        fatal_error("Usage: %s <file_path>\n", argv[0]);

    setup();

    chmod_stat(argv[1]);
}