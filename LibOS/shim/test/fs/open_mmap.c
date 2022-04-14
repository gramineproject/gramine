#include "common.h"

static void mmap_test(int fd, off_t offset, size_t length,
                      int prot, const char *prot_str,
                      int flags, const char *flags_str,
                      bool expect_success) {
    void *address = mmap(NULL, length, prot, flags, fd, offset);
    if (address == MAP_FAILED) {
        if (expect_success) {
            fatal_error("mmap %s, %s failed\n", prot_str, flags_str);
        } else {
            printf("mmap %s, %s failed as expected\n", prot_str, flags_str);
        }
    } else {
        munmap(address, length);
        if (expect_success) {
            printf("mmap %s, %s succeeded as expected\n", prot_str, flags_str);
        } else {
            fatal_error("mmap %s, %s unexpectedly succeeded\n", prot_str, flags_str);
        }
    }
}

#define MMAP_TEST(fd, offset, length, prot, flags, expect_success) \
    mmap_test(fd, offset, length, prot, #prot, flags, #flags, expect_success)

static void open_mmap(const char* path) {
    int fd = open(path, O_RDWR);

    if (fd < 0) {
        fatal_error("open %s failed!\n", path);
    }

    seek_fd(path, fd, 0, SEEK_END);
    size_t length = (size_t)tell_fd(path, fd);

    MMAP_TEST(fd, 0, length, PROT_READ, MAP_SHARED,
              /*expect_success=*/true);
    MMAP_TEST(fd, 0, length, PROT_WRITE, MAP_SHARED,
              /*expect_success=*/true);
    MMAP_TEST(fd, 0, length, PROT_READ, MAP_PRIVATE,
              /*expect_success=*/true);
    MMAP_TEST(fd, 0, length, PROT_WRITE, MAP_PRIVATE,
              /*expect_success=*/true);
    MMAP_TEST(fd, 0, length, PROT_READ | PROT_WRITE, MAP_PRIVATE,
              /*expect_success=*/true);

    close(fd);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        fatal_error("Usage: %s <path>\n", argv[0]);
    }

    setup();

    open_mmap(argv[1]);

    return 0;
}
