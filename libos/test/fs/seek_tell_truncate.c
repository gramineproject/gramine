#include "common.h"

#define CHUNK_SIZE 512

static void setup_files(const char* path, size_t size) {
    int fd = open_output_fd(path, /*rdwr=*/false);

    void* buf = alloc_buffer(size);
    fill_random(buf, size);
    write_fd(path, fd, buf, size);

    close_fd(path, fd);
}

static void seek_truncate(const char* path, size_t file_pos, size_t file_truncate) {
    int fd = open_output_fd(path, /*rdwr=*/false);
    printf("open(%s) output OK\n", path);

    seek_fd(path, fd, file_pos, SEEK_SET);
    printf("seek(%s) output OK: %zd\n", path, file_pos);

    off_t pos = tell_fd(path, fd);
    printf("first tell(%s) output position OK: %zd\n", path, pos);

    if (ftruncate(fd, file_truncate) != 0) {
        fatal_error("Failed to truncate file %s to %zd: %s\n", path, file_truncate,
                    strerror(errno));
    }
    printf("truncate(%s) to %zd OK\n", path, file_truncate);

    pos = tell_fd(path, fd);
    printf("second tell(%s) output position OK: %zd\n", path, pos);

    void* buf = alloc_buffer(CHUNK_SIZE);
    fill_random(buf, CHUNK_SIZE);
    write_fd(path, fd, buf, CHUNK_SIZE);

    pos = tell_fd(path, fd);
    printf("third tell(%s) output position OK: %zd\n", path, pos);

    close_fd(path, fd);
    printf("close(%s) OK\n", path);
}

int main(int argc, char* argv[]) {
    if (argc < 4)
        fatal_error("Usage: %s <output> <size> <position> <truncate>\n", argv[0]);

    setup();
    size_t file_size     = strtoul(argv[2], NULL, 10);
    size_t file_pos      = strtoul(argv[3], NULL, 10);
    size_t file_truncate = strtoul(argv[4], NULL, 10);

    setup_files(argv[1], file_size);
    seek_truncate(argv[1], file_pos, file_truncate);

    return 0;
}
