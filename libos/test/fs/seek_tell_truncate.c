#include "common.h"

#define CHUNK_SIZE 512

static void setup_file(const char* path, size_t size, void* check_buf, size_t check_size) {
    int fd = open_output_fd(path, /*rdwr=*/false);

    void* buf = alloc_buffer(size);
    fill_random(buf, size);
    write_fd(path, fd, buf, size);
    memcpy(check_buf, buf, size < check_size ? size : check_size);
    free(buf);

    close_fd(path, fd);
}

static void seek_truncate(const char* path, size_t file_pos, size_t file_truncate, void* check_buf) {
    int fd = open_output_fd(path, /*rdwr=*/false);

    seek_fd(path, fd, file_pos, SEEK_SET);

    off_t pos = tell_fd(path, fd);
    if ((size_t)pos != file_pos) {
        fatal_error("first tell failed (expected: %zu, got: %zd)", file_pos, pos);
    }
    printf("First tell(%s) returned position: %zd\n", path, pos);

    if (ftruncate(fd, file_truncate) != 0) {
        fatal_error("Failed to truncate file %s to %zu: %m\n", path, file_truncate);
    }

    pos = tell_fd(path, fd);
    if ((size_t)pos != file_pos) {
        fatal_error("second tell failed (expected: %zu, got: %zd)", file_pos, pos);
    }
    printf("Second tell(%s) returned position: %zd\n", path, pos);

    void* buf = alloc_buffer(CHUNK_SIZE);
    fill_random(buf, CHUNK_SIZE);
    write_fd(path, fd, buf, CHUNK_SIZE);
    memcpy(check_buf + pos, buf, CHUNK_SIZE);
    free(buf);

    size_t next_file_pos = file_pos + CHUNK_SIZE;
    pos = tell_fd(path, fd);
    if ((size_t)pos != next_file_pos) {
        fatal_error("third tell failed (expected: %zu, got: %zd)", next_file_pos, pos);
    }
    printf("Third tell(%s) returned position: %zd\n", path, pos);

    close_fd(path, fd);
}

static void check_contents(const char* path, void* data, size_t size) {
    int fd = open_input_fd(path);

    void* buf = alloc_buffer(size);
    read_fd(path, fd, buf, size);
    if (memcmp(buf, data, size)) {
        fatal_error("truncated data mismatch");
    }
    free(buf);

    close_fd(path, fd);
}

int main(int argc, char* argv[]) {
    if (argc < 5)
        fatal_error("Usage: %s <output> <size> <position> <truncate>\n", argv[0]);

    setup();
    size_t file_size     = strtoul(argv[2], NULL, 10);
    size_t file_pos      = strtoul(argv[3], NULL, 10);
    size_t file_truncate = strtoul(argv[4], NULL, 10);


    size_t check_size = file_pos + CHUNK_SIZE;
    if (file_truncate > check_size)
        check_size = file_truncate;
    void* check_buf = alloc_buffer(check_size);
    memset(check_buf, 0, check_size);

    setup_file(argv[1], file_size, check_buf, file_truncate);
    seek_truncate(argv[1], file_pos, file_truncate, check_buf);
    check_contents(argv[1], check_buf, check_size);

    printf("Test passed\n");

    return 0;
}
