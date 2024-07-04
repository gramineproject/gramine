#include "common.h"

static void read_append(const char* file_path) {
    const size_t size = 1024 * 1024;

    void* buf1 = alloc_buffer(size);
    void* buf2 = alloc_buffer(size);
    fill_random(buf1, size);

    ssize_t bytes_read;

    /* test 1: create new file, append buf1 in two chunks to it, try to read (this should return EOF
     * because appends moved file pos), then reset the file pos and read again */
    printf("TEST 1 (%s)\n", file_path);
    int fd = open_output_fd_append(file_path);
    printf("open(%s) OK\n", file_path);
    write_fd(file_path, fd, buf1, size / 2);
    printf("first write(%s) OK\n", file_path);
    write_fd(file_path, fd, buf1 + size / 2, size - size / 2);
    printf("second write(%s) OK\n", file_path);
    bytes_read = read(fd, buf2, size);
    if (bytes_read != 0)
        fatal_error("Read after append did not indicate EOF\n");
    printf("first read(%s) OK\n", file_path);
    seek_fd(file_path, fd, 0, SEEK_SET);
    printf("seek(%s) OK\n", file_path);
    read_fd(file_path, fd, buf2, size);
    printf("second read(%s) OK\n", file_path);
    if (memcmp(buf1, buf2, size) != 0)
        fatal_error("Read data is different from what was written\n");
    printf("compare(%s) OK\n", file_path);
    close_fd(file_path, fd);
    printf("close(%s) OK\n", file_path);
    size_t file_size1 = file_size(file_path);
    if (file_size1 != size)
        fatal_error("File size is wrong (expected %lu got %lu)\n", size, file_size1);
    printf("file_size(%s) OK\n", file_path);


    /* test 2: open the file created previously (it must contain buf1), then read (this should
     * return buf1 as there was no write/append operation yet, so file pos is zero), then reset the
     * file pos and append buf1 (this should result in buf1 + buf1 contents of the file) */
    printf("TEST 2 (%s)\n", file_path);
    fd = open_output_fd_append(file_path);
    printf("open(%s) OK\n", file_path);
    read_fd(file_path, fd, buf2, size);
    printf("first read(%s) OK\n", file_path);
    if (memcmp(buf1, buf2, size) != 0)
        fatal_error("Read data is different from what was written\n");
    printf("first compare(%s) OK\n", file_path);
    bytes_read = read(fd, buf2, size);
    if (bytes_read != 0)
        fatal_error("Second read did not indicate EOF\n");
    printf("second read(%s) OK\n", file_path);
    seek_fd(file_path, fd, 0, SEEK_SET);
    printf("seek(%s) OK\n", file_path);
    write_fd(file_path, fd, buf1, size);
    printf("write(%s) OK\n", file_path);
    seek_fd(file_path, fd, 0, SEEK_SET);
    printf("seek(%s) OK\n", file_path);
    read_fd(file_path, fd, buf2, size);
    printf("first read(%s) after appending OK\n", file_path);
    if (memcmp(buf1, buf2, size) != 0)
        fatal_error("Read data is different from what was written\n");
    read_fd(file_path, fd, buf2, size);
    printf("second read(%s) after appending OK\n", file_path);
    if (memcmp(buf1, buf2, size) != 0)
        fatal_error("Read data is different from what was written\n");
    printf("compare(%s) OK\n", file_path);
    close_fd(file_path, fd);
    printf("close(%s) OK\n", file_path);
    size_t file_size2 = file_size(file_path);
    if (file_size2 != size * 2)
        fatal_error("File size is wrong (expected %lu got %lu)\n", size * 2, file_size2);
    printf("file_size(%s) OK\n", file_path);

    /* test 3: open the file created previously (size must be sizeof(buf1) * 2) in no-append mode,
     * reset file pos and write buf1 (must overwrite contents, so file size must stay the same),
     * then change to append mode, reset file pos and write buf1 (must append, so size will
     * increase) */
    printf("TEST 3 (%s)\n", file_path);
    fd = open_output_fd(file_path, /*rdwr=*/true);
    printf("open(%s) OK\n", file_path);
    seek_fd(file_path, fd, 0, SEEK_SET);
    printf("first seek(%s) OK\n", file_path);
    write_fd(file_path, fd, buf1, size);
    printf("first write(%s) OK\n", file_path);
    int fcntl_ret = fcntl(fd, F_SETFL, O_APPEND);
    if (fcntl_ret < 0)
        fatal_error("Could not set O_APPEND flag using fcntl()\n");
    seek_fd(file_path, fd, 0, SEEK_SET);
    printf("second seek(%s) OK\n", file_path);
    write_fd(file_path, fd, buf1, size);
    printf("second write(%s) OK\n", file_path);
    seek_fd(file_path, fd, 0, SEEK_SET);
    printf("third seek(%s) OK\n", file_path);
    for (int i = 0; i < 2; i++) {
        read_fd(file_path, fd, buf2, size);
        printf("read number %d (%s) OK\n", i + 1, file_path);
        if (memcmp(buf1, buf2, size) != 0)
            fatal_error("read number %d: Read data is different from what was written\n", i + 1);
    }
    printf("compare(%s) OK\n", file_path);
    close_fd(file_path, fd);
    printf("close(%s) OK\n", file_path);
    size_t file_size3 = file_size(file_path);
    if (file_size3 != size * 3)
        fatal_error("File size is wrong (expected %lu got %lu)\n", size * 3, file_size3);
    printf("file_size(%s) OK\n", file_path);

    free(buf1);
    free(buf2);
}

int main(int argc, char* argv[]) {
    if (argc < 2)
        fatal_error("Usage: %s <file_path>\n", argv[0]);

    setup();
    read_append(argv[1]);

    printf("TEST OK\n");
    return 0;
}
