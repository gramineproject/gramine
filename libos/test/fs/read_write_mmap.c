#include "common.h"

static void read_write_mmap(const char* file_path) {
    const size_t size = 1024 * 1024;
    int fd = open_output_fd(file_path, /*rdwr=*/true);
    printf("open(%s) RW (mmap) OK\n", file_path);

    if (ftruncate(fd, size) == -1) {
        close(fd);
        fatal_error("ftruncate\n");
    }

    void* buf_write = alloc_buffer(size);
    void* buf_read = alloc_buffer(size);

    void* m = mmap_fd(file_path, fd, PROT_READ | PROT_WRITE, 0, size);
    printf("mmap_fd(%zu) OK\n", size);
    fill_random(m, size);
    int ret = msync(m, size, MS_SYNC);
    if (ret < 0) {
        close(fd);
        fatal_error("msync\n");
    }

    read_fd(file_path, fd, buf_read, size);
    printf("read(%s) 1 RW (mmap) OK\n", file_path);
    if (memcmp(m, buf_read, size) != 0)
        fatal_error("Read data via read() is different from what was written in the mapping\n");

    fill_random(buf_write, size);
    seek_fd(file_path, fd, 0, SEEK_SET);
    printf("seek(%s) 1 RW (mmap) OK\n", file_path);
    write_fd(file_path, fd, buf_write, size);
    printf("write(%s) RW (mmap) OK\n", file_path);
    seek_fd(file_path, fd, 0, SEEK_SET);
    printf("seek(%s) 2 RW (mmap) OK\n", file_path);
    read_fd(file_path, fd, buf_read, size);
    printf("read(%s) 2 RW (mmap) OK\n", file_path);
    if (memcmp(buf_write, buf_read, size) != 0)
        fatal_error("Read data via read() is different from what was written via write()\n");
    if (memcmp(buf_write, m, size) != 0)
        fatal_error("Read data in the mapping is different from what was written via write()\n");
    printf("compare(%s) RW (mmap) OK\n", file_path);

    munmap_fd(file_path, m, size);
    printf("munmap_fd(%zu) OK\n", size);
    close_fd(file_path, fd);
    printf("close(%s) RW (mmap) OK\n", file_path);
    free(buf_write);
    free(buf_read);
}

static void read_write_mmap_different_fds(const char* file_path) {
    const size_t size = 1024 * 1024;
    int fd1 = open_output_fd(file_path, /*rdwr=*/true);
    printf("open(%s) RW fd1 (mmap) OK\n", file_path);

    if (ftruncate(fd1, size) == -1) {
        close(fd1);
        fatal_error("ftruncate fd1\n");
    }

    int fd2 = open_output_fd(file_path, /*rdwr=*/true);
    printf("open(%s) RW fd2 OK\n", file_path);

    void* m = mmap_fd(file_path, fd1, PROT_READ, 0, size);
    printf("mmap_fd(%zu) fd1 OK\n", size);

    void* buf_write = alloc_buffer(size);
    fill_random(buf_write, size);
    write_fd(file_path, fd2, buf_write, size);
    printf("write(%s) RW fd2 OK\n", file_path);

    if (memcmp(m, buf_write, size) != 0)
        fatal_error("Read data from the mapping is different from what was written via write() by "
                    "another fd of the same file\n");

    munmap_fd(file_path, m, size);
    printf("munmap_fd(%zu) fd1 OK\n", size);
    close_fd(file_path, fd1);
    printf("close(%s) RW fd1 (mmap) OK\n", file_path);
    close_fd(file_path, fd2);
    printf("close(%s) RW fd2 OK\n", file_path);
    free(buf_write);
}

int main(int argc, char* argv[]) {
    if (argc < 2)
        fatal_error("Usage: %s <file_path>\n", argv[0]);

    setup();
    read_write_mmap(argv[1]);
    read_write_mmap_different_fds(argv[1]);

    return 0;
}
