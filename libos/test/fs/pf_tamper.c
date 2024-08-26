#include "common.h"

static void read_complete_file(const char* path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        printf("ERROR: Failed to open input file %s: %s\n", path, strerror(errno));
	return;
    }

    char buf[1024];
    while (true) {
        ssize_t ret = read(fd, buf, sizeof(buf));
        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            printf("ERROR: Failed to read file %s: %s\n", path, strerror(errno));
	    return;
        }
        if (ret == 0)
            break;
    }

    if (close(fd) != 0)
        printf("ERROR: Failed to close file %s: %s\n", path, strerror(errno));
}


int main(int argc, char* argv[]) {
    if (argc < 2)
        fatal_error("Usage: %s <file_path>\n", argv[0]);

    setup();
    read_complete_file(argv[1]);
    return 0;
}
