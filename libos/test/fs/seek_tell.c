#include <inttypes.h>

#include "common.h"

#define EXTEND_SIZE 4097

// Verify Unsigned
#define VERIFYU(msg, expected, got) do {                                \
    uint64_t __l = (expected);                                          \
    uint64_t __r = (got);                                               \
    if (__l != __r) {                                                   \
        fatal_error("%s:%d %s (expected %"PRIu64", got %"PRIu64")",     \
                    __func__, __LINE__, msg, __l, __r);                 \
    }                                                                   \
} while(0)

static void seek_input_fd(const char* path, uint64_t size) {
    int f = open_input_fd(path);

    seek_fd(path, f, 0, SEEK_SET);
    off_t pos = tell_fd(path, f);
    VERIFYU("tell position mismatch", 0, pos);

    seek_fd(path, f, 0, SEEK_END);
    pos = tell_fd(path, f);
    VERIFYU("tell position mismatch", size, pos);

    seek_fd(path, f, -pos, SEEK_END); // rewind
    pos = tell_fd(path, f);
    VERIFYU("tell position mismatch", 0, pos);

    close_fd(path, f);
}

static void seek_input_stdio(const char* path, uint64_t size) {
    FILE* f = open_input_stdio(path);

    seek_stdio(path, f, 0, SEEK_SET);
    off_t pos = tell_stdio(path, f);
    VERIFYU("ftell position mismatch", 0, pos);

    seek_stdio(path, f, 0, SEEK_END);
    pos = tell_stdio(path, f);
    VERIFYU("ftell position mismatch", size, pos);

    seek_stdio(path, f, -pos, SEEK_END); // rewind
    pos = tell_stdio(path, f);
    VERIFYU("ftell position mismatch", 0, pos);

    close_stdio(path, f);
}

static void seek_output_fd(const char* path, uint64_t size) {
    uint8_t buf[EXTEND_SIZE + 1] = {1};
    int f = open_output_fd(path, /*rdwr=*/true);

    seek_fd(path, f, 0, SEEK_SET);
    off_t pos = tell_fd(path, f);
    VERIFYU("tell position mismatch", 0, pos);

    seek_fd(path, f, 0, SEEK_END);
    pos = tell_fd(path, f);
    VERIFYU("tell position mismatch", size, pos);

    seek_fd(path, f, EXTEND_SIZE, SEEK_CUR); // extend
    write_fd(path, f, buf, 1);
    size += 1;
    seek_fd(path, f, -EXTEND_SIZE - 1, SEEK_CUR); // rewind to former end
    read_fd(path, f, buf, EXTEND_SIZE + 1);
    for (uint64_t i = 0; i < EXTEND_SIZE + 1; i++) {
        if (i == EXTEND_SIZE) {
            if (buf[i] != 1)
                fatal_error("invalid last byte\n");
        } else {
            if (buf[i] != 0)
                fatal_error("extended buffer not zeroed\n");
        }
    }
    size += EXTEND_SIZE;
    pos = tell_fd(path, f);
    VERIFYU("tell position mismatch", size, pos);

    uint64_t pos_over = pos * 2;
    seek_fd(path, f, pos_over, SEEK_SET);
    pos = tell_fd(path, f);
    VERIFYU("tell position mismatch", pos_over, pos);

    uint64_t ret = read(f, &buf, 1);
    VERIFYU("read failed", 0, ret);

    seek_fd(path, f, 0, SEEK_END);
    pos = tell_fd(path, f);
    VERIFYU("tell position mismatch", size, pos);

    close_fd(path, f);
}

static void seek_output_stdio(const char* path, uint64_t size) {
    uint8_t buf[EXTEND_SIZE + 1] = {1};
    FILE* f = open_output_stdio(path, /*rdwr=*/true);

    seek_stdio(path, f, 0, SEEK_SET);
    off_t pos = tell_stdio(path, f);
    VERIFYU("ftell position mismatch", 0, pos);

    seek_stdio(path, f, 0, SEEK_END);
    pos = tell_stdio(path, f);
    VERIFYU("ftell position mismatch", size, pos);

    seek_stdio(path, f, EXTEND_SIZE, SEEK_CUR); // extend
    write_stdio(path, f, buf, 1);
    size += 1;
    seek_stdio(path, f, -EXTEND_SIZE - 1, SEEK_CUR); // rewind to former end
    read_stdio(path, f, buf, EXTEND_SIZE + 1);
    for (uint64_t i = 0; i < EXTEND_SIZE + 1; i++) {
        if (i == EXTEND_SIZE) {
            if (buf[i] != 1)
                fatal_error("invalid last byte\n");
        } else {
            if (buf[i] != 0)
                fatal_error("extended buffer not zeroed\n");
        }
    }
    size += EXTEND_SIZE;
    pos = tell_stdio(path, f);
    VERIFYU("ftell position mismatch", size, pos);

    uint64_t pos_over = pos * 2;
    seek_stdio(path, f, pos_over, SEEK_SET);
    pos = tell_stdio(path, f);
    VERIFYU("ftell position mismatch", pos_over, pos);

    uint64_t ret = fread(&buf, 1, 1, f);
    VERIFYU("fread failed", 0, ret);

    seek_stdio(path, f, 0, SEEK_END);
    pos = tell_stdio(path, f);
    VERIFYU("ftell position mismatch", size, pos);

    close_stdio(path, f);
}

int main(int argc, char* argv[]) {
    setup();

    if (argc < 4)
        fatal_error("Usage: %s <input_path> <output_path_1> <output_path_2>\n", argv[0]);

    uint64_t argv1_size = file_size(argv[1]);
    uint64_t argv2_size = file_size(argv[2]);
    uint64_t argv3_size = file_size(argv[3]);

    seek_input_fd(argv[1], argv1_size);
    seek_input_stdio(argv[1], argv1_size);
    seek_output_fd(argv[2], argv2_size);
    seek_output_stdio(argv[3], argv3_size);

    printf("Test passed\n");

    return 0;
}
