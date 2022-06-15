#include "common.h"

#define MAX_BUF_SIZE (16 * 1024)

int write_output_file(const char* output_file, const char* buffer, int count);

static void print_usage(void) {
    printf("Usage: protect_file \t <Input file> \n");
}

int write_output_file(const char* output_file, const char* buffer, int count) {
    FILE* fptr = NULL;

    fptr = fopen(output_file, "w");
    if (fptr == NULL) {
        printf("Error in opening output file %s failed...\n", output_file);
        return 1;
    }
    fwrite(buffer, strlen(buffer), 1, fptr);
    fclose(fptr);

    printf("Successfuly wrote in protected file %s for %d iteration\n", output_file, count);

    return 0;
}

int main(int argc, char** argv) {
    int i = 1;
    char buffer[MAX_BUF_SIZE];

    memset(buffer, '0', sizeof(buffer));

    if (argc != 2) {
        print_usage();
        return 1;
    }
    printf("input file %s\n", argv[1]);

    if (write_output_file(argv[1], "Test data for checking protected file", i)) {
        printf("Creating protected text file failed for %d iteration...\n", i);
        return 1;
    }
    i += 1;

    if (write_output_file(argv[1], "Test data for existing protected file", i)) {
        printf("Writing to existing protected text file failed...\n");
        return 1;
    }

    return 0;
}
