/*
 * Copyright (C) 2023 Gramine contributors
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SEALED_DATA_DIR "/tmp_tcb/data"
#define CPU_SVN_PATH "/dev/attestation/cpu_svn"
#define TCB_MIGRATION_DONE_FLAG "/tmp_tcb/info/tcb_migration_done"
#define CURRENT_CPU_SVN_PATH "/tmp_tcb/info/current_cpu_svn"
#define OLD_CPU_SVN_PATH "/tmp_tcb/info/old_cpu_svn"
#define SVN_SIZE 16

typedef struct {
    const char* path;
    const char* content;
} sealed_file_t;

sealed_file_t sealed_files[] = {
    {SEALED_DATA_DIR "/helloworld.txt", "Hello World!\n"},
    {SEALED_DATA_DIR "/subdir/helloworld.txt", "Hello World!\n from a subdirectory"},
    {SEALED_DATA_DIR "/subdir1/subdir2/helloworld.txt",
     "Hello World!\n from a nested subdirectory"},
};
int num_sealed_files = 3;

static void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
}

static int file_exists(const char* path) {
    printf("Checking existence of file: %s\n", path);
    return access(path, F_OK) == 0;
}

static int read_file_binary(const char* path, unsigned char* buffer, size_t size) {
    printf("Reading from file: %s\n", path);
    FILE* f = fopen(path, "rb");
    if (!f) {
        perror("read_file_binary fopen");
        return -1;
    }
    size_t n = fread(buffer, 1, size, f);
    fclose(f);
    return (int)n;
}

static int write_file_binary(const char* path, const unsigned char* data, size_t len) {
    printf("Writing to file: %s\n", path);
    FILE* f = fopen(path, "wb");
    if (!f) {
        perror("write_file_binary fopen");
        return -1;
    }
    size_t n = fwrite(data, 1, len, f);
    fclose(f);
    return (int)n == (int)len ? 0 : -1;
}

static int read_file_text(const char* path, char* buffer, size_t size) {
    printf("Reading from file: %s\n", path);
    FILE* f = fopen(path, "r");
    if (!f) {
        perror("fopen");
        return -1;
    }
    int n = fread(buffer, 1, size - 1, f);
    fclose(f);
    if (n > 0) {
        buffer[n] = '\0';
    }
    return n;
}

static int write_file_text(const char* path, const char* data) {
    printf("Writing to file: %s\n", path);
    FILE* f = fopen(path, "w");
    if (!f) {
        perror("fopen");
        return -1;
    }
    size_t n = fwrite(data, 1, strlen(data), f);
    fclose(f);
    return (int)n == (int)strlen(data) ? 0 : -1;
}

static int create_directories(const char* path) {
    char tmp[512];
    printf("Creating directories for path: %s\n", path);
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    for (char* p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return 0;
}

int main() {
    unsigned char cpu_svn[SVN_SIZE];
    unsigned char current_cpu_svn[SVN_SIZE];
    unsigned char old_cpu_svn[SVN_SIZE];
    printf("Starting TCB migration test\n");
    if (file_exists(TCB_MIGRATION_DONE_FLAG)) {
        printf("TCB migration already done, testing results\n");

        if (read_file_binary(CPU_SVN_PATH, cpu_svn, SVN_SIZE) < 0) {
            printf("Error reading CPU SVN\n");
            return 1;
        }
        printf("CPU SVN: ");
        print_hex(cpu_svn, SVN_SIZE);
        printf("\n");

        if (read_file_binary(CURRENT_CPU_SVN_PATH, current_cpu_svn, SVN_SIZE) < 0) {
            printf("Error reading current CPU SVN\n");
            return 1;
        }
        printf("Current CPU SVN: ");
        print_hex(current_cpu_svn, SVN_SIZE);
        printf("\n");

        if (memcmp(cpu_svn, current_cpu_svn, SVN_SIZE) != 0) {
            printf("Error: CPU SVN does not match current CPU SVN\n");
            return 1;
        }

        if (read_file_binary(OLD_CPU_SVN_PATH, old_cpu_svn, SVN_SIZE) < 0) {
            printf("Error reading old CPU SVN\n");
            return 1;
        }
        printf("Old CPU SVN: ");
        print_hex(old_cpu_svn, SVN_SIZE);
        printf("\n");

        if (memcmp(cpu_svn, old_cpu_svn, SVN_SIZE) == 0) {
            printf("Error: CPU SVN matches old CPU SVN\n");
            return 1;
        }

        printf("Sealed files:\n");
        for (int i = 0; i < num_sealed_files; i++) {
            const char* filename = sealed_files[i].path;
            const char* expected = sealed_files[i].content;

            printf("Reading sealed file: %s\n", filename);

            if (!file_exists(filename)) {
                printf("Error: Sealed file %s does not exist\n", filename);
                return 1;
            }

            char buffer[512] = {0};
            read_file_text(filename, buffer, sizeof(buffer));

            if (strcmp(buffer, expected) != 0) {
                printf("%d Error: Sealed file %s content does not match expected content\n", i,
                       filename);
                printf("Expected: %s\n", expected);
                printf("Got: %s\n", buffer);
                return 1;
            }
            printf("Sealed file %s content matches expected content\n", filename);
        }
        printf("TCB migration test successful\n");
        puts("TEST OK\n");

    } else {
        printf("Performing CPU SVN downgrade to enable old key\n");

        if (read_file_binary(CPU_SVN_PATH, cpu_svn, SVN_SIZE) < 0) {
            printf("Error reading CPU SVN\n");
            return 1;
        }
        printf("CPU SVN: ");
        print_hex(cpu_svn, SVN_SIZE);
        printf("\n");

        memcpy(old_cpu_svn, cpu_svn, SVN_SIZE);
        for (int i = 0; i < (int)SVN_SIZE - 1; i++) {
            if (cpu_svn[i + 1] == 0x00 || i + 1 == (int)SVN_SIZE - 1) {
                printf("Decreasing byte %d of cpu_svn from %d to %d\n", i, cpu_svn[i],
                       cpu_svn[i] - 1);
                old_cpu_svn[i] = cpu_svn[i] - 1;
                break;
            }
        }

        printf("Old CPU SVN: ");
        print_hex(old_cpu_svn, SVN_SIZE);
        printf("\n");

        if (write_file_binary(CPU_SVN_PATH, old_cpu_svn, SVN_SIZE) < 0) {
            printf("Error writing CPU SVN\n");
            return 1;
        }

        if (write_file_binary(CURRENT_CPU_SVN_PATH, cpu_svn, SVN_SIZE) < 0) {
            printf("Error writing current CPU SVN\n");
            return 1;
        }

        if (write_file_binary(OLD_CPU_SVN_PATH, old_cpu_svn, SVN_SIZE) < 0) {
            printf("Error writing old CPU SVN\n");
            return 1;
        }

        for (int i = 0; i < num_sealed_files; i++) {
            const char* filename = sealed_files[i].path;
            const char* content = sealed_files[i].content;

            create_directories(filename);

            if (write_file_text(filename, content) < 0) {
                printf("Error writing sealed file: %s\n", filename);
                return 1;
            }
            printf("Wrote sealed file: %s using old key\n", filename);
        }

        if (write_file_text(TCB_MIGRATION_DONE_FLAG, "done") < 0) {
            printf("Error writing TCB migration flag\n");
            return 1;
        }

        puts("TEST READY\n");
        printf("do \"cp %s %s/gramine.tcb_info\"\n", OLD_CPU_SVN_PATH, SEALED_DATA_DIR);
        printf("then restart the application to test TCB migration\n");
    }

    return 0;
}