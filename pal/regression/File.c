#include "api.h"
#include "pal.h"
#include "pal_regression.h"

#define NUM_TO_HEX(num) ((num) >= 10 ? 'a' + ((num) - 10) : '0' + (num))
#define BUF_SIZE        40

char buffer1[BUF_SIZE];
char buffer2[BUF_SIZE];
char hex_buf[BUF_SIZE * 2 + 1];

static void print_hex(const char* fmt, const void* data, size_t size) {
    hex_buf[size * 2] = '\0';
    for (size_t i = 0; i < size; i++) {
        unsigned char b = ((unsigned char*)data)[i];
        hex_buf[i * 2]     = NUM_TO_HEX(b >> 4);
        hex_buf[i * 2 + 1] = NUM_TO_HEX(b & 0xf);
    }
    pal_printf(fmt, hex_buf);
}

int main(int argc, char** argv, char** envp) {
    int ret;

    /* test regular file opening */

    PAL_HANDLE file1 = NULL;
    ret = PalStreamOpen("file:File.manifest", PAL_ACCESS_RDWR, /*share_flags=*/0,
                        PAL_CREATE_NEVER, /*options=*/0, &file1);
    if (ret >= 0 && file1) {
        pal_printf("File Open Test 1 OK\n");

        /* test file read */
        size_t size = sizeof(buffer1);
        ret = PalStreamRead(file1, 0, &size, buffer1);
        if (ret == 0 && size == sizeof(buffer1)) {
            print_hex("Read Test 1 (0th - 40th): %s\n", buffer1, size);
        }

        size = sizeof(buffer1);
        ret = PalStreamRead(file1, 0, &size, buffer1);
        if (ret == 0 && size == sizeof(buffer1)) {
            print_hex("Read Test 2 (0th - 40th): %s\n", buffer1, size);
        }

        size = sizeof(buffer2);
        ret = PalStreamRead(file1, 200, &size, buffer2);
        if (ret == 0 && size == sizeof(buffer2)) {
            print_hex("Read Test 3 (200th - 240th): %s\n", buffer2, size);
        }

        /* test file attribute query */

        PAL_STREAM_ATTR attr1;
        ret = PalStreamAttributesQueryByHandle(file1, &attr1);
        if (ret >= 0) {
            pal_printf("Query by Handle: type = %d, size = %ld\n", attr1.handle_type,
                       attr1.pending_size);
        }

        /* test file map */

        uintptr_t mem1_addr;
        ret = mem_bkeep_alloc(PAGE_SIZE, &mem1_addr);
        if (ret < 0) {
            pal_printf("mem_bkeep_alloc failed: %d\n", ret);
            return 1;
        }
        void* mem1 = (void*)mem1_addr;
        ret = PalStreamMap(file1, mem1, PAL_PROT_READ | PAL_PROT_WRITECOPY, 0, PAGE_SIZE);
        if (ret >= 0 && mem1) {
            memcpy(buffer1, mem1, 40);
            print_hex("Map Test 1 (0th - 40th): %s\n", buffer1, 40);

            memcpy(buffer2, mem1 + 200, 40);
            print_hex("Map Test 2 (200th - 240th): %s\n", buffer2, 40);

            ret = PalVirtualMemoryFree(mem1, PAGE_SIZE);
            if (ret < 0) {
                pal_printf("PalVirtualMemoryFree failed\n");
                return 1;
            }
            ret = mem_bkeep_free((uintptr_t)mem1, PAGE_SIZE);
            if (ret < 0) {
                pal_printf("mem_bkeep_free failed: %d\n", ret);
                return 1;
            }
        } else {
            pal_printf("Map Test 1 & 2: Failed to map buffer\n");
        }

        PalObjectDestroy(file1);
    }

    PAL_HANDLE file2 = NULL;
    ret = PalStreamOpen("file:File.manifest", PAL_ACCESS_RDWR, /*share_flags=*/0,
                        PAL_CREATE_NEVER, /*options=*/0, &file2);
    if (ret >= 0 && file2) {
        pal_printf("File Open Test 2 OK\n");
        PalObjectDestroy(file2);
    }

    PAL_HANDLE file3 = NULL;
    ret = PalStreamOpen("file:../regression/File.manifest", PAL_ACCESS_RDWR, /*share_flags=*/0,
                        PAL_CREATE_NEVER, /*options=*/0, &file3);
    if (ret >= 0 && file3) {
        pal_printf("File Open Test 3 OK\n");
        PalObjectDestroy(file3);
    }

    PAL_STREAM_ATTR attr2;
    ret = PalStreamAttributesQuery("file:File.manifest", &attr2);
    if (ret >= 0) {
        pal_printf("Query: type = %d, size = %ld\n", attr2.handle_type, attr2.pending_size);
    }

    /* test regular file creation */

    PAL_HANDLE file4 = NULL;
    ret = PalStreamOpen("file:file_nonexist.tmp", PAL_ACCESS_RDWR,
                        PAL_SHARE_OWNER_R | PAL_SHARE_OWNER_W, PAL_CREATE_ALWAYS, /*options=*/0,
                        &file4);
    if (ret >= 0 && file4)
        pal_printf("File Creation Test 1 OK\n");

    PAL_HANDLE file5 = NULL;
    ret = PalStreamOpen("file:file_nonexist.tmp", PAL_ACCESS_RDWR,
                        PAL_SHARE_OWNER_R | PAL_SHARE_OWNER_W, PAL_CREATE_ALWAYS, /*options=*/0,
                        &file5);
    if (ret >= 0) {
        PalObjectDestroy(file5);
    } else {
        pal_printf("File Creation Test 2 OK\n");
    }

    PAL_HANDLE file6 = NULL;
    ret = PalStreamOpen("file:file_nonexist.tmp", PAL_ACCESS_RDWR,
                        PAL_SHARE_OWNER_R | PAL_SHARE_OWNER_W, PAL_CREATE_TRY, /*options=*/0,
                        &file6);
    if (ret >= 0 && file6) {
        pal_printf("File Creation Test 3 OK\n");
        PalObjectDestroy(file6);
    }

    if (file4) {
        /* test file writing */

        size_t size = sizeof(buffer1);
        ret = PalStreamWrite(file4, 0, &size, buffer1);
        if (ret < 0)
            goto fail_writing;

        size = sizeof(buffer2);
        ret = PalStreamWrite(file4, 0, &size, buffer2);
        if (ret < 0)
            goto fail_writing;

        size = sizeof(buffer1);
        ret = PalStreamWrite(file4, 200, &size, buffer1);
        if (ret < 0)
            goto fail_writing;

        /* test file truncate */
        ret = PalStreamSetLength(file4, PalGetPalPublicState()->alloc_align);
        if (ret < 0) {
            goto fail_writing;
        }

    fail_writing:
        PalObjectDestroy(file4);
        if (ret < 0) {
            return 1;
        }
    }

    PAL_HANDLE file7 = NULL;
    ret = PalStreamOpen("file:file_delete.tmp", PAL_ACCESS_RDONLY, /*share_flags=*/0,
                        PAL_CREATE_NEVER, /*options=*/0, &file7);
    if (ret >= 0 && file7) {
        ret = PalStreamDelete(file7, PAL_DELETE_ALL);
        if (ret < 0) {
            pal_printf("PalStreamDelete failed\n");
            return 1;
        }
        PalObjectDestroy(file7);
    }

    return 0;
}
