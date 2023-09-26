#include "pal.h"
#include "pal_regression.h"

#define FILE_URI "file:test.txt"

char str[12] = "Hello World";

int main(int argc, char** argv, char** envp) {
    pal_printf("Enter Main Thread\n");

    PAL_HANDLE out = NULL;
    int ret = PalStreamOpen(FILE_URI, PAL_ACCESS_RDWR, PAL_SHARE_OWNER_W | PAL_SHARE_OWNER_R,
                            PAL_CREATE_TRY, /*options=*/0, &out);

    if (ret < 0) {
        pal_printf("first PalStreamOpen failed\n");
        return 1;
    }

    size_t bytes = sizeof(str) - 1;
    ret = PalStreamWrite(out, 0, &bytes, str);
    if (ret < 0 || bytes != sizeof(str) - 1) {
        pal_printf("second PalStreamWrite failed\n");
        return 1;
    }

    PalObjectDestroy(out);

    PAL_HANDLE in = NULL;
    ret = PalStreamOpen(FILE_URI, PAL_ACCESS_RDONLY, /*share_flags=*/0, PAL_CREATE_NEVER,
                        /*options=*/0, &in);
    if (ret < 0) {
        pal_printf("third PalStreamOpen failed\n");
        return 1;
    }

    bytes = sizeof(str);
    memset(str, 0, bytes);
    ret = PalStreamRead(in, 0, &bytes, str);
    if (ret < 0) {
        pal_printf("PalStreamRead failed\n");
        return 1;
    }
    if (bytes > sizeof(str) - 1) {
        pal_printf("PalStreamRead read more than expected\n");
        return 1;
    }
    str[bytes] = '\0';

    pal_printf("%s\n", str);

    ret = PalStreamDelete(in, PAL_DELETE_ALL);
    if (ret < 0) {
        pal_printf("PalStreamDelete failed\n");
        return 1;
    }

    PAL_HANDLE del = NULL;
    ret = PalStreamOpen(FILE_URI, PAL_ACCESS_RDWR, /*share_flags=*/0, PAL_CREATE_NEVER,
                        /*options=*/0, &del);

    if (ret >= 0) {
        pal_printf("PalStreamDelete did not actually delete\n");
        return 1;
    }

    pal_printf("Leave Main Thread\n");
    return 0;
}
