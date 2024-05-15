#include "pal.h"
#include "pal_regression.h"

char str[13] = "Hello World\n";

int main(int argc, char** argv, char** envp) {
    pal_printf("start program: Pie\n");

    PAL_HANDLE out = NULL;
    pal_error_t pret = PalStreamOpen("console:", PAL_ACCESS_WRONLY, /*share_flags=*/0,
                                     PAL_CREATE_NEVER, /*options=*/0, &out);

    if (pret != PAL_ERROR_SUCCESS) {
        pal_printf("PalStreamOpen failed\n");
        return 1;
    }

    size_t bytes = sizeof(str) - 1;
    int ret = PalStreamWrite(out, 0, &bytes, str);

    if (ret < 0 || bytes != sizeof(str) - 1) {
        pal_printf("PalStreamWrite failed\n");
        return 1;
    }

    PalObjectDestroy(out);
    return 0;
}
