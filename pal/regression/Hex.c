#include <assert.h>

#include "hex.h"
#include "pal.h"
#include "pal_regression.h"

char x[] = {0xde, 0xad, 0xbe, 0xef};
char y[] = {0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd, 0xcd};

static_assert(sizeof(x) <= sizeof(y), "array x is longer than array y");
char hex_buf[sizeof(y) * 2 + 1];

int main(int argc, char** argv, char** envp) {
    /* We don't care about unused args to main, but UBSan complains otherwise
     * with "call through pointer with incorrect function type" */
    __UNUSED(argc);
    __UNUSED(argv);
    __UNUSED(envp);

    pal_printf("Hex test 1 is %s\n", bytes2hex(x, sizeof(x), hex_buf, sizeof(hex_buf)));
    pal_printf("Hex test 2 is %s\n", bytes2hex(y, sizeof(y), hex_buf, sizeof(hex_buf)));
    return 0;
}
