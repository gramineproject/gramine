#include "api.h"
#include "pal_regression.h"

#define FAIL(fmt...) ({ \
    pal_printf(fmt);    \
    pal_printf("\n");   \
    PalProcessExit(1);  \
})

#define TEST(output_str, fmt...) ({                                                                \
    size_t output_len = strlen(output_str);                                                        \
    char buf[0x100];                                                                               \
    int x = snprintf(buf, sizeof(buf) - 1,  fmt);                                                  \
    buf[sizeof(buf) - 1] = 0;                                                                      \
    if (x < 0 || (size_t)x != output_len) {                                                        \
        FAIL("wrong return val at %d, expected %zu, got %d", __LINE__, output_len, x);             \
    }                                                                                              \
    if (strcmp(buf, output_str)) {                                                                 \
        FAIL("wrong output string at %d, expected \"%s\", got \"%s\"", __LINE__, output_str, buf); \
    }                                                                                              \
})

int main(int argc, const char** argv) {
    const char* ptr = "123 asd";
    const char* next = ptr;

    long long a = strtoll(ptr, (char**)&next, 10);
    TEST("123 31(1) 20( )", "%lld %x(%c) %x(%c)", a, *ptr, *ptr, *next, *next);
    ptr = next;

    a = strtoll(ptr, (char**)&next, 10);
    TEST("0 20( ) 20( )", "%lld %x(%c) %x(%c)", a, *ptr, *ptr, *next, *next);

    ptr = " ";
    next = ptr;
    a = strtoll(ptr, (char**)&next, 10);
    TEST("0 20( ) 20( )", "%lld %x(%c) %x(%c)", a, *ptr, *ptr, *next, *next);

    pal_printf("TEST OK\n");
    return 0;
}
