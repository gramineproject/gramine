#include "api.h"
#include "pal_regression.h"

#define FAIL(fmt...) ({ \
    pal_printf(fmt);    \
    pal_printf("\n");   \
    PalProcessExit(1);  \
})

int main(int argc, const char** argv) {
    const char* ptr = "123 asd";
    const char* next = ptr;

    long long a = strtoll(ptr, (char**)&next, 10);
    if (a != 123 || *ptr != '1' || next != ptr + 3) {
        FAIL("Wrong return values in %d, got (a, ptr, next) = (%lld, %c, %p), expected (%d, %c, %p)",
             __LINE__, a, *ptr, next, 123, '1', ptr + 3);
    }
    ptr = next;

    /* nothing to convert */
    a = strtoll(ptr, (char**)&next, 10);
    if (a != 0 || *ptr != ' ' || next != ptr) {
        FAIL("Wrong return values in %d, got (a, ptr, next) = (%lld, %c, %p), expected (%d, %c, %p)",
             __LINE__, a, *ptr, next, 0, ' ', ptr);
    }

    ptr = " ";
    next = ptr;
    a = strtoll(ptr, (char**)&next, 10);
    if (a != 0 || *ptr != ' ' || next != ptr) {
        FAIL("Wrong return values in %d, got (a, ptr, next) = (%lld, %c, %p), expected (%d, %c, %p)",
             __LINE__, a, *ptr, next, 0, ' ', ptr);
    }

    pal_printf("TEST OK\n");
    return 0;
}
