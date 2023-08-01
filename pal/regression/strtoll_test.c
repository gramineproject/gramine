#include "api.h"
#include "pal_regression.h"

int main(int argc, const char** argv) {
    const char* ptr = "123 asd";
    const char* next = ptr;

    long long a = strtoll(ptr, (char**)&next, 10);
    if (a != 123 || next != ptr + 3) {
        FAIL("Wrong return values in %d, got (a, next) = (%lld, %p), expected (%d, %p)",
             __LINE__, a, next, 123, ptr + 3);
    }
    ptr = next;

    /* nothing to convert */
    a = strtoll(ptr, (char**)&next, 10);
    if (a != 0 || next != ptr) {
        FAIL("Wrong return values in %d, got (a, next) = (%lld, %p), expected (%d, %p)",
             __LINE__, a, next, 0, ptr);
    }

    ptr = " ";
    next = ptr;
    a = strtoll(ptr, (char**)&next, 10);
    if (a != 0 || next != ptr) {
        FAIL("Wrong return values in %d, got (a, next) = (%lld, %p), expected (%d, %p)",
             __LINE__, a, next, 0, ptr);
    }

    /* corner case of parsing "0" with base 0 -- Gramine had a bug of not updating `next` */
    ptr = "0";
    next = ptr;
    a = strtoll(ptr, (char**)&next, 0);
    if (a != 0 || next != ptr + 1) {
        FAIL("Wrong return values in %d, got (a, next) = (%lld, %p), expected (%d, %p)",
             __LINE__, a, next, 0, ptr + 1);
    }

    pal_printf("TEST OK\n");
    return 0;
}
