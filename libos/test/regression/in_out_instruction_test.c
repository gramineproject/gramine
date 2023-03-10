/* Test description: this test verifies that in and out instructions correctly generate SIGSEGV.
 * This raises SIGSEGV once for IN and once for OUT and then counts if number of SIGSEGVs is 2.
 */
#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809

#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "common.h"

#define EXPECTED_NUM_SIGSEGVS 2
static int g_sigsegv_triggered = 0;
static sigjmp_buf g_point;

static void fault_handler(int signum) {
    assert(signum == SIGSEGV);
    g_sigsegv_triggered++;
    siglongjmp(g_point, 1);
}

int main(void) {
    struct sigaction int_handler = {.sa_handler=fault_handler,
                                    .sa_flags = SA_RESTART};
    unsigned char value = 0;
    unsigned short port = 0x3F8;
    CHECK(sigaction(SIGSEGV, &int_handler, NULL));
    if (sigsetjmp(g_point, 1) == 0) {
        __asm__ volatile("inb %1, %0" : "=a"(value) : "d"(port));
    }
    puts("handled IN instruction");
    if (sigsetjmp(g_point, 1) == 0) {
        __asm__ volatile("outb %0, %1" : : "a"(value), "d"(port));
    }
    puts("handled OUT instruction");
    if (g_sigsegv_triggered != EXPECTED_NUM_SIGSEGVS)
        errx(1, "Expected %d number of SIGSEGVs, but got only %d", EXPECTED_NUM_SIGSEGVS,
             g_sigsegv_triggered);
    puts("SIGSEGV TEST OK");
    return 0;
}
