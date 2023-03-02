/* Test description: this test verifies that in and out instructions
 * correctly generate SIGSEGV. This raises SIGSEGV once for IN and once for OUT
 * and then counts if number of SIGSEGVs are 2.
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
    int value = 0;
    int port = 0;
    sigaction(SIGSEGV, &int_handler, 0);
    if (sigsetjmp(g_point, 1) == 0) {
        __asm__ volatile("in %1, %0" : "=a"(value) : "d"(port));
    }
    puts("handled IN instruction");
    if (sigsetjmp(g_point, 1) == 0) {
        port = 0;
        __asm__ volatile("out %0, %1" : "=a"(value) : "d"(port));
    }
    puts("handled OUT instruction");
    if (g_sigsegv_triggered == EXPECTED_NUM_SIGSEGVS)
        puts("SIGSEGV TEST OK");
    else
        puts("SIGSEGV TEST FAILED");
    return 0;
}
