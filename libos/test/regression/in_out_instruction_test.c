/* Test Description: This test verifies that in and out instructions 
 * correctly generate SIGSEGV. This raises SIGSEGV once for in and once for out  
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
static jmp_buf g_point;

static void fault_handler(int signum) {
    assert(signum == SIGSEGV);
    g_sigsegv_triggered++;
    siglongjmp(g_point, 1);
    return;
}

int main(void) {
    struct sigaction int_handler = {.sa_handler=fault_handler,
                                    .sa_flags = SA_RESTART};
    sigaction(SIGSEGV, &int_handler, 0);
    if (CHECK(sigsetjmp(g_point, 1)) == 0) {
        __asm__("mov $0, %al;");
        __asm__("mov $0, %dx;");
        __asm__("in %dx, %al;");/* AT & T style */
    }
    puts("handled in instruction\n");
    if (CHECK(sigsetjmp(g_point, 1)) == 0) {
        __asm__("mov $0, %al;");
        __asm__("mov $0, %dx;");
        __asm__("out %al, %dx;");/* AT & T style */
    }
    puts("handled out instruction\n");
    assert(g_sigsegv_triggered == EXPECTED_NUM_SIGSEGVS);
    puts("SIGSEGV TEST OK");
    return 0;
}