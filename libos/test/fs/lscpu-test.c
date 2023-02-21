/* Test Description: This test verifies that in/out instructions correctly generate
 * SIGSEGV. It raises SIGSEGV once for in and one for out and then counts if 
 * number of SIGSEGVs are is 2. Once this passes it runs lscpu command.
 * 
 */

#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809

#include <assert.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#define EXPECTED_NUM_SIGSEGVS 2
#define COMMAND "/usr/bin/lscpu"
int g_sigsegv_triggered = 0;
jmp_buf g_point;
jmp_buf g_point2;


static void fault_handler(int ignored)
{
    g_sigsegv_triggered++;
    siglongjmp(g_point, 1);
    return;
}

static int run_system(const char *command)
{
    return system(command);
}

int main(void)
{
    struct sigaction int_handler = {.sa_handler=fault_handler,
                                    .sa_flags = SA_RESTART};
    sigaction(SIGSEGV, &int_handler, 0);
    if (sigsetjmp(g_point, 1) == 0) {
        __asm__("in %dx, %al;");/* AT & T style */
    }
    printf("handled in instruction\n");

    if (sigsetjmp(g_point, 1) == 0) {
      __asm__("out %al, %dx;");/* AT & T style */
    }
    printf("handled out instruction\n");

    assert(g_sigsegv_triggered == EXPECTED_NUM_SIGSEGVS);

    /* Once we are sure that in/out instructions generate correct signals we can
     * check for lscpu
     */
    int ret = run_system(COMMAND);
    assert(ret == 0);

    printf("\nlscpu-test test passed\n");

    return 0;
}
