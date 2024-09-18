#include <stdbool.h>

#include "pal.h"
#include "pal_regression.h"

int count = 0;
int i     = 0;

static void handler(bool is_in_pal, uintptr_t addr, PAL_CONTEXT* context) {
    __UNUSED(is_in_pal);

    pal_printf("failure in the handler: 0x%08lx\n", addr);
    count++;

    if (count == 30)
        PalProcessExit(0);
}

int main(int argc, char** argv, char** envp) {
    /* We don't care about unused args to main, but UBSan complains otherwise
     * with "call through pointer with incorrect function type" */
    __UNUSED(argc);
    __UNUSED(argv);
    __UNUSED(envp);

    pal_printf("Enter Main Thread\n");

    PalSetExceptionHandler(handler, PAL_EVENT_ARITHMETIC_ERROR);

    __asm__ volatile (
            "movq $1, %%rax\n"
            "cqo\n"
            "movq $0, %%rbx\n"
            "divq %%rbx\n"
            "nop\n"
            ::: "rax", "rbx", "rdx", "cc");

    pal_printf("Leave Main Thread\n");
    return 0;
}
