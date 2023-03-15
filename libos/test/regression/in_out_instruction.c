/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Fortanix Inc
 *                    Nirjhar Roy <nirjhar.roy@fortanix.com>
 */
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
    /* sigsetjmp returns 0 if it directly invocated, else it returns a non zero value if it
     * from a call to siglongjmp()
     */
    if (sigsetjmp(g_point, 1) == 0) {
        __asm__ volatile("inb %1, %0" : "=a"(value) : "d"(port));
    } else {
        if (g_sigsegv_triggered < 1) {
            errx(1, "sigsetjmp failed before inb instruction could have executed");
        }
    }
    if (sigsetjmp(g_point, 1) == 0) {
        __asm__ volatile("outb %0, %1" : : "a"(value), "d"(port));
    } else {
        if (g_sigsegv_triggered < 2) {
            errx(1, "sigsetjmp failed before outb instruction could have executed");
        }
    }
    if (g_sigsegv_triggered != EXPECTED_NUM_SIGSEGVS)
        errx(1, "Expected %d number of SIGSEGVs, but got only %d", EXPECTED_NUM_SIGSEGVS,
             g_sigsegv_triggered);
    puts("TEST OK");
    return 0;
}
