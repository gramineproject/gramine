#include <stdnoreturn.h>

#include "api.h"
#include "cpu.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_regression.h"

static void wait_for(int* ptr, int val) {
    while (__atomic_load_n(ptr, __ATOMIC_ACQUIRE) != val) {
        CPU_RELAX();
    }
}

static void set(int* ptr, int val) {
    __atomic_store_n(ptr, val, __ATOMIC_RELEASE);
}

static int g_clear_thread_exit = 1;
static int g_ready = 0;

static noreturn int thread_func(void* arg) {
    PAL_HANDLE sleep_handle = NULL;
    CHECK(PalEventCreate(&sleep_handle, /*init_signaled=*/false, /*auto_clear=*/false));

    PAL_HANDLE event = (PAL_HANDLE)arg;
    set(&g_ready, 1);
    wait_for(&g_ready, 2);

    uint64_t timeout = TIME_US_IN_S;
    int ret = PalEventWait(sleep_handle, &timeout);
    if (ret != PAL_ERROR_TRYAGAIN || timeout != 0) {
        pal_printf("Error: unexpected short sleep, remaining time: %lu\n", timeout);
        PalProcessExit(1);
    }

    PalEventSet(event);

    PalThreadExit(&g_clear_thread_exit);
}

int main(void) {
    PAL_HANDLE event = NULL;
    CHECK(PalEventCreate(&event, /*init_signaled=*/true, /*auto_clear=*/true));

    /* Event is already set, should not sleep. */
    CHECK(PalEventWait(event, /*timeout=*/NULL));

    uint64_t start = 0;
    CHECK(PalSystemTimeQuery(&start));
    /* Sleep for one second. */
    uint64_t timeout = TIME_US_IN_S;
    int ret = PalEventWait(event, &timeout);
    if (ret != PAL_ERROR_TRYAGAIN) {
        CHECK(-1);
    }
    uint64_t end = 0;
    CHECK(PalSystemTimeQuery(&end));

    if (end < start) {
        CHECK(-1);
    }
    if (end - start < TIME_US_IN_S) {
        CHECK(-1);
    }
    if (end - start > TIME_US_IN_S * 3 / 2) {
        CHECK(-1);
    }

    PAL_HANDLE thread = NULL;
    CHECK(PalThreadCreate(thread_func, event, &thread));

    wait_for(&g_ready, 1);
    set(&g_ready, 2);

    CHECK(PalSystemTimeQuery(&start));
    CHECK(PalEventWait(event, /*timeout=*/NULL));
    CHECK(PalSystemTimeQuery(&end));

    if (end < start) {
        CHECK(-1);
    }
    if (end - start < TIME_US_IN_S) {
        CHECK(-1);
    }
    if (end - start > TIME_US_IN_S * 3 / 2) {
        CHECK(-1);
    }

    wait_for(&g_clear_thread_exit, 0);

    pal_printf("TEST OK\n");
    return 0;
}
