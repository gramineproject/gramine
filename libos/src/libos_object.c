#include "libos_internal.h"
#include "pal.h"

int event_wait_with_retry(PAL_HANDLE handle) {
    int ret;
    do {
        ret = PalEventWait(handle, /*timeout=*/NULL);
    } while (ret == -PAL_ERROR_INTERRUPTED || ret == -PAL_ERROR_TRYAGAIN);

    if (ret < 0) {
        ret = pal_to_unix_errno(ret);
        log_error("waiting on an event with retry failed (%d)", ret);
        return ret;
    }
    return 0;
}
