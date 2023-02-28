#include "libos_fs.h"
#include "libos_fs_lock.h"
#include "libos_handle.h"
#include "libos_process.h"
#include "libos_table.h"
#include "libos_thread.h"

long libos_syscall_flock(int fd, int operation) {

    int ret;
    int flags = 0;

    /* Get the handle map associated with the current thread */
    struct libos_handle_map* handle_map = get_thread_handle_map(NULL);
    assert(handle_map);

    /* Get the file handle associated with the given file descriptor */
    struct libos_handle* hdl = get_fd_handle(fd, &flags, handle_map);
    if (!hdl)
        return -EBADF;

    /* Initialize a posix_lock struct to represent the requested lock */
    struct posix_lock pl = {
        .start = 0,
        .end = FS_LOCK_EOF,
        .pid = g_process.pid,
        .handle_id = ((uint64_t)g_process.pid << 32) | ((uint64_t)dentry_ino(hdl->dentry))
    };

    /* Set the type of the lock based on the requested operation */
    switch (operation) {

        /* Shared read lock */
        case LOCK_SH:
        case LOCK_NB:
            pl.type = F_RDLCK;
            ret = posix_lock_set(hdl->dentry, &pl, /*block=*/false);
            break;

        /* Exclusive write lock */
        case LOCK_EX:
            pl.type = F_WRLCK;
            ret = posix_lock_set(hdl->dentry, &pl, /*block=*/true);
            break;

        /* Unlock */
        case LOCK_UN:
            pl.type = F_UNLCK;
            ret = posix_lock_set(hdl->dentry, &pl, /*block=*/true);
            break;

        /* Invalid operation */
        default:
            return -EINVAL;
    }

    /* Return the result of the lock operation */
    return ret;
}
