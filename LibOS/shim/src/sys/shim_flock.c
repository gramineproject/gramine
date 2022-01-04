
#include <linux/fcntl.h>

#include "shim_table.h"

/*  Emulate flock() with shim_do_fcntl().
*/

long shim_do_flock(int fd, int operation) {
    long ret;
    struct flock flock;

    switch (operation & ~LOCK_NB) {
    case LOCK_SH:
        flock.l_type = F_RDLCK;
        break;
    case LOCK_EX:
        flock.l_type = F_WRLCK;
        break;
    case LOCK_UN:
        flock.l_type = F_UNLCK;
        break;
    default:
        return -EINVAL;
    }
    flock.l_whence = SEEK_SET;
    flock.l_start = flock.l_len = (off_t)0;

    ret = shim_do_fcntl(fd, (operation & LOCK_NB) ? F_SETLK : F_SETLKW, (unsigned long)&flock);
    if ((ret == -EAGAIN) || (ret == -EACCES))
        ret = -EWOULDBLOCK;
    return ret;
}
