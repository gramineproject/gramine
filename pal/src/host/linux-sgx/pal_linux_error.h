#pragma once

#ifdef IN_PAL

#include <asm/errno.h>

#include "assert.h"
#include "pal_error.h"

static int unix_to_pal_error_negative(int unix_errno) {
    assert(unix_errno >= 0);
    switch (unix_errno) {
        case 0:
            return PAL_ERROR_SUCCESS;
            static_assert(PAL_ERROR_SUCCESS == 0, "unexpected PAL_ERROR_SUCCESS value");
        case ENOENT:
            return PAL_ERROR_STREAMNOTEXIST;
        case EINTR:
            return PAL_ERROR_INTERRUPTED;
        case EBADF:
            return PAL_ERROR_BADHANDLE;
        case ETIMEDOUT:
        case EAGAIN:
        case EINPROGRESS:
            return PAL_ERROR_TRYAGAIN;
        case ENOMEM:
            return PAL_ERROR_NOMEM;
        case EFAULT:
            return PAL_ERROR_BADADDR;
        case EEXIST:
        case EADDRINUSE:
            return PAL_ERROR_STREAMEXIST;
        case EADDRNOTAVAIL:
            return PAL_ERROR_ADDRNOTEXIST;
        case ENOTDIR:
            return PAL_ERROR_STREAMISFILE;
        case EINVAL:
            return PAL_ERROR_INVAL;
        case EMSGSIZE:
        case ENAMETOOLONG:
            return PAL_ERROR_TOOLONG;
        case EISDIR:
            return PAL_ERROR_STREAMISDIR;
        case ECONNABORTED:
        case ECONNRESET:
        case ECONNREFUSED:
            return PAL_ERROR_CONNFAILED;
        case ENOTCONN:
            return PAL_ERROR_NOTCONNECTION;
        case EPIPE:
            return PAL_ERROR_CONNFAILED_PIPE;
        case EAFNOSUPPORT:
            return PAL_ERROR_AFNOSUPPORT;
        default:
            return PAL_ERROR_DENIED;
    }
}

/*!
 * \brief Translate UNIX error code into PAL error code.
 *
 * The sign of the error code is preserved.
 */
static __attribute__((unused)) int unix_to_pal_error(int unix_errno) {
    // TODO: The unix_errno variable should always be negative.
    if (unix_errno >= 0) {
        return -unix_to_pal_error_negative(unix_errno);
    }
    return unix_to_pal_error_negative(-unix_errno);
}

#endif /* IN_PAL */
