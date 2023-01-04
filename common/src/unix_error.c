/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2022 Intel Corporation
 *                    Mariusz Zaborski <oshogbo@invisiblethingslab.com>
 */

#include "api.h"
#include "unix_error.h"

#include <errno.h>

static const char* g_unix_error_list[] = {
    [0] = "Success",
    /* Let's assume that this one must always be defined to detect errors with includes. */
    [EPERM] = "Operation not permitted (EPERM)",
#ifdef ENOENT
    [ENOENT] = "No such file or directory (ENOENT)",
#endif
#ifdef ESRCH
    [ESRCH] = "No such process (ESRCH)",
#endif
#ifdef EINTR
    [EINTR] = "Interrupted system call (EINTR)",
#endif
#ifdef EIO
    [EIO] = "Input/output error (EIO)",
#endif
#ifdef ENXIO
    [ENXIO] = "No such device or address (ENXIO)",
#endif
#ifdef E2BIG
    [E2BIG] = "Argument list too long (E2BIG)",
#endif
#ifdef ENOEXEC
    [ENOEXEC] = "Exec format error (ENOEXEC)",
#endif
#ifdef EBADF
    [EBADF] = "Bad file descriptor (EBADF)",
#endif
#ifdef ECHILD
    [ECHILD] = "No child processes (ECHILD)",
#endif
#ifdef EDEADLK
    [EDEADLK] = "Resource deadlock avoided (EDEADLK)",
#endif
#ifdef ENOMEM
    [ENOMEM] = "Cannot allocate memory (ENOMEM)",
#endif
#ifdef EACCES
    [EACCES] = "Permission denied (EACCES)",
#endif
#ifdef EFAULT
    [EFAULT] = "Bad address (EFAULT)",
#endif
#ifdef ENOTBLK
    [ENOTBLK] = "Block device required (ENOTBLK)",
#endif
#ifdef EBUSY
    [EBUSY] = "Device or resource busy (EBUSY)",
#endif
#ifdef EEXIST
    [EEXIST] = "File exists (EEXIST)",
#endif
#ifdef EXDEV
    [EXDEV] = "Invalid cross-device link (EXDEV)",
#endif
#ifdef ENODEV
    [ENODEV] = "No such device (ENODEV)",
#endif
#ifdef ENOTDIR
    [ENOTDIR] = "Not a directory (ENOTDIR)",
#endif
#ifdef EISDIR
    [EISDIR] = "Is a directory (EISDIR)",
#endif
#ifdef EINVAL
    [EINVAL] = "Invalid argument (EINVAL)",
#endif
#ifdef EMFILE
    [EMFILE] = "Too many open files (EMFILE)",
#endif
#ifdef ENFILE
    [ENFILE] = "Too many open files in system (ENFILE)",
#endif
#ifdef ENOTTY
    [ENOTTY] = "Inappropriate ioctl for device (ENOTTY)",
#endif
#ifdef ETXTBSY
    [ETXTBSY] = "Text file busy (ETXTBSY)",
#endif
#ifdef EFBIG
    [EFBIG] = "File too large (EFBIG)",
#endif
#ifdef ENOSPC
    [ENOSPC] = "No space left on device (ENOSPC)",
#endif
#ifdef ESPIPE
    [ESPIPE] = "Illegal seek (ESPIPE)",
#endif
#ifdef EROFS
    [EROFS] = "Read-only file system (EROFS)",
#endif
#ifdef EMLINK
    [EMLINK] = "Too many links (EMLINK)",
#endif
#ifdef EPIPE
    [EPIPE] = "Broken pipe (EPIPE)",
#endif
#ifdef EDOM
    [EDOM] = "Numerical argument out of domain (EDOM)",
#endif
#ifdef ERANGE
    [ERANGE] = "Numerical result out of range (ERANGE)",
#endif
#ifdef EAGAIN
    [EAGAIN] = "Resource temporarily unavailable (EAGAIN)",
#endif
#ifdef EINPROGRESS
    [EINPROGRESS] = "Operation now in progress (EINPROGRESS)",
#endif
#ifdef EALREADY
    [EALREADY] = "Operation already in progress (EALREADY)",
#endif
#ifdef ENOTSOCK
    [ENOTSOCK] = "Socket operation on non-socket (ENOTSOCK)",
#endif
#ifdef EMSGSIZE
    [EMSGSIZE] = "Message too long (EMSGSIZE)",
#endif
#ifdef EPROTOTYPE
    [EPROTOTYPE] = "Protocol wrong type for socket (EPROTOTYPE)",
#endif
#ifdef ENOPROTOOPT
    [ENOPROTOOPT] = "Protocol not available (ENOPROTOOPT)",
#endif
#ifdef EPROTONOSUPPORT
    [EPROTONOSUPPORT] = "Protocol not supported (EPROTONOSUPPORT)",
#endif
#ifdef ESOCKTNOSUPPORT
    [ESOCKTNOSUPPORT] = "Socket type not supported (ESOCKTNOSUPPORT)",
#endif
#ifdef EOPNOTSUPP
    [EOPNOTSUPP] = "Operation not supported (EOPNOTSUPP)",
#endif
#ifdef EPFNOSUPPORT
    [EPFNOSUPPORT] = "Protocol family not supported (EPFNOSUPPORT)",
#endif
#ifdef EAFNOSUPPORT
    [EAFNOSUPPORT] = "Address family not supported by protocol (EAFNOSUPPORT)",
#endif
#ifdef EADDRINUSE
    [EADDRINUSE] = "Address already in use (EADDRINUSE)",
#endif
#ifdef EADDRNOTAVAIL
    [EADDRNOTAVAIL] = "Cannot assign requested address (EADDRNOTAVAIL)",
#endif
#ifdef ENETDOWN
    [ENETDOWN] = "Network is down (ENETDOWN)",
#endif
#ifdef ENETUNREACH
    [ENETUNREACH] = "Network is unreachable (ENETUNREACH)",
#endif
#ifdef ENETRESET
    [ENETRESET] = "Network dropped connection on reset (ENETRESET)",
#endif
#ifdef ECONNABORTED
    [ECONNABORTED] = "Software caused connection abort (ECONNABORTED)",
#endif
#ifdef ECONNRESET
    [ECONNRESET] = "Connection reset by peer (ECONNRESET)",
#endif
#ifdef ENOBUFS
    [ENOBUFS] = "No buffer space available (ENOBUFS)",
#endif
#ifdef EISCONN
    [EISCONN] = "Transport endpoint is already connected (EISCONN)",
#endif
#ifdef ENOTCONN
    [ENOTCONN] = "Transport endpoint is not connected (ENOTCONN)",
#endif
#ifdef EDESTADDRREQ
    [EDESTADDRREQ] = "Destination address required (EDESTADDRREQ)",
#endif
#ifdef ESHUTDOWN
    [ESHUTDOWN] = "Cannot send after transport endpoint shutdown (ESHUTDOWN)",
#endif
#ifdef ETOOMANYREFS
    [ETOOMANYREFS] = "Too many references: cannot splice (ETOOMANYREFS)",
#endif
#ifdef ETIMEDOUT
    [ETIMEDOUT] = "Connection timed out (ETIMEDOUT)",
#endif
#ifdef ECONNREFUSED
    [ECONNREFUSED] = "Connection refused (ECONNREFUSED)",
#endif
#ifdef ELOOP
    [ELOOP] = "Too many levels of symbolic links (ELOOP)",
#endif
#ifdef ENAMETOOLONG
    [ENAMETOOLONG] = "File name too long (ENAMETOOLONG)",
#endif
#ifdef EHOSTDOWN
    [EHOSTDOWN] = "Host is down (EHOSTDOWN)",
#endif
#ifdef EHOSTUNREACH
    [EHOSTUNREACH] = "No route to host (EHOSTUNREACH)",
#endif
#ifdef ENOTEMPTY
    [ENOTEMPTY] = "Directory not empty (ENOTEMPTY)",
#endif
#ifdef EUSERS
    [EUSERS] = "Too many users (EUSERS)",
#endif
#ifdef EDQUOT
    [EDQUOT] = "Disk quota exceeded (EDQUOT)",
#endif
#ifdef ESTALE
    [ESTALE] = "Stale file handle (ESTALE)",
#endif
#ifdef EREMOTE
    [EREMOTE] = "Object is remote (EREMOTE)",
#endif
#ifdef ENOLCK
    [ENOLCK] = "No locks available (ENOLCK)",
#endif
#ifdef ENOSYS
    [ENOSYS] = "Function not implemented (ENOSYS)",
#endif
#ifdef EILSEQ
    [EILSEQ] = "Invalid or incomplete multibyte or wide character (EILSEQ)",
#endif
#ifdef EBADMSG
    [EBADMSG] = "Bad message (EBADMSG)",
#endif
#ifdef EIDRM
    [EIDRM] = "Identifier removed (EIDRM)",
#endif
#ifdef EMULTIHOP
    [EMULTIHOP] = "Multihop attempted (EMULTIHOP)",
#endif
#ifdef ENODATA
    [ENODATA] = "No data available (ENODATA)",
#endif
#ifdef ENOLINK
    [ENOLINK] = "Link has been severed (ENOLINK)",
#endif
#ifdef ENOMSG
    [ENOMSG] = "No message of desired type (ENOMSG)",
#endif
#ifdef ENOSR
    [ENOSR] = "Out of streams resources (ENOSR)",
#endif
#ifdef ENOSTR
    [ENOSTR] = "Device not a stream (ENOSTR)",
#endif
#ifdef EOVERFLOW
    [EOVERFLOW] = "Value too large for defined data type (EOVERFLOW)",
#endif
#ifdef EPROTO
    [EPROTO] = "Protocol error (EPROTO)",
#endif
#ifdef ETIME
    [ETIME] = "Timer expired (ETIME)",
#endif
#ifdef ECANCELED
    [ECANCELED] = "Operation canceled (ECANCELED)",
#endif
#ifdef EOWNERDEAD
    [EOWNERDEAD] = "Owner died (EOWNERDEAD)",
#endif
#ifdef ENOTRECOVERABLE
    [ENOTRECOVERABLE] = "State not recoverable (ENOTRECOVERABLE)",
#endif
#ifdef ERESTART
    [ERESTART] = "Interrupted system call should be restarted (ERESTART)",
#endif
#ifdef ECHRNG
    [ECHRNG] = "Channel number out of range (ECHRNG)",
#endif
#ifdef EL2NSYNC
    [EL2NSYNC] = "Level 2 not synchronized (EL2NSYNC)",
#endif
#ifdef EL3HLT
    [EL3HLT] = "Level 3 halted (EL3HLT)",
#endif
#ifdef EL3RST
    [EL3RST] = "Level 3 reset (EL3RST)",
#endif
#ifdef ELNRNG
    [ELNRNG] = "Link number out of range (ELNRNG)",
#endif
#ifdef EUNATCH
    [EUNATCH] = "Protocol driver not attached (EUNATCH)",
#endif
#ifdef ENOCSI
    [ENOCSI] = "No CSI structure available (ENOCSI)",
#endif
#ifdef EL2HLT
    [EL2HLT] = "Level 2 halted (EL2HLT)",
#endif
#ifdef EBADE
    [EBADE] = "Invalid exchange (EBADE)",
#endif
#ifdef EBADR
    [EBADR] = "Invalid request descriptor (EBADR)",
#endif
#ifdef EXFULL
    [EXFULL] = "Exchange full (EXFULL)",
#endif
#ifdef ENOANO
    [ENOANO] = "No anode (ENOANO)",
#endif
#ifdef EBADRQC
    [EBADRQC] = "Invalid request code (EBADRQC)",
#endif
#ifdef EBADSLT
    [EBADSLT] = "Invalid slot (EBADSLT)",
#endif
#ifdef EBFONT
    [EBFONT] = "Bad font file format (EBFONT)",
#endif
#ifdef ENONET
    [ENONET] = "Machine is not on the network (ENONET)",
#endif
#ifdef ENOPKG
    [ENOPKG] = "Package not installed (ENOPKG)",
#endif
#ifdef EADV
    [EADV] = "Advertise error (EADV)",
#endif
#ifdef ESRMNT
    [ESRMNT] = "Srmount error (ESRMNT)",
#endif
#ifdef ECOMM
    [ECOMM] = "Communication error on send (ECOMM)",
#endif
#ifdef EDOTDOT
    [EDOTDOT] = "RFS specific error (EDOTDOT)",
#endif
#ifdef ENOTUNIQ
    [ENOTUNIQ] = "Name not unique on network (ENOTUNIQ)",
#endif
#ifdef EBADFD
    [EBADFD] = "File descriptor in bad state (EBADFD)",
#endif
#ifdef EREMCHG
    [EREMCHG] = "Remote address changed (EREMCHG)",
#endif
#ifdef ELIBACC
    [ELIBACC] = "Can not access a needed shared library (ELIBACC)",
#endif
#ifdef ELIBBAD
    [ELIBBAD] = "Accessing a corrupted shared library (ELIBBAD)",
#endif
#ifdef ELIBSCN
    [ELIBSCN] = ".lib section in a.out corrupted (ELIBSCN)",
#endif
#ifdef ELIBMAX
    [ELIBMAX] = "Attempting to link in too many shared libraries (ELIBMAX)",
#endif
#ifdef ELIBEXEC
    [ELIBEXEC] = "Cannot exec a shared library directly (ELIBEXEC)",
#endif
#ifdef ESTRPIPE
    [ESTRPIPE] = "Streams pipe error (ESTRPIPE)",
#endif
#ifdef EUCLEAN
    [EUCLEAN] = "Structure needs cleaning (EUCLEAN)",
#endif
#ifdef ENOTNAM
    [ENOTNAM] = "Not a XENIX named type file (ENOTNAM)",
#endif
#ifdef ENAVAIL
    [ENAVAIL] = "No XENIX semaphores available (ENAVAIL)",
#endif
#ifdef EISNAM
    [EISNAM] = "Is a named type file (EISNAM)",
#endif
#ifdef EREMOTEIO
    [EREMOTEIO] = "Remote I/O error (EREMOTEIO)",
#endif
#ifdef ENOMEDIUM
    [ENOMEDIUM] = "No medium found (ENOMEDIUM)",
#endif
#ifdef EMEDIUMTYPE
    [EMEDIUMTYPE] = "Wrong medium type (EMEDIUMTYPE)",
#endif
#ifdef ENOKEY
    [ENOKEY] = "Required key not available (ENOKEY)",
#endif
#ifdef EKEYEXPIRED
    [EKEYEXPIRED] = "Key has expired (EKEYEXPIRED)",
#endif
#ifdef EKEYREVOKED
    [EKEYREVOKED] = "Key has been revoked (EKEYREVOKED)",
#endif
#ifdef EKEYREJECTED
    [EKEYREJECTED] = "Key was rejected by service (EKEYREJECTED)",
#endif
#ifdef ERFKILL
    [ERFKILL] = "Operation not possible due to RF-kill (ERFKILL)",
#endif
#ifdef EHWPOISON
    [EHWPOISON] = "Memory page has hardware error (EHWPOISON)",
#endif
#ifdef EBADRPC
    [EBADRPC] = "RPC struct is bad (EBADRPC)",
#endif
#ifdef EFTYPE
    [EFTYPE] = "Inappropriate file type or formati (EFTYPE)",
#endif
#ifdef EPROCUNAVAIL
    [EPROCUNAVAIL] = "RPC bad procedure for program (EPROCUNAVAIL)",
#endif
#ifdef EAUTH
    [EAUTH] = "Authentication error (EAUTH)",
#endif
#ifdef EDIED
    [EDIED] = "Translator died (EDIED)",
#endif
#ifdef ERPCMISMATCH
    [ERPCMISMATCH] = "RPC version wrong (ERPCMISMATCH)",
#endif
#ifdef EGREGIOUS
    [EGREGIOUS] = "You really blew it this time (EGREGIOUS)",
#endif
#ifdef EPROCLIM
    [EPROCLIM] = "Too many processes (EPROCLIM)",
#endif
#ifdef EGRATUITOUS
    [EGRATUITOUS] = "Gratuitous error (EGRATUITOUS)",
#endif
#if defined(ENOTSUP) && ENOTSUP != EOPNOTSUPP
    [ENOTSUP] = "Not supported (ENOTSUP)",
#endif
#ifdef EPROGMISMATCH
    [EPROGMISMATCH] = "RPC program version wrong (EPROGMISMATCH)",
#endif
#ifdef EBACKGROUND
    [EBACKGROUND] = "Inappropriate operation for background process (EBACKGROUND)",
#endif
#ifdef EIEIO
    [EIEIO] = "Computer bought the farm (EIEIO)",
#endif
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    [EWOULDBLOCK] = "Operation would block (EWOULDBLOCK)",
#endif
#ifdef ENEEDAUTH
    [ENEEDAUTH] = "Need authenticator (ENEEDAUTH)",
#endif
#ifdef ED
    [ED] = "? (ED)",
#endif
#ifdef EPROGUNAVAIL
    [EPROGUNAVAIL] = "RPC program not available (EPROGUNAVAIL)",
#endif
};

const char* unix_strerror(int err) {
    unsigned err_idx = err >= 0 ? err : -err;
    if (err_idx >= ARRAY_SIZE(g_unix_error_list) || !g_unix_error_list[err_idx]) {
        log_error("Unknown UNIX error (errno = %d)", err);
        abort();
    }
    return g_unix_error_list[err_idx];
}
