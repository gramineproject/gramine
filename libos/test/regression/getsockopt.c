#define _GNU_SOURCE
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <sys/socket.h>

#include "common.h"

#define DEFAULT_TCP_KEEPIDLE (120 * 60)
#define DEFAULT_TCP_KEEPINTVL 75
#define DEFAULT_TCP_KEEPCNT 9
#define DEFAULT_TCP_USER_TIMEOUT 0

int main(void) {
    socklen_t optlen; /* Option length */

    int fd = CHECK(socket(AF_INET, SOCK_STREAM, 0));

    int so_type;
    optlen = sizeof(so_type);
    CHECK(getsockopt(fd, SOL_SOCKET, SO_TYPE, &so_type, &optlen));

    if (optlen != sizeof(so_type) || so_type != SOCK_STREAM) {
        errx(1, "getsockopt(SOL_SOCKET, SO_TYPE) returned unexpected value");
    }

    int so_flags = 1;
    optlen = sizeof(so_flags);
    CHECK(getsockopt(fd, SOL_TCP, TCP_NODELAY, &so_flags, &optlen));

    if (optlen != sizeof(so_flags) || (so_flags != 0 && so_flags != 1)) {
        errx(1, "getsockopt(SOL_TCP, TCP_NODELAY) returned unexpected value");
    }

    int tcp_keepidle;
    optlen = sizeof(tcp_keepidle);
    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &tcp_keepidle, &optlen));

    if (optlen != sizeof(tcp_keepidle) || tcp_keepidle != DEFAULT_TCP_KEEPIDLE) {
        errx(1, "getsockopt(IPPROTO_TCP, TCP_KEEPIDLE) returned unexpected value");
    }

    int tcp_keepintvl;
    optlen = sizeof(tcp_keepintvl);
    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &tcp_keepintvl, &optlen));

    if (optlen != sizeof(tcp_keepintvl) || tcp_keepintvl != DEFAULT_TCP_KEEPINTVL) {
        errx(1, "getsockopt(IPPROTO_TCP, TCP_KEEPINTVL) returned unexpected value");
    }

    int tcp_keepcnt;
    optlen = sizeof(tcp_keepcnt);
    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &tcp_keepcnt, &optlen));

    if (optlen != sizeof(tcp_keepcnt) || tcp_keepcnt != DEFAULT_TCP_KEEPCNT) {
        errx(1, "getsockopt(IPPROTO_TCP, TCP_KEEPCNT) returned unexpected value");
    }

    int tcp_user_timeout;
    optlen = sizeof(tcp_user_timeout);
    CHECK(getsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &tcp_user_timeout, &optlen));

    if (optlen != sizeof(tcp_user_timeout) || tcp_user_timeout != DEFAULT_TCP_USER_TIMEOUT) {
        errx(1, "getsockopt(IPPROTO_TCP, TCP_USER_TIMEOUT) returned unexpected value");
    }

    puts("TEST OK");
    return 0;
}
