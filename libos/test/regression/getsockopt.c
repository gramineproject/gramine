/* Unit test for issues #92 and #644 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#define DEFAULT_TCP_KEEPIDLE (120 * 60)
#define DEFAULT_TCP_KEEPINTVL 75
#define DEFAULT_TCP_KEEPCNT 9

int main(int argc, char** argv) {
    int ret;
    socklen_t optlen; /* Option length */

    int fd = socket(PF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket failed");
        return 1;
    }

    int so_type;
    optlen = sizeof(so_type);
    ret = getsockopt(fd, SOL_SOCKET, SO_TYPE, &so_type, &optlen);
    if (ret < 0) {
        perror("getsockopt(SOL_SOCKET, SO_TYPE) failed");
        return 1;
    }

    if (optlen != sizeof(so_type) || so_type != SOCK_STREAM) {
        fprintf(stderr, "getsockopt(SOL_SOCKET, SO_TYPE) failed\n");
        return 1;
    }

    printf("getsockopt: Got socket type OK\n");

    int so_flags = 1;
    optlen = sizeof(so_flags);
    ret = getsockopt(fd, SOL_TCP, TCP_NODELAY, (void*)&so_flags, &optlen);
    if (ret < 0) {
        perror("getsockopt(SOL_TCP, TCP_NODELAY) failed");
        return 1;
    }

    if (optlen != sizeof(so_flags) || (so_flags != 0 && so_flags != 1)) {
        fprintf(stderr, "getsockopt(SOL_TCP, TCP_NODELAY) failed\n");
        return 1;
    }

    printf("getsockopt: Got TCP_NODELAY flag OK\n");

    int tcp_keepidle;
    optlen = sizeof(tcp_keepidle);
    ret = getsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, (void*)&tcp_keepidle, &optlen);
    if (ret < 0) {
        perror("getsockopt(IPPROTO_TCP, TCP_KEEPIDLE) failed");
        return 1;
    }

    if (optlen != sizeof(tcp_keepidle) || (tcp_keepidle != DEFAULT_TCP_KEEPIDLE)) {
        fprintf(stderr, "getsockopt(IPPROTO_TCP, TCP_KEEPIDLE) failed\n");
        return 1;
    }

    printf("getsockopt: Got TCP_KEEPIDLE socket option OK\n");

    int tcp_keepintvl;
    optlen = sizeof(tcp_keepintvl);
    ret = getsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, (void*)&tcp_keepintvl, &optlen);
    if (ret < 0) {
        perror("getsockopt(IPPROTO_TCP, TCP_KEEPINTVL) failed");
        return 1;
    }

    if (optlen != sizeof(tcp_keepintvl) || (tcp_keepintvl != DEFAULT_TCP_KEEPINTVL)) {
        fprintf(stderr, "getsockopt(IPPROTO_TCP, TCP_KEEPINTVL) failed\n");
        return 1;
    }

    printf("getsockopt: Got TCP_KEEPINTVL socket option OK\n");

    int tcp_keepcnt;
    optlen = sizeof(tcp_keepcnt);
    ret = getsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, (void*)&tcp_keepcnt, &optlen);
    if (ret < 0) {
        perror("getsockopt(IPPROTO_TCP, TCP_KEEPCNT) failed");
        return 1;
    }

    if (optlen != sizeof(tcp_keepcnt) || (tcp_keepcnt != DEFAULT_TCP_KEEPCNT)) {
        fprintf(stderr, "getsockopt(IPPROTO_TCP, TCP_KEEPCNT) failed\n");
        return 1;
    }

    printf("getsockopt: Got TCP_KEEPCNT socket option OK\n");

    return 0;
}
