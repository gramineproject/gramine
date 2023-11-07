#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"

#define ERR(msg, args...) \
    errx(1, "%d: " msg, __LINE__, ##args)

#define SRV_IP "127.0.0.1"
#define PORT   12345       /* nothing must be bound to this port! */

int main(void) {
    int ret;

    int s = CHECK(socket(AF_INET, SOCK_STREAM, 0));

    int flags = CHECK(fcntl(s, F_GETFL, 0));
    CHECK(fcntl(s, F_SETFL, flags | O_NONBLOCK));

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
    };
    if (inet_aton(SRV_IP, &sa.sin_addr) != 1)
        ERR("inet_aton failed");

    ret = connect(s, (void*)&sa, sizeof(sa));
    if (!ret)
        ERR("connect unexpectedly succeeded (expected EINPROGRESS or ECONNREFUSED)");

    if (ret < 0 && errno != EINPROGRESS) {
        if (errno != ECONNREFUSED)
            ERR("expected connect to fail with ECONNREFUSED but failed with %s", strerror(errno));

        /* boring case without EINPROGRESS (aka blocking connect) */
        puts("TEST OK (no EINPROGRESS)");
        CHECK(close(s));
        return 0;
    }

    struct sockaddr_in sa_local;
    socklen_t addrlen_local = sizeof(sa_local);
    ret = getsockname(s, (struct sockaddr*)&sa_local, &addrlen_local);
    if (ret < 0)
        ERR("[after EINPROGRESS] getsockname failed with %s", strerror(errno));
    printf("local address %s:%hu\n", inet_ntoa(sa_local.sin_addr), ntohs(sa_local.sin_port));
    fflush(stdout);

    ret = connect(s, (void*)&sa, sizeof(sa));
    if (ret != -1 || errno != EALREADY) {
        if (errno == ECONNREFUSED) {
            /* boring case with EINPROGRESS but a quick response */
            puts("TEST OK (quick response)");
            CHECK(close(s));
            return 0;
        }
        ERR("[after EINPROGRESS] expected second connect to fail with EALREADY but failed with %s",
            strerror(errno));
    }

    struct sockaddr_in sa_peer;
    socklen_t addrlen_peer = sizeof(sa_peer);
    ret = getpeername(s, (struct sockaddr*)&sa_peer, &addrlen_peer);
    if (ret != -1 || errno != ENOTCONN)
        ERR("[after EINPROGRESS] expected getpeername to fail with ENOTCONN but failed with %s",
            strerror(errno));

    struct pollfd infds[] = {
        {.fd = s, .events = POLLOUT},
    };
    ret = CHECK(poll(infds, 1, /*timout_ms=*/10000));
    if (ret == 0) {
        /* one interesting case -- remote peer is completely unresponsive */
        puts("TEST OK (connection timed out)");
        CHECK(close(s));
        return 0;
    }

    /* the most interesting case -- remote peer not unresponsive but very slow */
    if (!(infds[0].revents & POLLOUT)) {
        ERR("polling didn't return POLLOUT on connecting socket");
    }

    int so_error;
    socklen_t optlen = sizeof(so_error);
    CHECK(getsockopt(s, SOL_SOCKET, SO_ERROR, &so_error, &optlen));
    if (optlen != sizeof(so_error) || so_error != ECONNREFUSED) {
        ERR("[after EINPROGRESS] expected SO_ERROR to be ECONNREFUSED but it is %s",
            strerror(so_error));
    }

    puts("TEST OK (connection refused after initial EINPROGRESS)");
    CHECK(close(s));
    return 0;
}
