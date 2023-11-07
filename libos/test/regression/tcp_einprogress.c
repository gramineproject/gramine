#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"

#define ERR(msg, args...) \
    errx(1, "%d: " msg, __LINE__, ##args)

#define TIMEOUT_MS 1000  /* 1s; increase to e.g. 10s for manual tests */
#define PORT       12345 /* nothing must be bound to this port! */

static void usage(const char* prog_name) {
    fprintf(stderr, "usage: %s <IP address> poll|epoll\n", prog_name);
    fprintf(stderr, "(use 127.0.0.1 for responsive peer and 10.255.255.255 for unresponsive "
                    "peer)\n");
}

int main(int argc, const char** argv) {
    int ret;

    if (argc != 3) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[2], "poll") && strcmp(argv[2], "epoll")) {
        usage(argv[0]);
        fprintf(stderr, "error: second argument not recognized (only 'poll'/'epoll' allowed)\n");
        return 1;
    }

    int s = CHECK(socket(AF_INET, SOCK_STREAM, 0));

    int flags = CHECK(fcntl(s, F_GETFL, 0));
    CHECK(fcntl(s, F_SETFL, flags | O_NONBLOCK));

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
    };
    if (inet_aton(argv[1], &sa.sin_addr) != 1)
        ERR("inet_aton failed");

    ret = connect(s, (void*)&sa, sizeof(sa));
    if (ret != -1)
        ERR("connect unexpectedly succeeded");
    if (errno != EINPROGRESS && errno != ECONNREFUSED)
        ERR("connect didn't fail with EINPROGRESS or ECONNREFUSED but with %s", strerror(errno));

    if (errno == ECONNREFUSED) {
        /* boring case without EINPROGRESS (aka blocking connect) */
        puts("TEST OK (no EINPROGRESS)");
        CHECK(close(s));
        return 0;
    }
    assert(errno == EINPROGRESS);

    struct sockaddr_in sa_local;
    socklen_t addrlen_local = sizeof(sa_local);
    ret = getsockname(s, (struct sockaddr*)&sa_local, &addrlen_local);
    if (ret < 0)
        ERR("[after EINPROGRESS] getsockname failed with %s", strerror(errno));
    printf("local address %s:%hu\n", inet_ntoa(sa_local.sin_addr), ntohs(sa_local.sin_port));
    fflush(stdout);

    ret = connect(s, (void*)&sa, sizeof(sa));
    if (ret != -1) {
        ERR("[after EINPROGRESS] second connect unexpectedly succeeded");
    }
    if (errno != EALREADY && errno != ECONNREFUSED) {
        ERR("[after EINPROGRESS] second connect didn't fail with EALREADY or ECONNREFUSED but with"
            " %s", strerror(errno));
    }

    if (errno == ECONNREFUSED) {
        /* another boring case with EINPROGRESS but a quick response */
        puts("TEST OK (quick response)");
        CHECK(close(s));
        return 0;
    }
    assert(errno == EALREADY);

    struct sockaddr_in sa_peer;
    socklen_t addrlen_peer = sizeof(sa_peer);
    ret = getpeername(s, (struct sockaddr*)&sa_peer, &addrlen_peer);
    if (ret != -1) {
        ERR("[after EINPROGRESS] expected getpeername to fail but it succeeded");
    }
    if (errno != ENOTCONN) {
        ERR("[after EINPROGRESS] expected getpeername to fail with ENOTCONN but failed with %s",
            strerror(errno));
    }

    char dummy_buf[3] = "hi";
    ssize_t bytes = send(s, dummy_buf, sizeof(dummy_buf), /*flags=*/0);
    if (bytes != -1) {
        ERR("[after EINPROGRESS] expected send to fail but it succeeded");
    }
    if (errno != EAGAIN) {
        ERR("[after EINPROGRESS] expected send to fail with EAGAIN but failed with %s",
            strerror(errno));
    }

    bytes = recv(s, dummy_buf, sizeof(dummy_buf), /*flags=*/0);
    if (bytes != -1) {
        ERR("[after EINPROGRESS] expected recv to fail but it succeeded");
    }
    if (errno != EAGAIN) {
        ERR("[after EINPROGRESS] expected recv to fail with EAGAIN but failed with %s",
            strerror(errno));
    }

    /* test can be run with "poll" or "epoll" cmdline arg: we test POLLOUT for the poll case and
     * EPOLLIN for the epoll case (no reason other than to test both write and read events) */
    bool timedout = false;
    bool poll_event_happened = false;
    if (strcmp(argv[2], "poll") == 0) {
        struct pollfd infds[] = {
            {.fd = s, .events = POLLOUT},
        };
        ret = CHECK(poll(infds, 1, TIMEOUT_MS));
        if (ret == 0)
            timedout = true;
        else
            poll_event_happened = !!(infds[0].revents & POLLOUT);

    } else {
        int epfd = CHECK(epoll_create(/*size=*/1));
        struct epoll_event event = { .events = EPOLLIN };
        CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, s, &event));
        struct epoll_event out_event = { 0 };
        ret = CHECK(epoll_wait(epfd, &out_event, /*max_events=*/1, TIMEOUT_MS));
        CHECK(close(epfd));
        if (ret == 0)
            timedout = true;
        else
            poll_event_happened = !!(out_event.events & EPOLLIN);
    }

    /* one interesting case -- remote peer is completely unresponsive */
    if (timedout) {
        puts("TEST OK (connection timed out)");
        CHECK(close(s));
        return 0;
    }

    /* the most interesting case -- remote peer not unresponsive but very slow */
    if (!poll_event_happened) {
        ERR("[after EINPROGRESS] polling didn't return %s on connecting socket",
            strcmp(argv[2], "poll") == 0 ? "POLLOUT" : "EPOLLIN");
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
