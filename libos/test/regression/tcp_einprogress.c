/*
 * Test for non-blocking connect() that returns EINPROGRESS. Modes:
 *   - responsive:   peer refuses the connection (nothing listens on the port);
 *   - unresponsive: peer drops SYNs, emulated by a local listener with a full accept queue (Linux
 *                   drops SYNs to such a listener), so polling must time out;
 *   - slow:         as unresponsive, then the accept queue is drained, so the connection is
 *                   established on SYN retransmission.
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
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
    fprintf(stderr, "usage: %s responsive|unresponsive|slow poll|epoll\n", prog_name);
}

/* Returns a listener on 127.0.0.1 (address in `out_addr`) whose accept queue is full. */
static int create_full_listener(struct sockaddr_in* out_addr) {
    int l = CHECK(socket(AF_INET, SOCK_STREAM, 0));
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    CHECK(bind(l, (void*)&sa, sizeof(sa)));
    CHECK(listen(l, /*backlog=*/0)); /* Linux queues up to backlog + 1 connections */

    socklen_t addrlen = sizeof(*out_addr);
    CHECK(getsockname(l, (void*)out_addr, &addrlen));

    /* fill the queue; the filler socket is leaked on purpose */
    int filler = CHECK(socket(AF_INET, SOCK_STREAM, 0));
    CHECK(connect(filler, (void*)out_addr, sizeof(*out_addr)));
    return l;
}

/* Waits for POLLOUT (poll) or EPOLLIN (epoll) on `s`; returns reported events or 0 on timeout. */
static uint32_t wait_events(int s, bool use_epoll, int timeout_ms) {
    if (!use_epoll) {
        struct pollfd pfd = { .fd = s, .events = POLLOUT };
        return CHECK(poll(&pfd, 1, timeout_ms)) ? (uint16_t)pfd.revents : 0;
    }

    int epfd = CHECK(epoll_create(/*size=*/1));
    struct epoll_event event = { .events = EPOLLIN };
    CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, s, &event));
    int ret = CHECK(epoll_wait(epfd, &event, /*maxevents=*/1, timeout_ms));
    CHECK(close(epfd));
    return ret ? event.events : 0;
}

static void check_so_error(int s, int expected) {
    int so_error;
    socklen_t optlen = sizeof(so_error);
    CHECK(getsockopt(s, SOL_SOCKET, SO_ERROR, &so_error, &optlen));
    if (optlen != sizeof(so_error) || so_error != expected)
        ERR("expected SO_ERROR to be %d but it is %d (%s)", expected, so_error, strerror(so_error));
}

int main(int argc, const char** argv) {
    int ret;

    if (argc != 3 || (strcmp(argv[2], "poll") && strcmp(argv[2], "epoll"))) {
        usage(argv[0]);
        return 1;
    }
    bool responsive = !strcmp(argv[1], "responsive");
    bool slow = !strcmp(argv[1], "slow");
    if (!responsive && !slow && strcmp(argv[1], "unresponsive")) {
        usage(argv[0]);
        return 1;
    }
    bool use_epoll = !strcmp(argv[2], "epoll");
    uint32_t wanted_event = use_epoll ? EPOLLIN : POLLOUT;

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    int listener = responsive ? -1 : create_full_listener(&sa);

    int s = CHECK(socket(AF_INET, SOCK_STREAM, 0));

    int flags = CHECK(fcntl(s, F_GETFL, 0));
    CHECK(fcntl(s, F_SETFL, flags | O_NONBLOCK));

    ret = connect(s, (void*)&sa, sizeof(sa));
    if (ret != -1)
        ERR("connect unexpectedly succeeded");
    if (responsive && errno == ECONNREFUSED) {
        /* boring case without EINPROGRESS (aka blocking connect) */
        puts("TEST OK (no EINPROGRESS)");
        CHECK(close(s));
        return 0;
    }
    if (errno != EINPROGRESS)
        ERR("connect didn't fail with EINPROGRESS but with %s", strerror(errno));

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
    if (responsive && errno == ECONNREFUSED) {
        /* another boring case with EINPROGRESS but a quick response */
        puts("TEST OK (quick response)");
        CHECK(close(s));
        return 0;
    }
    if (errno != EALREADY) {
        ERR("[after EINPROGRESS] second connect didn't fail with EALREADY but with %s",
            strerror(errno));
    }

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

    uint32_t events = wait_events(s, use_epoll, TIMEOUT_MS);

    if (responsive) {
        if (!(events & wanted_event))
            ERR("[after EINPROGRESS] expected event %#x but got %#x", wanted_event, events);
        check_so_error(s, ECONNREFUSED);
        puts("TEST OK (connection refused after initial EINPROGRESS)");
        CHECK(close(s));
        return 0;
    }

    if (events)
        ERR("[after EINPROGRESS] expected timeout but got events %#x", events);
    if (!slow) {
        puts("TEST OK (connection timed out)");
        CHECK(close(s));
        return 0;
    }

    /* drain the queue; the peer then accepts our retransmitted SYN and sends data to us */
    CHECK(close(CHECK(accept(listener, NULL, NULL))));
    int peer = CHECK(accept(listener, NULL, NULL));
    if (CHECK(send(peer, "hi", sizeof("hi"), /*flags=*/0)) != sizeof("hi"))
        ERR("[slow peer] short send");

    events = wait_events(s, use_epoll, TIMEOUT_MS);
    if (!(events & wanted_event))
        ERR("[slow peer] expected event %#x but got %#x", wanted_event, events);
    check_so_error(s, 0);

    addrlen_peer = sizeof(sa_peer);
    CHECK(getpeername(s, (struct sockaddr*)&sa_peer, &addrlen_peer));
    if (sa_peer.sin_port != sa.sin_port)
        ERR("[slow peer] getpeername returned wrong port %hu", ntohs(sa_peer.sin_port));

    char buf[sizeof("hi")];
    if (CHECK(recv(s, buf, sizeof(buf), /*flags=*/0)) != sizeof(buf) || strcmp(buf, "hi"))
        ERR("[slow peer] received unexpected data");

    puts("TEST OK (connection established after initial EINPROGRESS)");
    CHECK(close(peer));
    CHECK(close(s));
    return 0;
}
