#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

#define ERR(msg, args...) \
    errx(1, "%d: " msg, __LINE__, ##args)

#define SRV_IP "127.0.0.1"
#define PORT   11113

static uint64_t wait_event(int epfd, struct epoll_event* possible_events,
                           size_t possible_events_len) {
    struct epoll_event event = { 0 };
    int x = CHECK(epoll_wait(epfd, &event, 1, -1));
    if (x != 1) {
        ERR("epoll_wait returned: %d", x);
    }

    for (size_t i = 0; i < possible_events_len; i++) {
        if (possible_events[i].data.u64 == event.data.u64) {
            if (possible_events[i].events != event.events) {
                ERR("wrong events returned: %#x", event.events);
            }
            return event.data.u64;
        }
    }

    ERR("unknown event: %zu %#x", event.data.u64, event.events);
}

static void test_epoll_migration(void) {
    int epfd = CHECK(epoll_create1(EPOLL_CLOEXEC));
    int pipe_fds[2];
    CHECK(pipe(pipe_fds));

    struct epoll_event events[2] = {
        { .events = EPOLLIN, .data.u64 = pipe_fds[0], },
        { .events = EPOLLOUT, .data.u64 = pipe_fds[1], },
    };
    CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_fds[0], &events[0]));

    CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_fds[1], &events[1]));

    pid_t p = CHECK(fork());
    if (p != 0) {
        int status = 0;
        pid_t w = CHECK(wait(&status));
        if (w != p) {
            ERR("wait returned wrong pid: %d (expected: %d)", w, p);
        }
        if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0)) {
            ERR("child exited with: %#x", status);
        }

        CHECK(close(pipe_fds[0]));
        CHECK(close(pipe_fds[1]));
        CHECK(close(epfd));
        return;
    }

    // child

    if (wait_event(epfd, events, ARRAY_LEN(events)) != (uint64_t)pipe_fds[1]) {
        ERR("expected different event");
    }

    char c = 0;
    ssize_t y = CHECK(write(pipe_fds[1], &c, sizeof(c)));
    if (y != sizeof(c)) {
        ERR("write: %zd", y);
    }

    uint64_t e1 = wait_event(epfd, events, ARRAY_LEN(events));
    uint64_t e2 = wait_event(epfd, events, ARRAY_LEN(events));

    if (e1 == e2) {
        ERR("epoll_wait did not round robin");
    }

    exit(0);
}

static void test_epoll_oneshot(void) {
    int epfd = CHECK(epoll_create1(EPOLL_CLOEXEC));
    int pipe_fds[2];
    CHECK(pipe(pipe_fds));

    struct epoll_event event = {
        .events = EPOLLIN | EPOLLONESHOT,
        .data.u64 = pipe_fds[0],
    };
    CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, pipe_fds[0], &event));

    memset(&event, 0, sizeof(event));
    int x = CHECK(epoll_wait(epfd, &event, 1, 1));
    if (x != 0) {
        ERR("epoll_wait returned: %d, events: %#x, data: %lu", x, event.events, event.data.u64);
    }

    char c = 0;
    ssize_t y = CHECK(write(pipe_fds[1], &c, sizeof(c)));
    if (y != sizeof(c)) {
        ERR("write: %zd", y);
    }

    memset(&event, 0, sizeof(event));
    x = CHECK(epoll_wait(epfd, &event, 1, 1));
    if (x != 1 || event.events != EPOLLIN || event.data.u64 != (uint64_t)pipe_fds[0]) {
        ERR("epoll_wait returned: %d, events: %#x, data: %lu", x, event.events, event.data.u64);
    }

    memset(&event, 0, sizeof(event));
    x = CHECK(epoll_wait(epfd, &event, 1, 1));
    if (x != 0) {
        ERR("epoll_wait returned: %d, events: %#x, data: %lu", x, event.events, event.data.u64);
    }

    /* rearm */
    event.events = EPOLLIN | EPOLLONESHOT;
    event.data.u64 = pipe_fds[0];
    CHECK(epoll_ctl(epfd, EPOLL_CTL_MOD, pipe_fds[0], &event));

    memset(&event, 0, sizeof(event));
    x = CHECK(epoll_wait(epfd, &event, 1, 1));
    if (x != 1 || event.events != EPOLLIN || event.data.u64 != (uint64_t)pipe_fds[0]) {
        ERR("epoll_wait returned: %d, events: %#x, data: %lu", x, event.events, event.data.u64);
    }

    CHECK(close(pipe_fds[0]));
    CHECK(close(pipe_fds[1]));
    CHECK(close(epfd));
}

static void test_epoll_empty(void) {
    int epfd = CHECK(epoll_create1(0));

    struct epoll_event event = { 0 };
    int x = CHECK(epoll_wait(epfd, &event, 1, 0));
    if (x != 0) {
        ERR("epoll_wait on empty epoll instance returned: %d", x);
    }

    CHECK(close(epfd));
}

static void server(int sockfd) {
    int epfd = CHECK(epoll_create1(EPOLL_CLOEXEC));

    int s = CHECK(socket(AF_INET, SOCK_STREAM, 0));

    int enable = 1;
    CHECK(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)));

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    CHECK(bind(s, (void*)&sa, sizeof(sa)));
    CHECK(listen(s, 5));

    char c = 0;
    ssize_t x = CHECK(write(sockfd, &c, sizeof(c)));
    if (x != sizeof(c)) {
        ERR("write: %zd", x);
    }

    int client = CHECK(accept(s, NULL, NULL));

    CHECK(close(s));

    struct epoll_event event = {
        .events = EPOLLIN | EPOLLRDHUP,
        .data.fd = client,
    };
    CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, client, &event));

    memset(&event, 0, sizeof(event));
    int r = CHECK(epoll_wait(epfd, &event, 1, 0));
    if (r != 0) {
        ERR("epoll_wait returned: %d, events: %#x, fd: %d", r, event.events, event.data.fd);
    }

    x = CHECK(write(sockfd, &c, sizeof(c)));
    if (x != sizeof(c)) {
        ERR("write: %zd", x);
    }

    x = CHECK(read(sockfd, &c, sizeof(c)));
    if (x != sizeof(c)) {
        ERR("read: %zd", x);
    }
    CHECK(close(sockfd));

    memset(&event, 0, sizeof(event));
    r = CHECK(epoll_wait(epfd, &event, 1, 0));
    /* `EPOLLRDHUP` is always reported together with `EPOLLHUP` in Gramine as its limitation. We
     * thus ignore `EPOLLHUP` here (which is not reported natively) to make the test also work for
     * native. */
    if (r != 1 || (event.events & ~EPOLLHUP) != (EPOLLIN | EPOLLRDHUP) || event.data.fd != client) {
        ERR("epoll_wait returned: %d, events: %#x, fd: %d", r, event.events, event.data.fd);
    }

    CHECK(close(client));
    CHECK(close(epfd));
}

static void client(int sockfd) {
    char c = 0;
    ssize_t x = CHECK(read(sockfd, &c, sizeof(c)));
    if (x != sizeof(c)) {
        ERR("read: %zd", x);
    }

    int s = CHECK(socket(AF_INET, SOCK_STREAM, 0));

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
    };
    if (inet_aton(SRV_IP, &sa.sin_addr) != 1) {
        ERR("inet_aton failed");
    }

    CHECK(connect(s, (void*)&sa, sizeof(sa)));

    x = CHECK(read(sockfd, &c, sizeof(c)));
    if (x != sizeof(c)) {
        ERR("read: %zd", x);
    }

    CHECK(close(s));

    x = CHECK(write(sockfd, &c, sizeof(c)));
    if (x != sizeof(c)) {
        ERR("write: %zd", x);
    }
    CHECK(close(sockfd));
}

static void test_epoll_wait_rdhup(void) {
    int sockfds[2];
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds));

    pid_t p = CHECK(fork());
    if (p == 0) {
        CHECK(close(sockfds[1]));
        client(sockfds[0]);
        exit(0);
    }

    CHECK(close(sockfds[0]));
    server(sockfds[1]);

    int status = 0;
    CHECK(wait(&status));
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        errx(1, "child wait status: %#x", status);
    }
}

int main(void) {
    test_epoll_empty();

    test_epoll_migration();

    test_epoll_oneshot();

    test_epoll_wait_rdhup();

    puts("TEST OK");
    return 0;
}
