#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

#define ERR(msg, args...) \
    errx(1, "%d: " msg, __LINE__, ##args)

#define SRV_IP "127.0.0.1"
#define PORT   11111

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

static void server(int pipefd) {
    int epfd = CHECK(epoll_create1(EPOLL_CLOEXEC));

    int s = CHECK(socket(AF_INET, SOCK_STREAM, 0));

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    CHECK(bind(s, (void*)&sa, sizeof(sa)));
    CHECK(listen(s, 5));

    char c = 0;
    ssize_t x = CHECK(write(pipefd, &c, sizeof(c)));
    if (x != 1) {
        CHECK(-1);
    }

    int client = CHECK(accept(s, NULL, NULL));

    CHECK(close(s));

    struct epoll_event event = {
        .events = EPOLLIN | EPOLLRDHUP,
        .data.fd = client,
    };
    CHECK(epoll_ctl(epfd, EPOLL_CTL_ADD, client, &event));

    memset(&event, 0, sizeof(event));
    int r = CHECK(epoll_wait(epfd, &event, 1, 1));
    if (r != 0) {
        ERR("epoll_wait returned: %d, events: %#x, data: %d", r, event.events, event.data.fd);
    }

    x = CHECK(write(pipefd, &c, sizeof(c)));
    if (x != 1) {
        CHECK(-1);
    }
    CHECK(close(pipefd));

    memset(&event, 0, sizeof(event));
    r = CHECK(epoll_wait(epfd, &event, 1, 1));
    if (r != 1 || event.events != (EPOLLIN | EPOLLRDHUP) || event.data.fd != client) {
        ERR("epoll_wait returned: %d, events: %#x, data: %d", r, event.events, event.data.fd);
    }

    CHECK(close(client));
    CHECK(close(epfd));
}

static void client(int pipefd) {
    char c = 0;
    ssize_t x = CHECK(read(pipefd, &c, sizeof(c)));
    if (x != 1) {
        CHECK(-1);
    }

    int s = CHECK(socket(AF_INET, SOCK_STREAM, 0));

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr = {
            /* TODO: remove this once Ubuntu 18.04 is deprecated. */
            .s_addr = 0,
        },
    };
    if (inet_aton(SRV_IP, &sa.sin_addr) != 1) {
        CHECK(-1);
    }

    CHECK(connect(s, (void*)&sa, sizeof(sa)));

    x = CHECK(read(pipefd, &c, sizeof(c)));
    if (x != 1) {
        CHECK(-1);
    }
    CHECK(close(pipefd));

    CHECK(close(s));
}

static void test_epoll_wait_rdhup(void) {
    int pipefds[2];
    CHECK(pipe(pipefds));

    pid_t p = CHECK(fork());
    if (p == 0) {
        CHECK(close(pipefds[1]));
        client(pipefds[0]);
        return;
    }

    CHECK(close(pipefds[0]));
    server(pipefds[1]);

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
