#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

#define SRV_IP "127.0.0.1"
#define PORT   11111

static const char g_buffer[] = "Hello from server!";

static void server(int pipefd) {
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
    ssize_t x = CHECK(write(pipefd, &c, sizeof(c)));
    if (x != 1) {
        CHECK(-1);
    }
    CHECK(close(pipefd));

    int client = CHECK(accept(s, NULL, NULL));

    struct sockaddr_in local_addr = { 0 };
    socklen_t len = sizeof(local_addr);
    CHECK(getsockname(client, (struct sockaddr*)&local_addr, &len));
    char local_ip[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &local_addr.sin_addr, local_ip, sizeof(local_ip)) != local_ip) {
        CHECK(-1);
    }
    if (strcmp(local_ip, SRV_IP)) {
        errx(1, "incorrect local IP address of client: \"%s\"", local_ip);
    }
    uint16_t local_port = ntohs(local_addr.sin_port);
    if (local_port != PORT) {
        errx(1, "incorrect local port of client: %hu", local_port);
    }

    CHECK(close(s));

    size_t written = 0;
    while (written < sizeof(g_buffer)) {
        x = CHECK(write(client, g_buffer + written, sizeof(g_buffer) - written));
        if (!x) {
            /* technically impossible, but let's fail loudly if we ever hit this */
            errx(1, "sendto to client returned zero");
        }
        written += x;
    }

    CHECK(close(client));
}

static ssize_t client_recv(int s, char* buf, size_t len, int flags) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(s, buf + got, len - got, flags);
        if (n == -1 && errno == EAGAIN && (flags & MSG_DONTWAIT)) {
            /* Nonblocking read returned no data. */
            return 0;
        }
        CHECK(n);
        got += n;
        if (!n || flags & MSG_PEEK) {
            /* recv with MSG_PEEK flag should be done only once */
            break;
        }
    }

    return got;
}

static void client(int pipefd) {
    char c = 0;
    ssize_t x = CHECK(read(pipefd, &c, sizeof(c)));
    if (x != 1) {
        CHECK(-1);
    }
    CHECK(close(pipefd));

    int s = CHECK(socket(AF_INET, SOCK_STREAM, 0));

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
    };
    if (inet_aton(SRV_IP, &sa.sin_addr) != 1) {
        CHECK(-1);
    }

    CHECK(connect(s, (void*)&sa, sizeof(sa)));

    struct pollfd poll_item = {
        .fd = s,
        .events = POLLIN,
    };
    x = CHECK(poll(&poll_item, 1, -1));
    if (x != 1) {
        /* Should be impossible. */
        CHECK(-1);
    }
    if (!(poll_item.revents & POLLIN)) {
        errx(1, "poll returned events: %#x", poll_item.revents);
    }

    while (1) {
        /* Wait for the full data to arive. We also test `FIONREAD` option here. */
        int v = 0;
        CHECK(ioctl(s, FIONREAD, &v));
        if ((unsigned int)v >= sizeof(g_buffer)) {
            break;
        }
    }

    char buf[sizeof(g_buffer) + 1] = { 0 };
    ssize_t count = client_recv(s, buf, sizeof(buf), MSG_PEEK);
    if (count != sizeof(g_buffer)) {
        errx(1, "recv with MSG_PEEK returned less than available: %zd", count);
    }
    if (memcmp(buf, g_buffer, sizeof(g_buffer))) {
        errx(1, "wrong data received: %s", buf);
    }

    memset(buf, 0, sizeof(buf));
    /* Receive with `MSG_PEEK` again. */
    count = client_recv(s, buf, sizeof(buf), MSG_PEEK);
    if (count != sizeof(g_buffer)) {
        errx(1, "recv with MSG_PEEK returned less than available: %zd", count);
    }
    if (memcmp(buf, g_buffer, sizeof(g_buffer))) {
        errx(1, "wrong data received: %s", buf);
    }

    memset(buf, 0, sizeof(buf));
    /* Receive without `MSG_PEEK` this time. */
    count = client_recv(s, buf, sizeof(buf), /*flags=*/0);
    if (count != sizeof(g_buffer)) {
        errx(1, "recv without MSG_PEEK returned less than available: %zd", count);
    }
    if (memcmp(buf, g_buffer, sizeof(g_buffer))) {
        errx(1, "wrong data received: %s", buf);
    }

    /* Check how much data is left, with a nonblocking recv. */
    count = client_recv(s, buf, sizeof(buf), MSG_DONTWAIT);
    if (count) {
        errx(1, "There should be no data left, yet recv returned %ld", count);
    }

    CHECK(close(s));
}

int main(int argc, char** argv) {
    int pipefds[2];
    CHECK(pipe(pipefds));

    pid_t p = CHECK(fork());
    if (p == 0) {
        CHECK(close(pipefds[1]));
        client(pipefds[0]);
        return 0;
    }

    CHECK(close(pipefds[0]));
    server(pipefds[1]);

    int status = 0;
    CHECK(wait(&status));
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        errx(1, "child wait status: %#x", status);
    }

    puts("TEST OK");
    return 0;
}
