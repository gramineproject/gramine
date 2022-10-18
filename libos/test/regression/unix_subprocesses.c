#define _GNU_SOURCE
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

#define SRV_ADDR "tmp/uds_subprocesses"

static const char g_buffer[] = "Hello from UDS server!";

static void server(int pipefd) {
    int s = CHECK(socket(AF_UNIX, SOCK_STREAM, 0));

    struct sockaddr_un sa;
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, SRV_ADDR, sizeof(sa.sun_path));

    CHECK(bind(s, (void*)&sa, sizeof(sa)));
    CHECK(listen(s, 5));

    char c = 0;
    ssize_t x = CHECK(write(pipefd, &c, sizeof(c)));
    if (x != 1) {
        errx(1, "client terminated unexpectedly");
    }
    CHECK(close(pipefd));

    int client = CHECK(accept(s, NULL, NULL));

    CHECK(close(s));

    size_t written = 0;
    while (written < sizeof(g_buffer)) {
        x = CHECK(write(client, g_buffer + written, sizeof(g_buffer) - written));
        if (!x) {
            /* technically impossible, but let's fail loudly if we ever hit this */
            errx(1, "write to client returned zero");
        }
        written += x;
    }

    CHECK(close(client));
}

static void client(int pipefd) {
    char c = 0;
    ssize_t x = CHECK(read(pipefd, &c, sizeof(c)));
    if (x != 1) {
        errx(1, "server terminated unexpectedly");
    }
    CHECK(close(pipefd));

    /* named UNIX domain sockets must create FS files, verify it; recall that by default Gramine
     * creates files with root UID/GID permissions if not specified otherwise in manifest */
    struct stat statbuf;
    CHECK(stat(SRV_ADDR, &statbuf));
    if (statbuf.st_uid != 0 || statbuf.st_gid != 0) {
        errx(1, "unexpected UID/GID of file `%s`", SRV_ADDR);
    }

    int s = CHECK(socket(AF_UNIX, SOCK_STREAM, 0));

    struct sockaddr_un sa;
    sa.sun_family = AF_UNIX;
    strncpy(sa.sun_path, SRV_ADDR, sizeof(sa.sun_path));

    CHECK(connect(s, (void*)&sa, sizeof(sa)));

    char buf[sizeof(g_buffer) + 1] = { 0 };
    size_t got = 0;
    while (got < sizeof(g_buffer)) {
        x = CHECK(read(s, buf + got, sizeof(g_buffer) - got));
        if (!x) {
            /* let's fail loudly if there is no data from server */
            errx(1, "read from server returned zero");
        }
        got += x;
    }

    if (strcmp(buf, g_buffer)) {
        errx(1, "unexpected message from server: expected %s, got %s", g_buffer, buf);
    }

    CHECK(close(s));
}

int main(void) {
    int pipefds[2];
    CHECK(pipe(pipefds));

    pid_t p_s = CHECK(fork());
    if (p_s == 0) {
        CHECK(close(pipefds[0]));
        server(pipefds[1]);
        return 0;
    }

    pid_t p_c = CHECK(fork());
    if (p_c == 0) {
        CHECK(close(pipefds[1]));
        client(pipefds[0]);
        return 0;
    }

    for (int i = 0; i < 2; i++) {
        int status = 0;
        CHECK(wait(&status));
        if (!WIFEXITED(status) || WEXITSTATUS(status)) {
            errx(1, "child wait status: %#x", status);
        }
    }

    puts("TEST OK");
    return 0;
}
