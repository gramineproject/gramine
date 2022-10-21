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
#include "rw_file.h"

#define SRV_ADDR_NONEXISTING "/tmp/nonexisting/nonexisting"
#define SRV_ADDR_DUMMY       "tmp/dummy"
#define SRV_ADDR             "tmp/unix_socket"

static const char g_buffer[] = "Hello from UDS server!";

static void check_nonexisting_socket(void) {
    int s = CHECK(socket(AF_UNIX, SOCK_STREAM, 0));

    struct sockaddr_un sa = {
        .sun_family = AF_UNIX,
        .sun_path = SRV_ADDR_NONEXISTING,
    };

    int ret = connect(s, (void*)&sa, sizeof(sa));
    if (ret == 0 || errno != ENOENT) {
        errx(1, "nonexisting-socket connect didn't fail with ENOENT");
    }

    CHECK(close(s));
}

static void create_dummy_socket(void) {
    int s = CHECK(socket(AF_UNIX, SOCK_STREAM, 0));

    struct sockaddr_un sa = {
        .sun_family = AF_UNIX,
        .sun_path = SRV_ADDR_DUMMY,
    };
    CHECK(bind(s, (void*)&sa, sizeof(sa)));
    CHECK(listen(s, 5));
    /* do not close this socket to test two sockets in parallel */
}

static void server(int pipefd) {
    int s = CHECK(socket(AF_UNIX, SOCK_STREAM, 0));

    struct sockaddr_un sa = {
        .sun_family = AF_UNIX,
        .sun_path = SRV_ADDR,
    };
    CHECK(bind(s, (void*)&sa, sizeof(sa)));
    CHECK(listen(s, 5));

    char c = 0;
    ssize_t x = CHECK(write(pipefd, &c, sizeof(c)));
    if (x != sizeof(c)) {
        errx(1, "client terminated unexpectedly");
    }
    CHECK(close(pipefd));

    int client = CHECK(accept(s, NULL, NULL));

    CHECK(close(s));

    x = CHECK(posix_fd_write(client, g_buffer, sizeof(g_buffer)));
    if (x != sizeof(g_buffer)) {
        errx(1, "partial write to client");
    }

    CHECK(close(client));
}

static void client(int pipefd) {
    char c = 0;
    ssize_t x = CHECK(read(pipefd, &c, sizeof(c)));
    if (x != sizeof(c)) {
        errx(1, "server terminated unexpectedly");
    }
    CHECK(close(pipefd));

#if 0 /* FIXME: currently Gramine doesn't reflect named UNIX sockets in file system */
    /* named UNIX domain sockets must create FS files, verify it */
    struct stat statbuf;
    CHECK(stat(SRV_ADDR, &statbuf));
    if (statbuf.st_uid != getuid() || statbuf.st_gid != getgid()) {
        errx(1, "unexpected UID/GID of file `%s`", SRV_ADDR);
    }
    if ((statbuf.st_mode & S_IFMT) != S_IFSOCK) {
        errx(1, "file `%s` is not a UNIX domain socket", SRV_ADDR);
    }
#endif

    int s = CHECK(socket(AF_UNIX, SOCK_STREAM, 0));

    struct sockaddr_un sa = {
        .sun_family = AF_UNIX,
        .sun_path = SRV_ADDR,
    };
    CHECK(connect(s, (void*)&sa, sizeof(sa)));

    char buf[sizeof(g_buffer) + 1] = { 0 };
    x = CHECK(posix_fd_read(s, buf, sizeof(buf) - 1));
    if (x != sizeof(g_buffer)) {
        errx(1, "partial read from server");
    }

    if (strcmp(buf, g_buffer)) {
        errx(1, "unexpected message from server: expected %s, got %s", g_buffer, buf);
    }

    CHECK(close(s));
}

int main(void) {
    check_nonexisting_socket();
    create_dummy_socket();

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

    CHECK(close(pipefds[0]));
    CHECK(close(pipefds[1]));

    for (size_t i = 0; i < 2; i++) {
        int status = 0;
        CHECK(wait(&status));
        if (!WIFEXITED(status) || WEXITSTATUS(status)) {
            errx(1, "child wait status: %#x", status);
        }
    }

#if 0 /* FIXME: currently Gramine doesn't reflect named UNIX sockets in file system */
    CHECK(unlink(SRV_ADDR_DUMMY));
    CHECK(unlink(SRV_ADDR));
#endif

    puts("TEST OK");
    return 0;
}
