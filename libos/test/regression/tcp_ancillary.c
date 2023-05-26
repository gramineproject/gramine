#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SCM_TXTIME
#define SCM_TXTIME 61
#endif

#include "common.h"

#define SRV_IP "127.0.0.1"
#define PORT   11110

#define MSG_SPACE (CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct ucred)))

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
    if (x != sizeof(c)) {
        CHECK(-1);
    }
    CHECK(close(pipefd));

    int client = CHECK(accept(s, NULL, NULL));

    CHECK(close(s));

    struct iovec iovec = {
        .iov_base = (char*)g_buffer,
        .iov_len = sizeof(g_buffer),
    };

    char control[MSG_SPACE] = {0};
    struct msghdr msg = {
        .msg_iov = &iovec,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };

    /* below two ancillary data are dummies -- they should be ignored on TCP/IP */
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_CREDENTIALS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(struct ucred));
    struct ucred* cred = (struct ucred*)CMSG_DATA(cmsg);
    cred->pid = getpid();
    cred->uid = getuid();
    cred->gid = getgid();

    cmsg = CMSG_NXTHDR(&msg, cmsg);
    if (!cmsg) {
        /* make GCC happy (otherwise "potential null pointer dereference") */
        errx(1, "no space for second cmsg");
    }
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    int* fd = (int*)CMSG_DATA(cmsg);
    *fd = STDOUT_FILENO;

    x = CHECK(sendmsg(client, &msg, /*flags=*/0));
    if (!x) {
        /* technically impossible, but let's fail loudly if we ever hit this */
        errx(1, "sendmsg returned zero");
    }

    /* set some dummy incorrect SCM_TXTIME in second ancillary data -- must result in EINVAL */
    cmsg->cmsg_len = CMSG_LEN(sizeof(int)); /* wrong length */
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_TXTIME;
    x = sendmsg(client, &msg, /*flags=*/0);
    if (x != -1 && errno != EINVAL) {
        errx(1, "sendmsg with invalid SCM_TXTTIME didn't fail with -EINVAL");
    }

    CHECK(close(client));
}

static void client(int pipefd) {
    char c = 0;
    ssize_t x = CHECK(read(pipefd, &c, sizeof(c)));
    if (x != sizeof(c)) {
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

    while (1) {
        /* Wait for the full data to arive. */
        int v = 0;
        CHECK(ioctl(s, FIONREAD, &v));
        if ((unsigned int)v >= sizeof(g_buffer)) {
            break;
        }
    }

    char buf[sizeof(g_buffer) + 1] = { 0 };
    struct iovec iovec = {
        .iov_base = buf,
        .iov_len = sizeof(buf),
    };

    char control[MSG_SPACE] = {0};
    struct msghdr msg = {
        .msg_iov = &iovec,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };

    ssize_t count = recvmsg(s, &msg, /*flags=*/0);
    if (count != sizeof(g_buffer)) {
        errx(1, "recv returned less than available: %zd", count);
    }
    if (memcmp(buf, g_buffer, sizeof(g_buffer))) {
        errx(1, "wrong data received: %s", buf);
    }
    if (msg.msg_controllen) {
        errx(1, "unexpected ancillary data received (length = %zd)", msg.msg_controllen);
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
