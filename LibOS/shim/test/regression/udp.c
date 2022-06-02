#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SRV_IP "127.0.0.1"
#define PORT 9930
#define PACKET_SIZE 0x40

static void server(int pipefd) {
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0)
        err(EXIT_FAILURE, "server socket");

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
        .sin_addr = {
            .s_addr = htonl(INADDR_ANY),
        },
    };

    if (bind(s, (struct sockaddr*)&sa, sizeof(sa)) < 0)
        err(EXIT_FAILURE, "server bind");

    char byte = 0;
    ssize_t written = write(pipefd, &byte, sizeof(byte));
    if (written < 0) {
        err(EXIT_FAILURE, "server write on pipe");
    }
    if (!written) {
        /* technically impossible, but let's fail loudly if we ever hit this */
        errx(EXIT_FAILURE, "server write on pipe returned zero");
    }

    char buf[PACKET_SIZE] = { 0 };
    struct iovec iovec = {
        .iov_base = buf,
        .iov_len = sizeof(buf) / 2,
    };
    struct msghdr msg = {
        .msg_iov = &iovec,
        .msg_iovlen = 1,
    };
    ssize_t size = recvmsg(s, &msg, /*flags=*/0);
    if (size < 0) {
        err(EXIT_FAILURE, "recvmsg 1");
    }
    if ((size_t)size != iovec.iov_len) {
        errx(EXIT_FAILURE, "short read in udp: %ld", size);
    }
    if (msg.msg_flags != MSG_TRUNC) {
        errx(EXIT_FAILURE, "wrong flags returned 1: %d", msg.msg_flags);
    }

    msg.msg_flags = 0;
    size = recvmsg(s, &msg, MSG_TRUNC);
    if (size < 0) {
        err(EXIT_FAILURE, "recvmsg 2");
    }
    if ((size_t)size != PACKET_SIZE) {
        errx(EXIT_FAILURE, "wrong size return with MSG_TRUNC: %ld", size);
    }
    if (msg.msg_flags != MSG_TRUNC) {
        errx(EXIT_FAILURE, "wrong flags returned 1: %d", msg.msg_flags);
    }

    if (close(s) < 0)
        err(EXIT_FAILURE, "server close");
}

static void client(int pipefd) {
    char byte = 0;
    ssize_t received = read(pipefd, &byte, sizeof(byte));
    if (received < 0) {
        err(EXIT_FAILURE, "client read on pipe");
    }
    if (!received)
        err(EXIT_FAILURE, "client read on pipe (EOF)");

    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0)
        err(EXIT_FAILURE, "client socket");

    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port   = htons(PORT),
    };
    if (inet_aton(SRV_IP, &sa.sin_addr) != 1)
        errx(EXIT_FAILURE, "client inet_aton");

    char buf[PACKET_SIZE] = { 0 };

    ssize_t size = sendto(s, buf, sizeof(buf), /*flags=*/0, (void*)&sa, sizeof(sa));
    if (size < 0) {
        err(EXIT_FAILURE, "sendto 1");
    }
    if (size != sizeof(buf)) {
        errx(EXIT_FAILURE, "short udp send 1");
    }

    size = sendto(s, buf, sizeof(buf), /*flags=*/0, (void*)&sa, sizeof(sa));
    if (size < 0) {
        err(EXIT_FAILURE, "sendto 2");
    }
    if (size != sizeof(buf)) {
        errx(EXIT_FAILURE, "short udp send 2");
    }

    if (close(s) < 0)
        err(EXIT_FAILURE, "client close");
}

int main(void) {
    int pipefds[2];
    if (pipe(pipefds) < 0)
        err(EXIT_FAILURE, "pipe");

    int pid = fork();
    if (pid < 0)
        err(EXIT_FAILURE, "fork");

    if (pid == 0) {
        if (close(pipefds[1]) < 0)
            err(EXIT_FAILURE, "client close of pipe");

        client(pipefds[0]);
        return 0;
    }

    if (close(pipefds[0]) < 0)
        err(EXIT_FAILURE, "server close of pipe");

    server(pipefds[1]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        err(EXIT_FAILURE, "waitpid");
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        errx(EXIT_FAILURE, "child killed: %#x", status);
    }

    puts("TEST OK");
    return 0;
}
