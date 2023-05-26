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

static struct {
    size_t send_size;
    size_t recv_size;
    int recv_flags;
    ssize_t expected_return_value;
    int expected_flags;
} g_test_cases[] = {
    {
        .send_size = PACKET_SIZE, .recv_size = PACKET_SIZE / 2, .recv_flags = 0,
        .expected_return_value = PACKET_SIZE / 2, .expected_flags = MSG_TRUNC,
    },
    {
        .send_size = PACKET_SIZE, .recv_size = PACKET_SIZE / 2, .recv_flags = MSG_TRUNC,
        .expected_return_value = PACKET_SIZE, .expected_flags = MSG_TRUNC,
    },
    {
        .send_size = PACKET_SIZE / 2, .recv_size = PACKET_SIZE, .recv_flags = MSG_TRUNC,
        .expected_return_value = PACKET_SIZE / 2, .expected_flags = 0,
    },
};

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

    for (size_t i = 0; i < sizeof(g_test_cases) / sizeof(g_test_cases[0]); i++) {
        char* buf = malloc(g_test_cases[i].recv_size);
        if (!buf) {
            err(EXIT_FAILURE, "case %zu: malloc failed", i);
        }
        struct iovec iovec = {
            .iov_base = buf,
            .iov_len = g_test_cases[i].recv_size,
        };
        struct msghdr msg = {
            .msg_iov = &iovec,
            .msg_iovlen = 1,
        };
        ssize_t size = recvmsg(s, &msg, g_test_cases[i].recv_flags);
        if (size < 0) {
            err(EXIT_FAILURE, "case %zu: recvmsg failed", i);
        }
        if (size != g_test_cases[i].expected_return_value) {
            errx(EXIT_FAILURE, "case %zu: recvmsg returned: %ld, expected: %ld", i, size,
                 g_test_cases[i].expected_return_value);
        }
        if (msg.msg_flags != g_test_cases[i].expected_flags) {
            errx(EXIT_FAILURE, "case %zu: recvmsg output flags: %#x, expected: %#x", i,
                 msg.msg_flags, g_test_cases[i].expected_flags);
        }
        free(buf);
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
        .sin_port = htons(PORT),
    };
    if (inet_aton(SRV_IP, &sa.sin_addr) != 1)
        errx(EXIT_FAILURE, "client inet_aton");

    for (size_t i = 0; i < sizeof(g_test_cases) / sizeof(g_test_cases[0]); i++) {
        char* buf = calloc(1, g_test_cases[i].send_size);
        if (!buf) {
            err(EXIT_FAILURE, "case %zu: malloc failed", i);
        }
        ssize_t size = sendto(s, buf, g_test_cases[i].send_size, /*flags=*/0, (void*)&sa,
                              sizeof(sa));
        if (size < 0) {
            err(EXIT_FAILURE, "case %zu: sendto failed", i);
        }
        if ((size_t)size != g_test_cases[i].send_size) {
            errx(EXIT_FAILURE, "case %zu: sendto returned: %ld, expected: %ld", i, size,
                 g_test_cases[i].send_size);
        }
        free(buf);
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
