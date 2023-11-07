#include "api.h"
#include "pal.h"
#include "pal_regression.h"
#include "socket_utils.h"

#define MSG "Some message."
#define MSG_SIZE (static_strlen(MSG))
#define PORT 1337

static void write_all(PAL_HANDLE handle, int type, char* buf, size_t size) {
    size_t i = 0;
    while (i < size) {
        size_t this_size = size - i;
        switch (type) {
            case PAL_TYPE_FILE:
            case PAL_TYPE_PIPE:
            case PAL_TYPE_PIPECLI:
                CHECK(PalStreamWrite(handle, 0, &this_size, buf + i));
                break;
            case PAL_TYPE_SOCKET:;
                struct iovec iov = {
                    .iov_base = buf + i,
                    .iov_len = this_size,
                };
                CHECK(PalSocketSend(handle, &iov, 1, &this_size, /*addr=*/NULL,
                                    /*force_nonblocking=*/false));
                break;
            default:
                BUG();
        }
        if (!this_size) {
            pal_printf("Remote end closed the handle!\n");
            PalProcessExit(1);
        }
        i += this_size;
    }
}

static void read_all(PAL_HANDLE handle, int type, char* buf, size_t size) {
    size_t i = 0;
    while (i < size) {
        size_t this_size = size - i;
        switch (type) {
            case PAL_TYPE_FILE:
            case PAL_TYPE_PIPE:
                CHECK(PalStreamRead(handle, 0, &this_size, buf + i));
                break;
            case PAL_TYPE_SOCKET:;
                struct iovec iov = {
                    .iov_base = buf + i,
                    .iov_len = this_size,
                };
                CHECK(PalSocketRecv(handle, &iov, 1, &this_size, /*addr=*/NULL,
                                    /*force_nonblocking=*/false));
                break;
            default:
                BUG();
        }
        if (!this_size) {
            pal_printf("Remote end closed the handle!\n");
            PalProcessExit(1);
        }
        i += this_size;
    }
}

static void write_msg(PAL_HANDLE handle, int type) {
    char buf[MSG_SIZE] = MSG;
    write_all(handle, type, buf, sizeof(buf));
}

static void recv_and_check(PAL_HANDLE handle, int type) {
    char buf[MSG_SIZE] = { 0 };
    read_all(handle, type, buf, sizeof(buf));
    if (memcmp(buf, MSG, sizeof(buf))) {
        pal_printf("%s: got invalid message: %s\n", __func__, buf);
        PalProcessExit(1);
    }
}

static void set_reuseaddr(PAL_HANDLE handle) {
    PAL_STREAM_ATTR attr;
    CHECK(PalStreamAttributesQueryByHandle(handle, &attr));
    attr.socket.reuseaddr = true;
    CHECK(PalStreamAttributesSetByHandle(handle, &attr));
}

static void do_parent(void) {
    PAL_HANDLE child_process;
    const char* args[] = { "send_handle", "child", NULL };
    CHECK(PalProcessCreate(args, NULL, 0, &child_process));

    PAL_HANDLE handle;

    /* pipe.srv handle */
    CHECK(PalStreamOpen("pipe.srv:1", PAL_ACCESS_RDWR, /*share_flags=*/0, PAL_CREATE_IGNORED,
                        /*options=*/0, &handle));
    CHECK(PalSendHandle(child_process, handle));
    PalObjectDestroy(handle);

    CHECK(PalStreamOpen("pipe:1", PAL_ACCESS_RDWR, /*share_flags=*/0, PAL_CREATE_IGNORED,
                        /*options=*/0, &handle));
    recv_and_check(handle, PAL_TYPE_PIPE);
    PalObjectDestroy(handle);

    /* TCP socket */
    CHECK(PalSocketCreate(PAL_IPV4, PAL_SOCKET_TCP, /*options=*/0, &handle));
    struct pal_socket_addr addr = {
        .domain = PAL_IPV4,
        .ipv4 = {
            .addr = htonl(0x7f000001), // localhost
            .port = htons(PORT),
        },
    };
    set_reuseaddr(handle);
    CHECK(PalSocketBind(handle, &addr));
    CHECK(PalSocketListen(handle, /*backlog=*/3));
    CHECK(PalSendHandle(child_process, handle));
    PalObjectDestroy(handle);

    bool connect_inprogress_unused;
    CHECK(PalSocketCreate(PAL_IPV4, PAL_SOCKET_TCP, /*options=*/0, &handle));
    CHECK(PalSocketConnect(handle, &addr, /*local_addr=*/NULL, &connect_inprogress_unused));
    recv_and_check(handle, PAL_TYPE_SOCKET);
    PalObjectDestroy(handle);

    /* UDP IPv6 socket */
    CHECK(PalSocketCreate(PAL_IPV6, PAL_SOCKET_UDP, /*options=*/0, &handle));
    addr = (struct pal_socket_addr) {
        .domain = PAL_IPV6,
        .ipv6 = {
            .addr = { [15] = 1 }, // localhost
            .port = htons(PORT),
        },
    };
    set_reuseaddr(handle);
    CHECK(PalSocketBind(handle, &addr));
    CHECK(PalSendHandle(child_process, handle));
    PalObjectDestroy(handle);

    CHECK(PalSocketCreate(PAL_IPV6, PAL_SOCKET_UDP, /*options=*/0, &handle));
    CHECK(PalSocketConnect(handle, &addr, /*local_addr=*/NULL, &connect_inprogress_unused));
    write_msg(handle, PAL_TYPE_SOCKET);
    PalObjectDestroy(handle);

    /* file handle */
    CHECK(PalStreamOpen("file:to_send.tmp", PAL_ACCESS_RDWR, /*share_flags=*/0600, PAL_CREATE_TRY,
                        /*options=*/0, &handle));
    write_msg(handle, PAL_TYPE_FILE);
    CHECK(PalSendHandle(child_process, handle));
    PalObjectDestroy(handle);
}

static void do_child(void) {
    PAL_HANDLE handle;

    /* pipe.srv handle */
    CHECK(PalReceiveHandle(PalGetPalPublicState()->parent_process, &handle));
    PAL_HANDLE client_handle;
    CHECK(PalStreamWaitForClient(handle, &client_handle, /*options=*/0));
    PalObjectDestroy(handle);
    write_msg(client_handle, PAL_TYPE_PIPECLI);
    PalObjectDestroy(client_handle);

    /* TCP socket */
    CHECK(PalReceiveHandle(PalGetPalPublicState()->parent_process, &handle));
    CHECK(PalSocketAccept(handle, /*options=*/0, &client_handle, /*out_client_addr=*/NULL,
                          /*out_local_addr=*/NULL));
    PalObjectDestroy(handle);
    write_msg(client_handle, PAL_TYPE_SOCKET);
    PalObjectDestroy(client_handle);

    /* UDP IPv6 socket */
    CHECK(PalReceiveHandle(PalGetPalPublicState()->parent_process, &handle));
    recv_and_check(handle, PAL_TYPE_SOCKET);
    PalObjectDestroy(handle);

    /* file handle */
    CHECK(PalReceiveHandle(PalGetPalPublicState()->parent_process, &handle));
    recv_and_check(handle, PAL_TYPE_FILE);
    PalObjectDestroy(handle);
}

int main(int argc, char* argv[]) {
    if (argc <= 0) {
        pal_printf("Invalid argc: %d\n", argc);
        return 1;
    } else if (argc == 1) {
        do_parent();
        pal_printf("Parent: test OK\n");
    } else {
        do_child();
        pal_printf("Child: test OK\n");
    }
    return 0;
}
