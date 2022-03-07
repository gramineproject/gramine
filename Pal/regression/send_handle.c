#include "api.h"
#include "pal.h"
#include "pal_regression.h"

#define MSG "Some message."
#define MSG_SIZE static_strlen(MSG)
#define PORT 1337

static void write_all(PAL_HANDLE handle, int type, char* buf, size_t size) {
    size_t i = 0;
    while (i < size) {
        size_t this_size = size - i;
        switch (type) {
            case PAL_TYPE_FILE:
            case PAL_TYPE_PIPE:
            case PAL_TYPE_PIPECLI:
                CHECK(DkStreamWrite(handle, 0, &this_size, buf + i, NULL));
                break;
            case PAL_TYPE_SOCKET:;
                struct pal_iovec iov = {
                    .iov_base = buf + i,
                    .iov_len = this_size,
                };
                CHECK(DkSocketSend(handle, &iov, 1, &this_size, /*addr=*/NULL));
                break;
            default:
                BUG();
        }
        if (!this_size) {
            pal_printf("Remote end closed the handle!\n");
            DkProcessExit(1);
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
                CHECK(DkStreamRead(handle, 0, &this_size, buf + i, NULL, 0));
                break;
            case PAL_TYPE_SOCKET:;
                struct pal_iovec iov = {
                    .iov_base = buf + i,
                    .iov_len = this_size,
                };
                CHECK(DkSocketRecv(handle, &iov, 1, &this_size, /*addr=*/NULL,
                                   /*is_nonblocking=*/false));
                break;
            default:
                BUG();
        }
        if (!this_size) {
            pal_printf("Remote end closed the handle!\n");
            DkProcessExit(1);
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
        DkProcessExit(1);
    }
}

static void set_reuseaddr(PAL_HANDLE handle) {
    PAL_STREAM_ATTR attr;
    CHECK(DkStreamAttributesQueryByHandle(handle, &attr));
    attr.socket.reuseaddr = true;
    CHECK(DkStreamAttributesSetByHandle(handle, &attr));
}

static void do_parent(void) {
    PAL_HANDLE child_handle;
    const char* args[] = { "send_handle", "child", NULL };
    CHECK(DkProcessCreate(args, &child_handle));

    PAL_HANDLE handle;

    /* pipe.srv handle */
    CHECK(DkStreamOpen("pipe.srv:1", PAL_ACCESS_RDWR, /*share_flags=*/0, PAL_CREATE_IGNORED,
                       /*options=*/0, &handle));
    CHECK(DkSendHandle(child_handle, handle));
    DkObjectClose(handle);

    CHECK(DkStreamOpen("pipe:1", PAL_ACCESS_RDWR, /*share_flags=*/0, PAL_CREATE_IGNORED,
                       /*options=*/0, &handle));
    recv_and_check(handle, PAL_TYPE_PIPE);
    DkObjectClose(handle);

    /* TCP socket */
    CHECK(DkSocketCreate(IPV4, PAL_SOCKET_TCP, /*options=*/0, &handle));
    struct pal_socket_addr addr = {
        .domain = IPV4,
        .ipv4 = {
            .addr = __htonl(0x7f000001), // localhost
            .port = __htons(PORT),
        },
    };
    set_reuseaddr(handle);
    CHECK(DkSocketBind(handle, &addr));
    CHECK(DkSocketListen(handle, /*backlog=*/3));
    CHECK(DkSendHandle(child_handle, handle));
    DkObjectClose(handle);

    CHECK(DkSocketCreate(IPV4, PAL_SOCKET_TCP, /*options=*/0, &handle));
    CHECK(DkSocketConnect(handle, &addr, /*local_addr=*/NULL));
    recv_and_check(handle, PAL_TYPE_SOCKET);
    DkObjectClose(handle);

    /* UDP IPv6 socket */
    CHECK(DkSocketCreate(IPV6, PAL_SOCKET_UDP, /*options=*/0, &handle));
    addr = (struct pal_socket_addr) {
        .domain = IPV6,
        .ipv6 = {
            .addr = { [15] = 1 }, // localhost
            .port = __htons(PORT),
        },
    };
    set_reuseaddr(handle);
    CHECK(DkSocketBind(handle, &addr));
    CHECK(DkSendHandle(child_handle, handle));
    DkObjectClose(handle);

    CHECK(DkSocketCreate(IPV6, PAL_SOCKET_UDP, /*options=*/0, &handle));
    CHECK(DkSocketConnect(handle, &addr, /*local_addr=*/NULL));
    write_msg(handle, PAL_TYPE_SOCKET);
    DkObjectClose(handle);

    /* file handle */
    CHECK(DkStreamOpen("file:to_send.tmp", PAL_ACCESS_RDWR, /*share_flags=*/0600, PAL_CREATE_TRY,
                       /*options=*/0, &handle));
    write_msg(handle, PAL_TYPE_FILE);
    CHECK(DkSendHandle(child_handle, handle));
    DkObjectClose(handle);
}

static void do_child(void) {
    PAL_HANDLE handle;

    /* pipe.srv handle */
    CHECK(DkReceiveHandle(DkGetPalPublicState()->parent_process, &handle));
    PAL_HANDLE client_handle;
    CHECK(DkStreamWaitForClient(handle, &client_handle, /*options=*/0));
    DkObjectClose(handle);
    write_msg(client_handle, PAL_TYPE_PIPECLI);
    DkObjectClose(client_handle);

    /* TCP socket */
    CHECK(DkReceiveHandle(DkGetPalPublicState()->parent_process, &handle));
    CHECK(DkSocketAccept(handle, /*options=*/0, &client_handle, /*client_addr=*/NULL));
    DkObjectClose(handle);
    write_msg(client_handle, PAL_TYPE_SOCKET);
    DkObjectClose(client_handle);

    /* UDP IPv6 socket */
    CHECK(DkReceiveHandle(DkGetPalPublicState()->parent_process, &handle));
    recv_and_check(handle, PAL_TYPE_SOCKET);
    DkObjectClose(handle);

    /* file handle */
    CHECK(DkReceiveHandle(DkGetPalPublicState()->parent_process, &handle));
    recv_and_check(handle, PAL_TYPE_FILE);
    DkObjectClose(handle);
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
