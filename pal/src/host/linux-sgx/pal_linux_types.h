#pragma once

#include <asm/fcntl.h>
#include <asm/posix_types.h>
#include <asm/stat.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/time.h>
#include <stdint.h>

#include "linux_socket.h"
#include "sigset.h"

typedef __kernel_off_t off_t;
typedef __kernel_pid_t pid_t;

#ifndef size_t
typedef __kernel_size_t size_t;
#endif

struct linux_dirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};

#define DT_UNKNOWN 0
#define DT_FIFO    1
#define DT_CHR     2
#define DT_DIR     4
#define DT_BLK     6
#define DT_REG     8
#define DT_LNK     10
#define DT_SOCK    12
#define DT_WHT     14

struct sockaddr {
    unsigned short sa_family;
    char sa_data[128 - sizeof(unsigned short)];
};

struct cmsghdr {
    size_t cmsg_len;
    int cmsg_level;
    int cmsg_type;
};

#ifndef SCM_RIGHTS
#define SCM_RIGHTS 1
#endif

#define CMSG_DATA(cmsg)         ((unsigned char*)((struct cmsghdr*)(cmsg) + 1))
#define CMSG_NXTHDR(mhdr, cmsg) __cmsg_nxthdr(mhdr, cmsg)
#define CMSG_FIRSTHDR(mhdr)                                   \
    ((size_t)(mhdr)->msg_controllen >= sizeof(struct cmsghdr) \
         ? (struct cmsghdr*)(mhdr)->msg_control               \
         : (struct cmsghdr*)0)
#define CMSG_ALIGN(len) ALIGN_UP(len, sizeof(size_t))
#define CMSG_SPACE(len) (CMSG_ALIGN(len) + CMSG_ALIGN(sizeof(struct cmsghdr)))
#define CMSG_LEN(len)   (CMSG_ALIGN(sizeof(struct cmsghdr)) + (len))
