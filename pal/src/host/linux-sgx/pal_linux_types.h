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
