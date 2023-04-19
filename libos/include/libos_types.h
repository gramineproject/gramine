#pragma once

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "elf.h"
#include "linux_socket.h"
#include "pal.h"

// TODO: remove from here and include only where they are used.
#include "linux_abi/fs.h"
#include "linux_abi/limits.h"
#include "linux_abi/poll.h"
#include "linux_abi/sched.h"
#include "linux_abi/signals.h"
#include "linux_abi/time.h"
#include "linux_abi/types.h"

typedef unsigned long int nfds_t;
typedef unsigned long int nlink_t;

typedef Elf64_auxv_t elf_auxv_t;

/* typedef for LibOS internal types */
typedef uint32_t IDTYPE;
#define IDTYPE_MAX UINT32_MAX

#define PID_MAX_LIMIT 4194304 /* Linux limit 2^22, this value is *one greater* than max PID */
#define PID_MAX (PID_MAX_LIMIT - 1)

typedef uint64_t HASHTYPE;

#define FILE_OFF_MAX INT64_MAX
typedef int64_t file_off_t;

struct libos_lock {
    PAL_HANDLE lock;
    IDTYPE owner;
};

/* maximum length of pipe/FIFO name (should be less than Linux sockaddr_un.sun_path = 108) */
#define PIPE_URI_SIZE 96
