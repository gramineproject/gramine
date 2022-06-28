#pragma once

#include <stdint.h>

#include "libos_tcb_arch.h"

/* asm/signal.h */
#define SIGS_CNT 64
#define SIGRTMIN 32

typedef struct {
    unsigned long __val[SIGS_CNT / (8 * sizeof(unsigned long))];
} __sigset_t;

#define RED_ZONE_SIZE 128
