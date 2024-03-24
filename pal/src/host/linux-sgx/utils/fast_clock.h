#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "api.h"


#define _FC_NUM_TIMEPOINT_BITS  (1)
#define FC_NUM_TIMEPOINTS       (1<<_FC_NUM_TIMEPOINT_BITS)

typedef union
{
    struct
    {
        uint16_t state              : 4;
        uint16_t timepoint_index    : _FC_NUM_TIMEPOINT_BITS;
        uint16_t _pad0              : (16 - _FC_NUM_TIMEPOINT_BITS - 5);
        uint16_t state_changing     : 1;
    };

    uint16_t desc;
} fast_clock_desc;

static_assert(_FC_NUM_TIMEPOINT_BITS >= 1, "timepoint_index must have at minimum 1-bit");
static_assert(_FC_NUM_TIMEPOINT_BITS + 5 <= 16, "timepoint_index uses too many bits");
static_assert(sizeof(fast_clock_desc) == sizeof(uint16_t), "fast_clock_desc size mismatch");

typedef struct
{
    uint64_t clock_freq;
    uint64_t tsc0;
    uint64_t t0_usec;
    uint64_t expiration_usec;
} fast_clock_timepoint;

typedef struct
{
    fast_clock_desc atomic_descriptor;
    fast_clock_timepoint time_points[FC_NUM_TIMEPOINTS];
} fast_clock;

extern fast_clock g_fast_clock;

int fast_clock_get_time(fast_clock* fast_clock, uint64_t* time_micros);
bool fast_clock_is_enabled(const fast_clock* fast_clock);
void fast_clock_disable(fast_clock* fast_clock);
