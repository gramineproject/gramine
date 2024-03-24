#pragma once

#include <stdint.h>
#include <stdbool.h>


enum fast_clock_state_e
{
    FC_STATE_RDTSC,
    FC_STATE_RDTSC_RECALIBRATE,
    FC_STATE_CALIBRATING,
    FC_STATE_INIT,

    FC_STATE_RDTSC_DISABLED,
};
typedef uint16_t fast_clock_state_t;

#define _FC_NUM_TIMEPOINT_BITS  (1)
#define _FC_NUM_TIMEPOINTS      (1<<_FC_NUM_TIMEPOINT_BITS)

enum fast_clock_flags_e
{
    FC_FLAGS_INIT = 0,

    FC_FLAGS_TIMEPOINT_MASK = _FC_NUM_TIMEPOINTS - 1,
    FC_FLAGS_NUM_TIMEPOINTS = _FC_NUM_TIMEPOINTS,

    FC_FLAGS_STATE_CHANGING = 0x8000,
};
typedef uint16_t fast_clock_flags_t;

typedef union
{
    #pragma pack(push, 1)
    struct
    {
        fast_clock_state_t state;
        fast_clock_flags_t flags;
    };
    #pragma pack(pop)

    uint32_t desc;
} fast_clock_desc_t;

typedef struct fast_clock_timepoint_s
{
    uint64_t clock_freq;
    uint64_t tsc0;
    uint64_t t0_usec;
    uint64_t expiration_usec;
} fast_clock_timepoint_t;

typedef struct fast_clock_s
{
    fast_clock_desc_t atomic_descriptor;
    fast_clock_timepoint_t time_points[FC_FLAGS_NUM_TIMEPOINTS];
} fast_clock_t;

extern fast_clock_t g_fast_clock;

int fast_clock_get_time(fast_clock_t* fast_clock, uint64_t* time_micros, bool force_new_timepoint);
bool fast_clock_is_enabled(const fast_clock_t* fast_clock);
void fast_clock_disable(fast_clock_t* fast_clock);
