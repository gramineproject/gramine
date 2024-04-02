#include <string.h>
#include <unistd.h>

#include "cpu.h"
#include "enclave_ocalls.h"
#include "pal_internal.h"
#include "utils/fast_clock.h"

/**
 * FastClock
 *
 * The purpose of this module is to provide a fast sgx implementation for gettimeofday().
 *    - What this does: avoids OCALL on every gettimeofday() invocation. Given a "ground truth" timepoint, we can calculate the current time
 *      directly inside the enclave.
 *    - What this doesn't do: this solution does *NOT* provide a trusted time implementation. This still relies on the untrusted host time.
 *      In addition, privileged host code can write to the tsc register and affect the time calculation.
 *
 * In order to calculate the current time inside the enclave, we need the following:
 *   1. tv0 - a point in time that all fast clock times will be calculated against.
 *   2. tsc0 - the clock cycle counter for that point in time
 *   3. clock_frequency - how many clock cycles do we have per second. The tsc value is synced between all cores (it's not a "real" clock counter).
 * Using the above, given the current tsc we can calculate the current timeval.
 *
 * Note: reading the tsc register (using rdtsc x86 opcode) is NOT supported in SGX1 enclaves. Support was added in SGX2.
 *
 * *** Implementation ***
 *
 * FastClock is implemented as a state machine. This was done since we don't have a good portable way to get the cpu clock frequency.
 * So, our general strategy is to simply "calculate" it, by comparing two timeval values and their corresponding tsc values.
 *
 * The naive way of making this calculation is to take two timepoints during initialization with a "sleep" in between. Instead, we're letting the
 * program run "organically", and using the time that passes between calls to gettimeofday() as our sleep. This means FastClock will perform an
 * OCALL when needed, and calculate the time internally when it can.
 *
 * FastClock has the following states:
 *
 *  INIT -> CALIBRATING -> RDTSC -> RDTSC_RECALIBRATE -> RDTSC -> ...
 *  INIT -> DISABLED
 *
 *   1. INIT - this will first guarantee we have rdtsc() available and transition to DISABLED state if we don't. Otherwise, take the initial tv0 and tsc0 values
 *      and tranistion to CALIBRATING.
 *   2. DISABLED - simply OCALL to get the time, this is the slow path fallback (rdtsc not available in SGX1 enclaves).
 *   3. CALIBRATING - at this state, all calls will result in an OCALL since we don't know what the clock frequency is yet. Once enough time has
 *      passed since the initial OCALL timepoint, we can calculate the clock frequency and advance to RDTSC state.
 *   4. RDTSC - This is the "fast path", will calculate the time by comparing the current clock counter with tsc0, using the clock frequency and tv0.
 *      In order to keep the timer in sync with the host time, after a certain amount of time passes we will OCALL to get a new tv0 and tsc0,
 *      and transition to RDTSC_RECALIBRATE.
 *   5. RDTSC_RECALIBRATE - this state is similar to CALIBRATING state, since its purpose is to "wait enough time" in order to (re-)calculate the clock frequency.
 *      The difference is that we have the previously calculated clock frequency, so we can use it to calculate the time as done in the fast path.
 *      After enough time has passed in order to re-calculate the clock frequency, perform an OCALL to get another "real" timepoint, then transition back to RDTSC.
 *
 * *** Thread safety ***
 *
 * As far as multithreading goes, we had the following goals. We wanted the solution to give consistent times between all threads. This means FastClock object can't be
 * thread local, and needs to be thread safe. And since this is a performance optimization, we need this to be lockless (and definitely no OCALLs other than gettimeofday).
 *
 * To achieve the above, we use the following data structures.
 *
 *   1. fast_clock_timepoint_t - this contains all the internal state needed by FastClock to calculate the time as discussed above. FastClock internally
 *      has *two* timepoints, which are used in round-robin (alternating).
 *   2. fast_clock_desc_t - this is read and written to atomically, which is how the lockless thread safety is implemented. The descriptor contains:
 *      - The current "state" of the FastClock state machine.
 *      - The round-robin index of the timepoint that is currently in use.
 *      - A flag that guards state transitions, in case of concurrent calls only a single thread should calculate the new timepoint data and transition
 *        the state.
 *
 * By using an atomic descriptor and round-robin timepoints, we can make sure only a single thread is changing the timepoint values, and no one can read
 * "intermediate" state. We will only store the new descriptor pointing to the "next" state and timepoint after it's usable.
 *
 * Note: in theory this is not thread safe, as we can have the following -
 *   1. Thread A reads descriptor, starts flow using timepoint #0, then context switch.
 *   2. Some time passes and we transition to timepoint #1.
 *   3. Some more time passes and we transition back to timepoint #0.
 *   4. Thread A wakes up and reads inconsistent state in timepoint #0. At the worst case this might lead to negative \ max time.
 * In practice this will never happen, since "real" time passes between transitioning timepoints.
 */


#ifndef SEC_USEC
#define SEC_USEC                        ((uint64_t)1000000)
#endif

#define RDTSC_CALIBRATION_TIME          ((uint64_t)1 * SEC_USEC)
#define RDTSC_RECALIBRATION_INTERVAL    ((uint64_t)120 * SEC_USEC)

fast_clock_t g_fast_clock = {
    .atomic_descriptor = { .state = FC_STATE_INIT, .flags = FC_FLAGS_INIT },
    .time_points = { [0 ... _FC_NUM_TIMEPOINTS-1] = {
        .clock_freq = 0,
        .tsc0 = 0,
        .t0_usec = 0,
        .expiration_usec = 0,
        .tz_minutewest = 0,
        .tz_dsttime = 0,
    }}
};


static inline uint16_t timepoint_index(fast_clock_desc_t curr)
{
    return (curr.flags & FC_FLAGS_TIMEPOINT_MASK);
}

static inline fast_clock_desc_t advance_state(fast_clock_desc_t curr, fast_clock_state_t new_state, bool advance_timepoint)
{
    fast_clock_desc_t new_descriptor;
    new_descriptor.state = new_state;
    uint16_t new_tp_index = timepoint_index(curr);
    if (advance_timepoint) {
        new_tp_index = (new_tp_index + 1) % FC_FLAGS_NUM_TIMEPOINTS;
    }
    new_descriptor.flags = new_tp_index;
    return new_descriptor;
}

static inline bool is_expired(const fast_clock_timepoint_t* timepoint, uint64_t now_usec)
{
    return (timepoint->expiration_usec < now_usec);
}

static inline void calc_time(const fast_clock_timepoint_t* timepoint, uint64_t* time_usec)
{
    uint64_t tsc = get_tsc();
    uint64_t dtsc = tsc - timepoint->tsc0;
    uint64_t dt_usec = (dtsc * SEC_USEC) / timepoint->clock_freq;
    *time_usec = timepoint->t0_usec + dt_usec;
}

static inline void reset_clock_frequency(fast_clock_timepoint_t* timepoint, uint64_t tsc, uint64_t time_usec)
{
    // calculate clock frequency in Hz
    uint64_t dt_usec = time_usec - timepoint->t0_usec;
    uint64_t dtsc = tsc - timepoint->tsc0;
    timepoint->clock_freq = (dtsc * SEC_USEC) / dt_usec;
}

static inline long reset_timepoint(fast_clock_timepoint_t* timepoint)
{
    int ret = ocall_reset_time(&timepoint->t0_usec, &timepoint->tsc0, &timepoint->tz_minutewest, &timepoint->tz_dsttime);
    return ret;
}

static inline void reset_expiration(fast_clock_timepoint_t* timepoint, uint64_t next_expiration)
{
    timepoint->expiration_usec = timepoint->t0_usec + next_expiration;
}

static inline fast_clock_desc_t desc_atomic_load(const fast_clock_t* fast_clock, int mo)
{
    fast_clock_desc_t desc;
    desc.desc = __atomic_load_n(&fast_clock->atomic_descriptor.desc, mo);
    return desc;
}

static inline void desc_atomic_store(fast_clock_t* fast_clock, fast_clock_desc_t new_desc, int mo)
{
    __atomic_store_n(&fast_clock->atomic_descriptor.desc, new_desc.desc, mo);
}

static int handle_state_init(fast_clock_t* fast_clock, fast_clock_desc_t descriptor, uint64_t* time_usec);
static int handle_state_calibrating(fast_clock_t* fast_clock, fast_clock_desc_t descriptor, uint64_t* time_usec);
static inline int handle_state_rdtsc(fast_clock_t* fast_clock, fast_clock_desc_t descriptor, uint64_t* time_usec, bool force_new_timepoint);
static inline int handle_state_rdtsc_recalibrate(fast_clock_t* fast_clock, fast_clock_desc_t descriptor, uint64_t* time_usec);
static int handle_state_rdtsc_disabled(uint64_t* time_usec);

int fast_clock__get_time(fast_clock_t* fast_clock, uint64_t* time_usec, bool force_new_timepoint)
{
    fast_clock_desc_t descriptor = desc_atomic_load(fast_clock, __ATOMIC_ACQUIRE);
    switch (descriptor.state)
    {
    case FC_STATE_RDTSC:
        return handle_state_rdtsc(fast_clock, descriptor, time_usec, force_new_timepoint);
    case FC_STATE_RDTSC_RECALIBRATE:
        return handle_state_rdtsc_recalibrate(fast_clock, descriptor, time_usec);
    case FC_STATE_CALIBRATING:
        return handle_state_calibrating(fast_clock, descriptor, time_usec);
    case FC_STATE_INIT:
        return handle_state_init(fast_clock, descriptor, time_usec);
    case FC_STATE_RDTSC_DISABLED:
    default:
        return handle_state_rdtsc_disabled(time_usec);
    }
}

static inline bool set_change_state_guard(fast_clock_t* fast_clock, fast_clock_desc_t descriptor)
{
    if ((descriptor.flags & FC_FLAGS_STATE_CHANGING) != 0) {
        return false;
    }

    fast_clock_desc_t state_change_guard_desc = {
        .state = descriptor.state,
        .flags = descriptor.flags | FC_FLAGS_STATE_CHANGING,
    };

    return __atomic_compare_exchange_n(
        &fast_clock->atomic_descriptor.desc, &descriptor.desc, state_change_guard_desc.desc,
        /*weak=*/false, __ATOMIC_RELAXED, __ATOMIC_RELAXED
    );
}

bool fast_clock__is_enabled(const fast_clock_t* fast_clock)
{
    fast_clock_desc_t descriptor = desc_atomic_load(fast_clock, __ATOMIC_RELAXED);
    return (descriptor.state != FC_STATE_RDTSC_DISABLED);
}

void fast_clock__disable(fast_clock_t* fast_clock)
{
    /* We need to busy-loop until the state change guard is acquired here - since fast-clock
     * might be in the midst of transitioning states. We can't simply store the DISABLED state. */
    fast_clock_desc_t descriptor;
    do {
        descriptor = desc_atomic_load(fast_clock, __ATOMIC_ACQUIRE);
    } while(!set_change_state_guard(fast_clock, descriptor));

    fast_clock_desc_t disabled_desc = advance_state(descriptor, FC_STATE_RDTSC_DISABLED, false);
    desc_atomic_store(fast_clock, disabled_desc, __ATOMIC_RELEASE);
}

static inline fast_clock_timepoint_t* get_timepoint(fast_clock_t* fast_clock, fast_clock_desc_t descriptor)
{
    return &fast_clock->time_points[timepoint_index(descriptor)];
}

static bool is_rdtsc_available(void) {
    uint32_t words[CPUID_WORD_NUM];

    // rdtsc feature enabled
    _PalCpuIdRetrieve(FEATURE_FLAGS_LEAF, 0, words);
    if (!(words[CPUID_WORD_EDX] & (1 << 4)))
        return false;

    // SGX enabled (sanity check)
    _PalCpuIdRetrieve(EXTENDED_FEATURE_FLAGS_LEAF, 0, words);
    if (!(words[CPUID_WORD_EBX] & (1 << 2)))
        return false;

    // SGX2 capabilities - otherwise, rdtsc opcode is illegal in sgx enclave
    _PalCpuIdRetrieve(INTEL_SGX_LEAF, 0, words);
    if (!(words[CPUID_WORD_EAX] & (1 << 1)))
        return false;   // SGX1 features disabled
    if (!(words[CPUID_WORD_EAX] & (1 << 2)))
        return false;   // SGX2 features disabled

    return true;
}

static int handle_state_rdtsc_disabled(uint64_t* time_usec)
{
    // slow path - OCALL to get time
    return ocall_gettime(time_usec);
}

static int handle_state_init(fast_clock_t* fast_clock, fast_clock_desc_t descriptor, uint64_t* time_usec)
{
    if (!set_change_state_guard(fast_clock, descriptor)) {
        return handle_state_rdtsc_disabled(time_usec);
    }

    if (!is_rdtsc_available()) {
        fast_clock_desc_t next_desc = advance_state(descriptor, FC_STATE_RDTSC_DISABLED, false);
        desc_atomic_store(fast_clock, next_desc, __ATOMIC_RELAXED);
        return handle_state_rdtsc_disabled(time_usec);
    }

    fast_clock_desc_t next_desc = advance_state(descriptor, FC_STATE_CALIBRATING, false);
    fast_clock_timepoint_t* timepoint = get_timepoint(fast_clock, next_desc);
    int ret = reset_timepoint(timepoint);

    // gettimeofday failed - restore descriptor
    if (ret != 0) {
        desc_atomic_store(fast_clock, descriptor, __ATOMIC_RELAXED);
        return ret;
    }

    // advance state
    reset_expiration(timepoint, RDTSC_CALIBRATION_TIME);
    desc_atomic_store(fast_clock, next_desc, __ATOMIC_RELEASE);

    // output results from the timepoint
    *time_usec = timepoint->t0_usec;
    return ret;
}

static int handle_state_calibrating(fast_clock_t* fast_clock, fast_clock_desc_t descriptor, uint64_t* time_usec)
{
    // all callers in this state will perform an OCALL - no need to set the change_state_guard before OCALLing
    uint64_t tmp_tsc = 0;
    int ret = ocall_reset_time(time_usec, &tmp_tsc, NULL, NULL);
    if (ret != 0) {
        return ret;
    }

    fast_clock_timepoint_t* timepoint = get_timepoint(fast_clock, descriptor);
    if (!is_expired(timepoint, *time_usec) || !set_change_state_guard(fast_clock, descriptor)) {
        return ret;
    }

    // calculate the clock_freq and advance state
    reset_clock_frequency(timepoint, tmp_tsc, *time_usec);
    reset_expiration(timepoint, RDTSC_RECALIBRATION_INTERVAL);
    fast_clock_desc_t new_desc = advance_state(descriptor, FC_STATE_RDTSC, false);
    desc_atomic_store(fast_clock, new_desc, __ATOMIC_RELEASE);

    return ret;
}

static inline int handle_state_rdtsc(fast_clock_t* fast_clock, fast_clock_desc_t descriptor, uint64_t* time_usec, bool force_new_timepoint)
{
    fast_clock_timepoint_t* timepoint = get_timepoint(fast_clock, descriptor);

    // fast path - calculate time with rdtsc
    calc_time(timepoint, time_usec);
    bool should_advance = is_expired(timepoint, *time_usec) || force_new_timepoint;
    if (!should_advance || !set_change_state_guard(fast_clock, descriptor)) {
        return 0;
    }

    // acquire the state_change_guard and prepare the next state (get new ground truth timepoint)
    fast_clock_desc_t next_desc = advance_state(descriptor, FC_STATE_RDTSC_RECALIBRATE, true);
    fast_clock_timepoint_t* next_timepoint = get_timepoint(fast_clock, next_desc);

    int ret = reset_timepoint(next_timepoint);
    if (ret != 0) {
        // gettimeofday failed - restore the state_change_guard and return
        desc_atomic_store(fast_clock, descriptor, __ATOMIC_RELAXED);
        return ret;
    }

    // use current clock freq until RDTSC_CALIBRATE state ends and the new clock_freq can be calculated
    next_timepoint->clock_freq = timepoint->clock_freq;
    reset_expiration(next_timepoint, RDTSC_CALIBRATION_TIME);
    desc_atomic_store(fast_clock, next_desc, __ATOMIC_RELEASE);

    return ret;
}

static inline int handle_state_rdtsc_recalibrate(fast_clock_t* fast_clock, fast_clock_desc_t descriptor, uint64_t* time_usec)
{
    fast_clock_timepoint_t* timepoint = get_timepoint(fast_clock, descriptor);

    // fast path - calculate time with rdtsc
    calc_time(timepoint, time_usec);
    if (!is_expired(timepoint, *time_usec) || !set_change_state_guard(fast_clock, descriptor)) {
        return 0;
    }

    uint64_t tsc = 0;
    int ret = ocall_reset_time(time_usec, &tsc, NULL, NULL);
    if (ret != 0) {
        desc_atomic_store(fast_clock, descriptor, __ATOMIC_RELAXED);
        return ret;
    }

    reset_clock_frequency(timepoint, tsc, *time_usec);
    reset_expiration(timepoint, RDTSC_RECALIBRATION_INTERVAL);
    fast_clock_desc_t next_desc = advance_state(descriptor, FC_STATE_RDTSC, false);
    desc_atomic_store(fast_clock, next_desc, __ATOMIC_RELEASE);

    return ret;
}