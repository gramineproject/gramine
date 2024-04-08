#include "api.h"
#include "cpu.h"
#include "enclave_ocalls.h"
#include "pal_internal.h"
#include "utils/fast_clock.h"

/**
 * FastClock
 *
 * The purpose of this module is to provide a fast sgx implementation for gettimeofday().
 *    - What this does: avoids OCALL on every gettimeofday() invocation. Given a "ground truth"
 *      timepoint, we can calculate the current time directly inside the enclave.
 *    - What this doesn't do: this solution does *NOT* provide a trusted time implementation.
 *      This still relies on the untrusted host time.
 *
 * In order to calculate the current time inside the enclave, we need the following:
 *   1. t0 - a point in time that all fast clock times will be calculated against.
 *   2. tsc0 - the clock cycle counter for that point in time
 *   3. clock_frequency - how many clock cycles do we have per second. The tsc value is synced
 *      between all cores.
 * Using the above, given the current tsc we can calculate the current time.
 *
 * Note: old SGX enclaves (prior to SGX2) do not support using the `rdtsc` opcode to read the TSC.
 *
 * *** Implementation ***
 *
 * FastClock is implemented as a state machine. This was done since we don't have a good portable
 * way to get the cpu clock frequency. So, our general strategy is to simply "calculate" it, by
 * comparing two timeval values and their corresponding tsc values.
 *
 * The naive way of making this calculation is to take two timepoints during initialization with a
 * "sleep" in between. Instead, we're letting the program run "organically", and using the time
 * that passes between calls to gettimeofday() as our sleep. This means FastClock will perform an
 * OCALL when needed, and calculate the time internally when it can.
 *
 * FastClock has the following states:
 *
 *  INIT┌─►CALIBRATING┌─►RDTSC──►RDTSC_RECALIBRATE─┐
 *      │             │                            │
 *      └─►DISABLED   └────────────────────────────┘
 *
 *   1. INIT - this is the initial state for fast_clock. All calls are OCALLs
 *      a. check if rdtsc() is allowed from sgx within the current enclave (-> DISABLED otherwise)
 *      b. take the initial t0 and tsc0 values used for calibration (-> CALIBRATING)
 *   2. DISABLED - slow path, all calls will be OCALLs
 *   3. CALIBRATING - wait for some time to pass so we can calculate the clock_frequency
 *      a. OCALL to get the current time
 *      b. if "enough" time has passed since t0, we calculate clock_frequency (-> RDTSC)
 *   4. RDTSC - fast path, time calculation is done within the enclave
 *      a. calculate the current time by using clock_frequency, t0 and the tsc value taken within
 *         the enclave.
 *      b. if a "long" time has passed since we last synced with the host, OCALL to get new values
 *         for t0 and tsc0 to reduce divergence (-> RDTSC_RECALIBRATING)
 *   5. RDTSC_RECALIBRATE - similar to CALIBRATING, calculate an updated clock_frequency
 *      a. since we have a previous calculation of clock_frequency, we still use the "fast path" to
 *         calculate the time within the enclave.
 *      b. when enough time has passed to re-calculate the frequency, we OCALL to get a second
 *         "ground truth" and calculate a new clock_frequency (-> RDTSC)
 *
 * *** Thread safety ***
 *
 * As far as multithreading goes, we had the following goals. We wanted the solution to give
 * consistent times between all threads. This means FastClock state can't be thread local, and
 * needs to be thread safe. And since this is a performance optimization, we need this to be
 * lockless (and definitely no OCALLs other than gettimeofday).
 *
 * To achieve the above, we use the following data structures.
 *
 *   1. fast_clock_timepoint - this contains all the internal state needed by FastClock to
 *      calculate the time as discussed above. FastClock internally has *two* timepoints, which
 *      are used in round-robin (alternating).
 *   2. fast_clock_desc - this is read and written to atomically, which is how the lockless
 *      thread safety is implemented. The descriptor contains:
 *      - The current "state" of the FastClock state machine.
 *      - The round-robin index of the timepoint that is currently in use.
 *      - A flag that guards state transitions, in case of concurrent calls only a single thread
 *        should calculate the new timepoint data and transition the state.
 *
 * By using an atomic descriptor and round-robin timepoints, we can make sure only a single thread
 * is changing the timepoint values, and no one can read "intermediate" state. We will only store
 * the new descriptor pointing to the "next" state and timepoint after it's usable.
 *
 * Note: in theory this is not thread safe, as we can have the following -
 *   1. Thread A reads descriptor, starts flow using timepoint #0, then context switch.
 *   2. Some time passes and we transition to timepoint #1.
 *   3. Some more time passes and we transition back to timepoint #0.
 *   4. Thread A wakes up and reads inconsistent state in timepoint #0. At the worst case this might
 *      lead to negative \ max time.
 * In practice this will never happen, since a long time passes between transitioning timepoints.
 */


/**
 * We got these values experimentally (on azure dc#sv3 machines, SGX2 secure compute) -
 *   1. increasing CALIBRATION_TIME beyond 1sec doesn't increase the accuracy of the calculated
 *      clock frequency or times,
 *   2. 120 seconds keeps the time-drift with host time typically in the 50us range, and very rarely
 *      at the 1ms range.
 *
 * Note, time drift can vary, "ground truth" values can be "bad" and offset the calculation. This is
 * true regardless of the numbers we choose or the implementation (as long as we rely on OCALLing to
 * tell the time). The recalibration interval is used to offset this.
 */
#define RDTSC_CALIBRATION_TIME          ((uint64_t)1 * TIME_US_IN_S)
#define RDTSC_RECALIBRATION_INTERVAL    ((uint64_t)120 * TIME_US_IN_S)

typedef enum
{
    FC_STATE_RDTSC,
    FC_STATE_RDTSC_RECALIBRATE,
    FC_STATE_CALIBRATING,
    FC_STATE_INIT,

    FC_STATE_RDTSC_DISABLED,
} fast_clock_state;

fast_clock g_fast_clock = {
    .atomic_descriptor = {
        .state = FC_STATE_INIT,
        .timepoint_index = 0,
        .state_changing = 0,
    },
    .time_points = { [0 ... FC_NUM_TIMEPOINTS-1] = {
        .clock_freq = 0,
        .tsc0 = 0,
        .t0_usec = 0,
        .expiration_usec = 0,
    }}
};


static inline fast_clock_desc advance_state(fast_clock_desc curr, fast_clock_state new_state, bool advance_timepoint)
{
    fast_clock_desc new_descriptor = {
        .state = new_state,
        .timepoint_index = advance_timepoint ? curr.timepoint_index + 1  : curr.timepoint_index,
        .state_changing = 0,
    };
    return new_descriptor;
}

static inline bool is_expired(const fast_clock_timepoint* timepoint, uint64_t now_usec)
{
    return (timepoint->expiration_usec < now_usec);
}

static inline void calc_time(const fast_clock_timepoint* timepoint, uint64_t* time_usec)
{
    uint64_t tsc = get_tsc();
    uint64_t dtsc = tsc - timepoint->tsc0;
    uint64_t dt_usec = (dtsc * TIME_US_IN_S) / timepoint->clock_freq;
    *time_usec = timepoint->t0_usec + dt_usec;
}

static inline void reset_clock_frequency(fast_clock_timepoint* timepoint, uint64_t tsc, uint64_t time_usec)
{
    // calculate clock frequency in Hz
    uint64_t dt_usec = time_usec - timepoint->t0_usec;
    uint64_t dtsc = tsc - timepoint->tsc0;
    timepoint->clock_freq = (dtsc * TIME_US_IN_S) / dt_usec;
}

static inline long reset_timepoint(fast_clock_timepoint* timepoint)
{
    int ret = ocall_gettime(&timepoint->t0_usec, &timepoint->tsc0);
    return ret;
}

static inline void reset_expiration(fast_clock_timepoint* timepoint, uint64_t next_expiration)
{
    timepoint->expiration_usec = timepoint->t0_usec + next_expiration;
}

static inline bool set_change_state_guard(fast_clock* fast_clock, fast_clock_desc descriptor)
{
    if (descriptor.state_changing != 0) {
        return false;
    }

    fast_clock_desc state_change_guard_desc = descriptor;
    state_change_guard_desc.state_changing = 1;
    return __atomic_compare_exchange_n(
        &fast_clock->atomic_descriptor.desc, &descriptor.desc, state_change_guard_desc.desc,
        /*weak=*/false, __ATOMIC_RELAXED, __ATOMIC_RELAXED
    );
}

static inline fast_clock_timepoint* get_timepoint(fast_clock* fast_clock, fast_clock_desc descriptor)
{
    return &fast_clock->time_points[descriptor.timepoint_index];
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
    return ocall_gettime(time_usec, NULL);
}

static int handle_state_init(fast_clock* fast_clock, fast_clock_desc descriptor, uint64_t* time_usec)
{
    if (!set_change_state_guard(fast_clock, descriptor)) {
        return handle_state_rdtsc_disabled(time_usec);
    }

    if (!is_rdtsc_available()) {
        fast_clock_desc next_desc = advance_state(descriptor, FC_STATE_RDTSC_DISABLED, false);
        __atomic_store_n(&fast_clock->atomic_descriptor.desc, next_desc.desc, __ATOMIC_RELAXED);
        return handle_state_rdtsc_disabled(time_usec);
    }

    fast_clock_desc next_desc = advance_state(descriptor, FC_STATE_CALIBRATING, false);
    fast_clock_timepoint* timepoint = get_timepoint(fast_clock, next_desc);
    int ret = reset_timepoint(timepoint);

    // gettimeofday failed - restore descriptor
    if (ret != 0) {
        __atomic_store_n(&fast_clock->atomic_descriptor.desc, descriptor.desc, __ATOMIC_RELAXED);
        return ret;
    }

    // advance state
    reset_expiration(timepoint, RDTSC_CALIBRATION_TIME);
    __atomic_store_n(&fast_clock->atomic_descriptor.desc, next_desc.desc, __ATOMIC_RELEASE);

    // output results from the timepoint
    *time_usec = timepoint->t0_usec;
    return ret;
}

static int handle_state_calibrating(fast_clock* fast_clock, fast_clock_desc descriptor, uint64_t* time_usec)
{
    // all callers in this state will perform an OCALL - no need to set the change_state_guard before OCALLing
    uint64_t tmp_tsc = 0;
    int ret = ocall_gettime(time_usec, &tmp_tsc);
    if (ret != 0) {
        return ret;
    }

    fast_clock_timepoint* timepoint = get_timepoint(fast_clock, descriptor);
    if (!is_expired(timepoint, *time_usec) || !set_change_state_guard(fast_clock, descriptor)) {
        return ret;
    }

    // calculate the clock_freq and advance state
    reset_clock_frequency(timepoint, tmp_tsc, *time_usec);
    reset_expiration(timepoint, RDTSC_RECALIBRATION_INTERVAL);
    fast_clock_desc new_desc = advance_state(descriptor, FC_STATE_RDTSC, false);
    __atomic_store_n(&fast_clock->atomic_descriptor.desc, new_desc.desc, __ATOMIC_RELEASE);

    return ret;
}

static inline int handle_state_rdtsc(fast_clock* fast_clock, fast_clock_desc descriptor, uint64_t* time_usec, bool force_new_timepoint)
{
    fast_clock_timepoint* timepoint = get_timepoint(fast_clock, descriptor);

    // fast path - calculate time with rdtsc
    calc_time(timepoint, time_usec);
    bool should_advance = is_expired(timepoint, *time_usec) || force_new_timepoint;
    if (!should_advance || !set_change_state_guard(fast_clock, descriptor)) {
        return 0;
    }

    // acquire the state_change_guard and prepare the next state (get new ground truth timepoint)
    fast_clock_desc next_desc = advance_state(descriptor, FC_STATE_RDTSC_RECALIBRATE, true);
    fast_clock_timepoint* next_timepoint = get_timepoint(fast_clock, next_desc);

    int ret = reset_timepoint(next_timepoint);
    if (ret != 0) {
        // gettimeofday failed - restore the state_change_guard and return
        __atomic_store_n(&fast_clock->atomic_descriptor.desc, descriptor.desc, __ATOMIC_RELAXED);
        return ret;
    }

    // use current clock freq until RDTSC_CALIBRATE state ends and the new clock_freq can be calculated
    next_timepoint->clock_freq = timepoint->clock_freq;
    reset_expiration(next_timepoint, RDTSC_CALIBRATION_TIME);
    __atomic_store_n(&fast_clock->atomic_descriptor.desc, next_desc.desc, __ATOMIC_RELEASE);

    return ret;
}

static inline int handle_state_rdtsc_recalibrate(fast_clock* fast_clock, fast_clock_desc descriptor, uint64_t* time_usec)
{
    fast_clock_timepoint* timepoint = get_timepoint(fast_clock, descriptor);

    // fast path - calculate time with rdtsc
    calc_time(timepoint, time_usec);
    if (!is_expired(timepoint, *time_usec) || !set_change_state_guard(fast_clock, descriptor)) {
        return 0;
    }

    uint64_t tsc = 0;
    int ret = ocall_gettime(time_usec, &tsc);
    if (ret != 0) {
        __atomic_store_n(&fast_clock->atomic_descriptor.desc, descriptor.desc, __ATOMIC_RELAXED);
        return ret;
    }

    reset_clock_frequency(timepoint, tsc, *time_usec);
    reset_expiration(timepoint, RDTSC_RECALIBRATION_INTERVAL);
    fast_clock_desc next_desc = advance_state(descriptor, FC_STATE_RDTSC, false);
    __atomic_store_n(&fast_clock->atomic_descriptor.desc, next_desc.desc, __ATOMIC_RELEASE);

    return ret;
}

int fast_clock_get_time(fast_clock* fast_clock, uint64_t* time_usec, bool force_new_timepoint)
{
    fast_clock_desc descriptor = {
        .desc = __atomic_load_n(&fast_clock->atomic_descriptor.desc, __ATOMIC_ACQUIRE),
    };
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

bool fast_clock_is_enabled(const fast_clock* fast_clock)
{
    fast_clock_desc descriptor = {
        .desc = __atomic_load_n(&fast_clock->atomic_descriptor.desc, __ATOMIC_RELAXED),
    };
    return (descriptor.state != FC_STATE_RDTSC_DISABLED);
}

void fast_clock_disable(fast_clock* fast_clock)
{
    /* We need to busy-loop until the state change guard is acquired here - since fast-clock
     * might be in the midst of transitioning states. We can't simply store the DISABLED state. */
    fast_clock_desc descriptor;
    do {
        descriptor.desc = __atomic_load_n(&fast_clock->atomic_descriptor.desc, __ATOMIC_ACQUIRE);
    } while(!set_change_state_guard(fast_clock, descriptor));

    fast_clock_desc disabled_desc = advance_state(descriptor, FC_STATE_RDTSC_DISABLED, false);
    __atomic_store_n(&fast_clock->atomic_descriptor.desc, disabled_desc.desc, __ATOMIC_RELEASE);
}
