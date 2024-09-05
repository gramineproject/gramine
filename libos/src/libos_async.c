/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains functions to add asyncronous events triggered by timer.
 */

#include "list.h"
#include "pal.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_pollable_event.h"
#include "libos_thread.h"
#include "libos_utils.h"

DEFINE_LIST(async_event);
struct async_event {
    IDTYPE caller; /* thread installing this event */
    LIST_TYPE(async_event) list;
    LIST_TYPE(async_event) triggered_list;
    void (*callback)(IDTYPE caller, void* arg);
    void* arg;
    PAL_HANDLE object;       /* handle (async IO) to wait on */
    uint64_t expire_time_us; /* alarm/timer to wait on */
};
DEFINE_LISTP(async_event);
static LISTP_TYPE(async_event) async_list;

static int async_worker_shutdown = 0;
static int async_worker_running = 1;

static struct libos_thread* async_worker_thread;
static struct libos_lock async_worker_lock;

/* TODO: use async_worker_thread->pollable_event instead */
static struct libos_pollable_event install_new_event;

/* Threads register async events like alarm(), setitimer(), ioctl(FIOASYNC)
 * using this function. These events are enqueued in async_list and delivered
 * to async worker thread by triggering install_new_event. When event is
 * triggered in async worker thread, the corresponding event's callback with
 * arguments `arg` is called. This callback typically sends a signal to the
 * thread which registered the event (saved in `event->caller`).
 *
 * We distinguish between alarm/timer events and async IO events:
 *   - alarm/timer events set object = NULL and time_us = microseconds
 *     (time_us = 0 cancels all pending alarms/timers).
 *   - async IO events set object = handle and time_us = 0.
 *
 * Function returns remaining usecs for alarm/timer events (same as alarm())
 * or 0 for async IO events. On error, it returns a negated error code.
 */
int64_t install_async_event(PAL_HANDLE object, uint64_t time_us,
                            void (*callback)(IDTYPE caller, void* arg), void* arg) {
    /* if event happens on object, time_us must be zero */
    assert(!object || (object && !time_us));

    uint64_t now_us = 0;
    int ret = PalSystemTimeQuery(&now_us);
    if (ret < 0) {
        return pal_to_unix_errno(ret);
    }

    uint64_t max_prev_expire_time_us = now_us;

    struct async_event* event = malloc(sizeof(struct async_event));
    if (!event) {
        return -ENOMEM;
    }

    event->callback       = callback;
    event->arg            = arg;
    event->caller         = get_cur_tid();
    event->object         = object;
    event->expire_time_us = time_us ? now_us + time_us : 0;

    lock(&async_worker_lock);

    if (callback != &cleanup_thread && !object) {
        /* This is alarm() or setitimer() emulation, treat both according to
         * alarm() syscall semantics: cancel any pending alarm/timer. */
        struct async_event* tmp;
        struct async_event* n;
        LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &async_list, list) {
            if (tmp->expire_time_us) {
                /* this is a pending alarm/timer, cancel it and save its expiration time */
                if (max_prev_expire_time_us < tmp->expire_time_us)
                    max_prev_expire_time_us = tmp->expire_time_us;

                LISTP_DEL(tmp, &async_list, list);
                free(tmp);
            }
        }

        if (!time_us) {
            /* This is alarm(0), we cancelled all pending alarms/timers
             * and user doesn't want to set a new alarm: we are done. */
            free(event);
            unlock(&async_worker_lock);
            return max_prev_expire_time_us - now_us;
        }
    }

    INIT_LIST_HEAD(event, list);
    LISTP_ADD_TAIL(event, &async_list, list);

    unlock(&async_worker_lock);

    log_debug("Installed async event at %lu", now_us);
    set_pollable_event(&install_new_event);
    return max_prev_expire_time_us - now_us;
}

static int libos_async_worker(void* arg) {
    struct libos_thread* self = (struct libos_thread*)arg;
    if (!arg)
        return -1;

    libos_tcb_init();
    set_cur_thread(self);

    log_setprefix(libos_get_tcb());

    /* Assume async worker thread will not drain the stack that PAL provides,
     * so for efficiency we don't swap the stack. */
    log_debug("Async worker thread started");

    /* init `pals` so that it always contains at least install_new_event */
    size_t pals_max_cnt = 32;
    PAL_HANDLE* pals = malloc(sizeof(*pals) * (1 + pals_max_cnt));
    if (!pals) {
        log_error("Allocation of pals failed");
        goto out_err;
    }

    /* allocate one memory region to hold two pal_wait_flags_t arrays: events and revents */
    pal_wait_flags_t* pal_events = malloc(sizeof(*pal_events) * (1 + pals_max_cnt) * 2);
    if (!pal_events) {
        log_error("Allocation of pal_events failed");
        goto out_err;
    }
    pal_wait_flags_t* ret_events = pal_events + 1 + pals_max_cnt;

    PAL_HANDLE install_new_event_pal = install_new_event.read_handle;
    pals[0] = install_new_event_pal;
    pal_events[0] = PAL_WAIT_READ;
    ret_events[0] = 0;

    while (!__atomic_load_n(&async_worker_shutdown, __ATOMIC_ACQUIRE)) {
        uint64_t now_us = 0;
        int ret = PalSystemTimeQuery(&now_us);
        if (ret < 0) {
            log_error("PalSystemTimeQuery failed with: %s", pal_strerror(ret));
            ret = pal_to_unix_errno(ret);
            goto out_err;
        }

        lock(&async_worker_lock);

        uint64_t next_expire_time_us = 0;
        size_t pals_cnt = 0;

        struct async_event* tmp;
        struct async_event* n;
        LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &async_list, list) {
            /* repopulate `pals` with IO events and find the next expiring alarm/timer */
            if (tmp->object) {
                if (pals_cnt == pals_max_cnt) {
                    /* grow `pals` to accommodate more objects */
                    PAL_HANDLE* tmp_pals = malloc(sizeof(*tmp_pals) * (1 + pals_max_cnt * 2));
                    if (!tmp_pals) {
                        log_error("tmp_pals allocation failed");
                        goto out_err_unlock;
                    }
                    pal_wait_flags_t* tmp_pal_events =
                        malloc(sizeof(*tmp_pal_events) * (2 + pals_max_cnt * 4));
                    if (!tmp_pal_events) {
                        log_error("tmp_pal_events allocation failed");
                        goto out_err_unlock;
                    }
                    pal_wait_flags_t* tmp_ret_events = tmp_pal_events + 1 + pals_max_cnt * 2;

                    memcpy(tmp_pals, pals, sizeof(*tmp_pals) * (1 + pals_max_cnt));
                    memcpy(tmp_pal_events, pal_events,
                           sizeof(*tmp_pal_events) * (1 + pals_max_cnt));
                    memcpy(tmp_ret_events, ret_events,
                           sizeof(*tmp_ret_events) * (1 + pals_max_cnt));

                    pals_max_cnt *= 2;

                    free(pals);
                    free(pal_events);

                    pals = tmp_pals;
                    pal_events = tmp_pal_events;
                    ret_events = tmp_ret_events;
                }

                pals[pals_cnt + 1]       = tmp->object;
                pal_events[pals_cnt + 1] = PAL_WAIT_READ;
                ret_events[pals_cnt + 1] = 0;
                pals_cnt++;
            } else if (tmp->expire_time_us && tmp->expire_time_us > now_us) {
                if (!next_expire_time_us || next_expire_time_us > tmp->expire_time_us) {
                    /* use time of the next expiring alarm/timer */
                    next_expire_time_us = tmp->expire_time_us;
                }
            }
        }

        bool inf_sleep = false;
        uint64_t sleep_time_us;
        if (next_expire_time_us) {
            sleep_time_us  = next_expire_time_us - now_us;
        } else {
            inf_sleep = true;
        }

        unlock(&async_worker_lock);

        /* wait on async IO events + install_new_event + next expiring alarm/timer */
        ret = PalStreamsWaitEvents(pals_cnt + 1, pals, pal_events, ret_events,
                                   inf_sleep ? NULL : &sleep_time_us);
        if (ret < 0 && ret != PAL_ERROR_INTERRUPTED && ret != PAL_ERROR_TRYAGAIN) {
            log_error("PalStreamsWaitEvents failed with: %s", pal_strerror(ret));
            ret = pal_to_unix_errno(ret);
            goto out_err;
        }
        bool polled = ret == 0;

        ret = PalSystemTimeQuery(&now_us);
        if (ret < 0) {
            log_error("PalSystemTimeQuery failed with: %s", pal_strerror(ret));
            ret = pal_to_unix_errno(ret);
            goto out_err;
        }

        LISTP_TYPE(async_event) triggered;
        INIT_LISTP(&triggered);

        /* acquire lock because we read/modify async_list below */
        lock(&async_worker_lock);

        for (size_t i = 0; polled && i < pals_cnt + 1; i++) {
            if (ret_events[i]) {
                if (pals[i] == install_new_event_pal) {
                    /* some thread wants to install new event; this event is found in async_list,
                     * so just re-init install_new_event */
                    clear_pollable_event(&install_new_event);
                    continue;
                }

                /* check if this event is an IO event found in async_list */
                LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &async_list, list) {
                    if (tmp->object == pals[i]) {
                        log_debug("Async IO event triggered at %lu", now_us);
                        LISTP_ADD_TAIL(tmp, &triggered, triggered_list);
                        break;
                    }
                }
            }
        }

        /* check if exit-child or alarm/timer events were triggered */
        LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &async_list, list) {
            if (tmp->callback == &cleanup_thread) {
                log_debug("Thread exited, cleaning up");
                LISTP_DEL(tmp, &async_list, list);
                LISTP_ADD_TAIL(tmp, &triggered, triggered_list);
            } else if (tmp->expire_time_us && tmp->expire_time_us <= now_us) {
                log_debug("Alarm/timer triggered at %lu (expired at %lu)",
                          now_us, tmp->expire_time_us);
                LISTP_DEL(tmp, &async_list, list);
                LISTP_ADD_TAIL(tmp, &triggered, triggered_list);
            }
        }

        unlock(&async_worker_lock);

        /* call callbacks for all triggered events */
        if (!LISTP_EMPTY(&triggered)) {
            LISTP_FOR_EACH_ENTRY_SAFE(tmp, n, &triggered, triggered_list) {
                LISTP_DEL(tmp, &triggered, triggered_list);
                tmp->callback(tmp->caller, tmp->arg);
                if (!tmp->object) {
                    /* this is a one-off exit-child or alarm/timer event */
                    free(tmp);
                }
            }
        }
    }

    log_debug("Async worker thread terminated");

    free(pals);
    free(pal_events);

    PalThreadExit(&async_worker_running);
    /* UNREACHABLE */

out_err_unlock:
    unlock(&async_worker_lock);
out_err:
    log_error("Terminating the process due to a fatal error in async worker");
    PalProcessExit(1);
}

int init_async_worker(void) {
    /* early enough in init, can write global vars without the lock */
    if (!create_lock(&async_worker_lock)) {
        return -ENOMEM;
    }
    int ret = create_pollable_event(&install_new_event);
    if (ret < 0) {
        return ret;
    }

    struct libos_thread* new = get_new_internal_thread();
    if (!new)
        return -ENOMEM;

    PAL_HANDLE handle = NULL;
    ret = PalThreadCreate(libos_async_worker, new, &handle);

    if (ret < 0) {
        put_thread(new);
        return pal_to_unix_errno(ret);
    }

    new->pal_handle = handle;
    async_worker_thread = new;
    return 0;
}

void terminate_async_worker(void) {
    __atomic_store_n(&async_worker_shutdown, 1, __ATOMIC_RELEASE);
    /* force wake up of async worker thread so that it exits */
    set_pollable_event(&install_new_event);

    while (__atomic_load_n(&async_worker_running, __ATOMIC_ACQUIRE)) {
        CPU_RELAX();
    }

    /* no need to clean up resources, as this function is called at process exit */
}
