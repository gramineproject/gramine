#pragma once

#include "api.h"
#include "assert.h"
#include "gramine_entry_api.h"
#include "libos_entry.h"
#include "libos_tcb_arch.h"
#include "pal.h"

struct libos_context {
    PAL_CONTEXT* regs;
    long syscall_nr;
    uintptr_t tls; /* Used only in clone. */
};

typedef struct libos_tcb libos_tcb_t;
struct libos_tcb {
    libos_tcb_t*         self;

    /* Function pointer for patched code calling into Gramine. */
    void*                libos_syscall_entry;

    struct libos_thread* tp;
    void*                libos_stack_bottom;
    struct libos_context context;
    /* Scratch space to temporarily store a register. On some architectures (e.g. x86_64 inside
     * an SGX enclave) we lack a way to restore all (or at least some) registers atomically. */
    void*                syscall_scratch_pc;
    void*                vma_cache;
    char                 log_prefix[32];
};

static_assert(offsetof(PAL_TCB, libos_tcb) + offsetof(libos_tcb_t, libos_syscall_entry)
                == GRAMINE_SYSCALL_OFFSET, "GRAMINE_SYSCALL_OFFSET must match");

static inline void __libos_tcb_init(libos_tcb_t* libos_tcb) {
    libos_tcb->self = libos_tcb;
    libos_tcb->libos_syscall_entry = &libos_syscall_entry;
    libos_tcb->context.syscall_nr = -1;
    libos_tcb->vma_cache = NULL;
}

/* Call this function at the beginning of thread execution. */
static inline void libos_tcb_init(void) {
    PAL_TCB* tcb = pal_get_tcb();
    static_assert(sizeof(libos_tcb_t) <= sizeof(((PAL_TCB*)0)->libos_tcb),
                  "Not enough space for LibOS TCB inside PAL TCB");
    libos_tcb_t* libos_tcb = (libos_tcb_t*)tcb->libos_tcb;
    memset(libos_tcb, 0, sizeof(*libos_tcb));
    __libos_tcb_init(libos_tcb);
}

static inline libos_tcb_t* libos_get_tcb(void) {
    return LIBOS_TCB_GET(self);
}
