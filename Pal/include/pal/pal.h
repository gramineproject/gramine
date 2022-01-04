/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*!
 * \file pal.h
 * \brief This file contains definition of PAL host ABI.
 */

#ifndef PAL_H
#define PAL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

#if defined(__i386__) || defined(__x86_64__)
#include "cpu.h"
#endif

/* TODO: we should `#include "toml.h"` here. However, this is currently inconvenient to do in Meson,
 * because `toml.h` is a generated (patched) file, and all targets built using `pal.h` would need to
 * declare a dependency on it. */
typedef struct toml_table_t toml_table_t;

typedef uint64_t    PAL_NUM; /*!< a number */
typedef void*       PAL_PTR; /*!< a pointer to memory or buffer (something other than string) */
typedef uint32_t    PAL_IDX; /*!< an index */

/* maximum length of pipe/FIFO name (should be less than Linux sockaddr_un.sun_path = 108) */
#define PIPE_NAME_MAX 96

/* maximum length of URIs */
#define URI_MAX 4096

#ifdef IN_PAL
#include "atomic.h"
typedef struct atomic_int PAL_REF;

typedef struct {
    PAL_IDX type;
    uint32_t flags;
} PAL_HDR;

#include "pal_host.h"

#ifndef HANDLE_HDR
#define HANDLE_HDR(handle) (&((handle)->hdr))
#endif

static inline void init_handle_hdr(PAL_HDR* hdr, int pal_type) {
    hdr->type  = pal_type;
    hdr->flags = 0;
}

#else
typedef union pal_handle {
    struct {
        PAL_IDX type;
        /* the PAL-level reference counting is deprecated */
    } hdr;
}* PAL_HANDLE;

#ifndef HANDLE_HDR
#define HANDLE_HDR(handle) (&((handle)->hdr))
#endif

#endif /* !IN_PAL */

#include "pal-arch.h"

/********** PAL TYPE DEFINITIONS **********/
enum {
    PAL_TYPE_FILE,
    PAL_TYPE_PIPE,
    PAL_TYPE_PIPESRV,
    PAL_TYPE_PIPECLI,
    PAL_TYPE_DEV,
    PAL_TYPE_DIR,
    PAL_TYPE_TCP,
    PAL_TYPE_TCPSRV,
    PAL_TYPE_UDP,
    PAL_TYPE_UDPSRV,
    PAL_TYPE_PROCESS,
    PAL_TYPE_THREAD,
    PAL_TYPE_EVENT,
    PAL_TYPE_EVENTFD,
    PAL_HANDLE_TYPE_BOUND,
};

#define PAL_IDX_POISON         ((PAL_IDX)-1) /* PAL identifier poison value */
#define PAL_GET_TYPE(h)        (HANDLE_HDR(h)->type)
#define UNKNOWN_HANDLE(handle) (PAL_GET_TYPE(handle) >= PAL_HANDLE_TYPE_BOUND)

typedef struct PAL_PTR_RANGE_ {
    PAL_PTR start, end;
} PAL_PTR_RANGE;

typedef struct PAL_MEM_INFO_ {
    PAL_NUM mem_total;
} PAL_MEM_INFO;

/********** PAL APIs **********/

/* Part of PAL state which is shared between all PALs and accessible (read-only) by the binary
 * started by PAL (usually our LibOS). */
struct pal_public_state {
    const char* host_type;

    /*
     * Handles and executables
     */

    toml_table_t* manifest_root; /*!< program manifest */
    PAL_HANDLE parent_process;   /*!< handle of parent process */
    PAL_HANDLE first_thread;     /*!< handle of first thread */
    int log_level;               /*!< what log messages to enable */

    /*
     * Memory layout
     */
    bool disable_aslr;          /*!< disable ASLR (may be necessary for restricted environments) */
    PAL_PTR_RANGE user_address; /*!< The range of user addresses */

    struct {
        uintptr_t start;
        uintptr_t end;
        const char* comment;
    }* preloaded_ranges; /*!< array of memory ranges which are preoccupied */
    size_t preloaded_ranges_cnt;

    /*
     * Host information
     */

    /*!
     * \brief Host allocation alignment.
     *
     * This currently is (and most likely will always be) indistinguishable from the page size,
     * looking from the LibOS perspective. The two values can be different on the PAL level though,
     * see e.g. SYSTEM_INFO::dwAllocationGranularity on Windows.
     */
    PAL_NUM alloc_align;

    PAL_CPU_INFO cpu_info; /*!< CPU information (only required ones) */
    PAL_MEM_INFO mem_info; /*!< memory information (only required ones) */
    PAL_TOPO_INFO topo_info; /*!< Topology information (only required ones) */
    bool enable_sysfs_topology;
};

const struct pal_public_state* DkGetPalPublicState(void);

/*
 * MEMORY ALLOCATION
 */

/*! memory allocation flags */
typedef uint32_t pal_alloc_flags_t; /* bitfield */
#define PAL_ALLOC_RESERVE  0x1 /*!< Only reserve the memory */
#define PAL_ALLOC_INTERNAL 0x2 /*!< Allocate for PAL (valid only if #IN_PAL) */
#define PAL_ALLOC_MASK     0x3

/*! memory protection flags */
typedef uint32_t pal_prot_flags_t; /* bitfield */
#define PAL_PROT_READ      0x1
#define PAL_PROT_WRITE     0x2
#define PAL_PROT_EXEC      0x4
#define PAL_PROT_WRITECOPY 0x8
#define PAL_PROT_MASK      0xF

/*!
 * \brief Allocate virtual memory for the library OS and zero it out.
 *
 * \param[in,out] addr
 *  `*addr` can be any valid address aligned at the allocation alignment or `NULL`, in which case
 *  a suitable address will be picked automatically. Any memory previously allocated at the same
 *  address will be discarded (only if `*addr` was provided). Overwriting any part of PAL memory is
 *  forbidden. On successful return `*addr` will contain the allocated address (which can differ
 *  only in the `NULL` case).
 * \param size must be a positive number, aligned at the allocation alignment.
 * \param alloc_type a combination of any of the `PAL_ALLOC_*` flags
 * \param prot a combination of the `PAL_PROT_*` flags
 */
int DkVirtualMemoryAlloc(PAL_PTR* addr, PAL_NUM size, pal_alloc_flags_t alloc_type,
                         pal_prot_flags_t prot);

/*!
 * \brief This API deallocates a previously allocated memory mapping.
 *
 * \param addr the address
 * \param size the size
 *
 * Both `addr` and `size` must be non-zero and aligned at the allocation alignment.
 */
int DkVirtualMemoryFree(PAL_PTR addr, PAL_NUM size);

/*!
 * \brief Modify the permissions of a previously allocated memory mapping.
 *
 * \param addr the address
 * \param size the size
 * \param prot see #DkVirtualMemoryAlloc
 *
 * Both `addr` and `size` must be non-zero and aligned at the allocation alignment.
 */
int DkVirtualMemoryProtect(PAL_PTR addr, PAL_NUM size, pal_prot_flags_t prot);

/*
 * PROCESS CREATION
 */

/*!
 * \brief Create a new process.
 *
 * \param args an array of strings -- the arguments to be passed to the new process.
 * \param[out] handle on success contains the process handle.
 *
 * Loads and executes the same binary as currently executed one (`loader.entrypoint`), and passes
 * the new arguments.
 *
 * TODO: `args` is only used by PAL regression tests, and should be removed at some point.
 */
int DkProcessCreate(const char** args, PAL_HANDLE* handle);

/*!
 * \brief Terminate all threads in the process immediately.
 *
 * \param exit_code the exit value returned to the host.
 */
noreturn void DkProcessExit(PAL_NUM exit_code);

/*
 * STREAMS
 */

/*! Stream Access Flags */
enum pal_access {
    PAL_ACCESS_RDONLY,
    PAL_ACCESS_WRONLY,
    PAL_ACCESS_RDWR,
    PAL_ACCESS_BOUND,
};

/*! stream sharing flags */
// FIXME: These flags currently must correspond 1-1 to Linux flags, which is totally unportable.
//        They should be redesigned when we'll be rewriting the filesystem layer.
typedef uint32_t pal_share_flags_t; /* bitfield */
#define PAL_SHARE_GLOBAL_X    01
#define PAL_SHARE_GLOBAL_W    02
#define PAL_SHARE_GLOBAL_R    04
#define PAL_SHARE_GROUP_X    010
#define PAL_SHARE_GROUP_W    020
#define PAL_SHARE_GROUP_R    040
#define PAL_SHARE_OWNER_X   0100
#define PAL_SHARE_OWNER_W   0200
#define PAL_SHARE_OWNER_R   0400
#define PAL_SHARE_STICKY   01000
#define PAL_SHARE_SET_GID  02000
#define PAL_SHARE_SET_UID  04000
#define PAL_SHARE_MASK     07777

/*! stream create mode */
enum pal_create_mode {
    PAL_CREATE_NEVER,     /*!< Fail if file does not exist */
    PAL_CREATE_TRY,       /*!< Create file if file does not exist */
    PAL_CREATE_ALWAYS,    /*!< Create file and fail if file already exists */
    PAL_CREATE_IGNORED,   /*!< Magic value for calls to handle types which ignore creation mode */
};

/*! stream misc flags */
typedef uint32_t pal_stream_options_t; /* bitfield */
#define PAL_OPTION_CLOEXEC         1
#define PAL_OPTION_EFD_SEMAPHORE   2 /*!< specific to `eventfd` syscall */
#define PAL_OPTION_NONBLOCK        4
#define PAL_OPTION_DUALSTACK       8 /*!< Create dual-stack socket (opposite of IPV6_V6ONLY) */
#define PAL_OPTION_MASK          0xF

/*!
 * \brief Open/create a stream resource specified by `uri`
 *
 * \param uri         is the URI of the stream to be opened/created
 * \param access      see #pal_access
 * \param share_flags a combination of the `PAL_SHARE_*` flags
 * \param create      see #pal_create_mode
 * \param options     a combination of the `PAL_OPTION_*` flags
 * \param handle[out] if the resource is successfully opened or created, a PAL handle is returned
 *                    in `*handle` for further access such as reading or writing.
 *
 * \return 0 on success, negative error code on failure.
 *
 * Supported URI types:
 * * `%file:...`, `dir:...`: Files or directories on the host file system. If #PAL_CREATE_TRY or
 *   #PAL_CREATE_ALWAYS is given in `create` flags, the file/directory will be created.
 * * `dev:...`: Open a device as a stream. For example, `dev:tty` represents the standard I/O.
 * * `pipe.srv:<name>`, `pipe:<name>`, `pipe:`: Open a byte stream that can be used for RPC between
 *   processes. The server side of a pipe can accept any number of connections. If `pipe:` is given
 *   as the URI (i.e., without a name), it will open an anonymous bidirectional pipe.
 * * `tcp.srv:<ADDR>:<PORT>`, `tcp:<ADDR>:<PORT>`: Open a TCP socket to listen or connect to
 *   a remote TCP socket.
 * * `udp.srv:<ADDR>:<PORT>`, `udp:<ADDR>:<PORT>`: Open a UDP socket to listen or connect to
 *   a remote UDP socket.
 */
int DkStreamOpen(const char* uri, enum pal_access access, pal_share_flags_t share_flags,
                 enum pal_create_mode create, pal_stream_options_t options, PAL_HANDLE* handle);

/*!
 * \brief Blocks until a new connection is accepted and returns the PAL handle for the connection.
 *
 * \param handle handle to accept a new connection on.
 * \param[out] client on success holds handle for the new connection.
 * \param options flags to set on \p client handle.
 *
 * This API is only available for handles that are opened with `pipe.srv:...`, `tcp.srv:...`, and
 * `udp.srv:...`.
 */
int DkStreamWaitForClient(PAL_HANDLE handle, PAL_HANDLE* client, pal_stream_options_t options);

/*!
 * \brief Read data from an open stream.
 *
 * \param handle handle to the stream.
 * \param offset offset to read at. If \p handle is a file, \p offset must be specified at each
 *               call.
 * \param[in,out] count on function call should contain the size of \p buffer. On successful return
 *                contains the number of bytes read.
 * \param buffer pointer to the buffer to read into.
 * \param[out] source if \p handle is a UDP socket, \p size is not zero and \p source is not NULL,
 *             the remote socket address is returned in it.
 * \param size size of the \p source buffer.
 *
 * \return 0 on success, negative error code on failure.
 *
 * If \p handle is a directory, DkStreamRead fills the buffer with the null-terminated names of the
 * directory entries.
 */
int DkStreamRead(PAL_HANDLE handle, PAL_NUM offset, PAL_NUM* count, void* buffer, char* source,
                 PAL_NUM size);

/*!
 * \brief Write data to an open stream.
 *
 * \param handle handle to the stream.
 * \param offset offset to write to. If \p handle is a file, \p offset must be specified at each
 *               call.
 * \param[in,out] count on function call should contain the size of \p buffer. On successful return
 *                contains the number of bytes written.
 * \param buffer pointer to the buffer to write from.
 * \param dest if the handle is a UDP socket, specifies the remote socket address.
 *
 * \return 0 on success, negative error code on failure.
 */
int DkStreamWrite(PAL_HANDLE handle, PAL_NUM offset, PAL_NUM* count, void* buffer,
                  const char* dest);

enum pal_delete_mode {
    PAL_DELETE_ALL,  /*!< delete the whole resource / shut down both directions */
    PAL_DELETE_READ,  /*!< shut down the read side only */
    PAL_DELETE_WRITE, /*!< shut down the write side only */
};

/*!
 * \brief Delete files or directories on the host or shut down the connection of TCP/UDP sockets.
 *
 * \param access which side to shut down (see #pal_delete_mode values)
 */
int DkStreamDelete(PAL_HANDLE handle, enum pal_delete_mode delete_mode);

/*!
 * \brief Map a file to a virtual memory address in the current process.
 *
 * \param handle handle to the stream to be mapped.
 * \param[in,out] addr see #DkVirtualMemoryAlloc
 * \param prot see #DkVirtualMemoryAlloc
 * \param offset offset in the stream to be mapped. Must be properly aligned.
 * \param size size of the requested mapping. Must be non-zero and properly aligned.
 *
 * \return 0 on success, negative error code on failure.
 */
int DkStreamMap(PAL_HANDLE handle, PAL_PTR* addr, pal_prot_flags_t prot, PAL_NUM offset,
                PAL_NUM size);

/*!
 * \brief Unmap virtual memory that is backed by a file stream.
 *
 * `addr` and `size` must be aligned at the allocation alignment
 *
 * \return 0 on success, negative error code on failure.
 */
int DkStreamUnmap(PAL_PTR addr, PAL_NUM size);

/*!
 * \brief Set the length of the file referenced by handle to `length`.
 *
 * \return 0 on success, negative error code on failure.
 */
int DkStreamSetLength(PAL_HANDLE handle, PAL_NUM length);

/*!
 * \brief Flush the buffer of a file stream.
 *
 * \return 0 on success, negative error code on failure.
 */
int DkStreamFlush(PAL_HANDLE handle);

/*!
 * \brief Send a PAL handle over another handle.
 *
 * Currently, the handle that is used to send cargo must be a process handle.
 *
 * \param cargo the handle being sent
 *
 * \return 0 on success, negative error code on failure.
 */
int DkSendHandle(PAL_HANDLE handle, PAL_HANDLE cargo);

/*!
 * \brief This API receives a handle over another handle.
 *
 * TODO: document usage and parameters.
 *
 * \return 0 on success, negative error code on failure.
 */
int DkReceiveHandle(PAL_HANDLE handle, PAL_HANDLE* cargo);

/* stream attribute structure */
typedef struct _PAL_STREAM_ATTR {
    PAL_IDX handle_type;
    bool disconnected;
    bool nonblocking;
    bool readable, writable, runnable;
    pal_share_flags_t share_flags;
    PAL_NUM pending_size;
    union {
        struct {
            PAL_NUM linger;
            PAL_NUM receivebuf, sendbuf;
            PAL_NUM receivetimeout, sendtimeout;
            bool tcp_cork;
            bool tcp_keepalive;
            bool tcp_nodelay;
        } socket;
    };
} PAL_STREAM_ATTR;

/*!
 * \brief Query the attributes of a named stream.
 *
 * This API only applies for URIs such as `%file:...`, `dir:...`, and `dev:...`.
 */
int DkStreamAttributesQuery(const char* uri, PAL_STREAM_ATTR* attr);

/*!
 * \brief Query the attributes of an open stream.
 *
 * This API applies to any stream handle.
 */
int DkStreamAttributesQueryByHandle(PAL_HANDLE handle, PAL_STREAM_ATTR* attr);

/*!
 * \brief Set the attributes of an open stream.
 */
int DkStreamAttributesSetByHandle(PAL_HANDLE handle, PAL_STREAM_ATTR* attr);

/*!
 * \brief Query the name of an open stream. On success `buffer` contains a null-terminated string.
 */
int DkStreamGetName(PAL_HANDLE handle, char* buffer, PAL_NUM size);

/*!
 * \brief This API changes the name of an open stream.
 */
int DkStreamChangeName(PAL_HANDLE handle, const char* uri);

/*
 * Thread creation
 */

/*!
 * \brief Create a thread in the current process.
 *
 * \param addr is the address of an entry point of execution for the new thread
 * \param param is the pointer argument that is passed to the new thread
 * \param[out] handle on success contains the thread handle
 */
int DkThreadCreate(int (*callback)(void*), void* param, PAL_HANDLE* handle);

/*!
 * \brief Yield the current thread such that the host scheduler can reschedule it.
 */
void DkThreadYieldExecution(void);

/*!
 * \brief Terminate the current thread.
 *
 * \param clear_child_tid is the pointer to memory that is erased on thread exit
 *  to notify LibOS (which in turn notifies the parent thread if any); if
 *  `clear_child_tid` is NULL, then PAL doesn't do the clearing.
 */
noreturn void DkThreadExit(int* clear_child_tid);

/*!
 * \brief Resume a thread.
 */
int DkThreadResume(PAL_HANDLE thread);

/*!
 * \brief Sets the CPU affinity of a thread.
 *
 * All bit positions exceeding the count of host CPUs are ignored. Returns an error if no CPUs were
 * selected.
 *
 * \param thread PAL thread for which to set the CPU affinity.
 * \param cpumask_size size in bytes of the bitmask pointed by \a cpu_mask.
 * \param cpu_mask pointer to the new CPU mask.
 *
 * \return Returns 0 on success, negative error code on failure.
 */
int DkThreadSetCpuAffinity(PAL_HANDLE thread, PAL_NUM cpumask_size, unsigned long* cpu_mask);

/*!
 * \brief Gets the CPU affinity of a thread.
 *
 * This function assumes that \a cpumask_size is valid and greater than 0. Also, \a cpumask_size
 * must be able to fit all the processors in the host and must be aligned by sizeof(long). For
 * example, if the host supports 4 CPUs, \a cpumask_size should be 8 bytes.
 *
 * \param thread PAL thread for which to get the CPU affinity.
 * \param cpumask_size size in bytes of the bitmask pointed by \a cpu_mask.
 * \param cpu_mask pointer to hold the current CPU mask.
 *
 * \return Returns 0 on success, negative error code on failure.
 */
int DkThreadGetCpuAffinity(PAL_HANDLE thread, PAL_NUM cpumask_size, unsigned long* cpu_mask);

/*
 * Exception Handling
 */

/* These values are used as indices in an array of PAL_EVENT_NUM_BOUND elements, be careful when
 * changing them. */
enum pal_event {
    /*! pseudo event, used in some APIs to denote a lack of event */
    PAL_EVENT_NO_EVENT,
    /*! arithmetic error (div-by-zero, floating point exception, etc.) */
    PAL_EVENT_ARITHMETIC_ERROR,
    /*! segmentation fault, protection fault, bus fault */
    PAL_EVENT_MEMFAULT,
    /*! illegal instructions */
    PAL_EVENT_ILLEGAL,
    /*! terminated by external program (see "sys.enable_sigterm_injection" manifest option) */
    PAL_EVENT_QUIT,
    /*! interrupted (usually internally to handle aync event) */
    PAL_EVENT_INTERRUPTED,

    PAL_EVENT_NUM_BOUND,
};

/*!
 * \brief Type of exception handlers (upcalls).
 *
 * \param is_in_pal `true` if the exception happened inside PAL
 * \param addr address of the exception (meaningful only for sync exceptions)
 * \param context CPU context at the moment of exception.
 */
typedef void (*pal_event_handler_t)(bool is_in_pal, PAL_NUM addr, PAL_CONTEXT* context);

/*!
 * \brief Set the handler for the specific exception event.
 *
 * \param event can be one of #pal_event values
 */
void DkSetExceptionHandler(pal_event_handler_t handler, enum pal_event event);

/*
 * Synchronization
 */

/*!
 * \brief Create an event handle
 *
 * \param[out] handle on success `*handle` contains pointer to the event handle
 * \param init_signaled initial state of the event (`true` - set, `false` - not set)
 * \param auto_clear `true` if a successful wait for the event should also reset (consume) it
 *
 * Creates a handle to an event that resembles WinAPI synchronization events. A thread can set
 * (signal) the event using #DkEventSet, clear (unset) it using #DkEventClear or wait until
 * the event becomes set (signaled) using #DkEventWait.
 */
int DkEventCreate(PAL_HANDLE* handle, bool init_signaled, bool auto_clear);

/*!
 * \brief Set (signal) an event.
 *
 * If the event is already set, does nothing.
 *
 * This function has release semantics and synchronizes with #DkEventWait.
 */
void DkEventSet(PAL_HANDLE handle);

/*!
 * \brief Clear (unset) an event.
 *
 * If the event is not set, does nothing.
 */
void DkEventClear(PAL_HANDLE handle);

/*! block until the handle's event is triggered */
#define NO_TIMEOUT ((PAL_NUM)-1)

/*!
 * \brief Wait for an event handle.
 *
 * \param handle handle to wait on, must be of "event" type
 * \param[in,out] timeout_us timeout for the wait
 *
 * \return 0 if the event was triggered, negative error code otherwise (#PAL_ERROR_TRYAGAIN in case
 *         of timeout triggering)
 *
 * \p timeout_us points to a value that specifies the maximal time (in microseconds) that this
 * function should sleep if this event is not signaled in the meantime. Specifying `NULL` blocks
 * indefinitely. Note that in any case this function can return earlier, e.g. if a signal has
 * arrived, but this will be indicated by the returned error code.
 * After returning (both successful and not), \p timeout_us will contain the remaining time (time
 * that need to pass before we hit original \p timeout_us).
 *
 * This function has acquire semantics and synchronizes with #DkEventSet.
 */
int DkEventWait(PAL_HANDLE handle, uint64_t* timeout_us);

typedef uint32_t pal_wait_flags_t; /* bitfield */
#define PAL_WAIT_READ   1
#define PAL_WAIT_WRITE  2
#define PAL_WAIT_ERROR  4 /*!< ignored in events */

/*!
 * \brief Poll
 *
 * \param count the number of items in the array
 * \param handle_array
 * \param events user-defined events
 * \param[out] ret_events polled-handles' events in `ret_events`
 * \param timeout_us is the maximum time that the API should wait (in
 *  microseconds), or `NO_TIMEOUT` to indicate it is to be blocked until at
 *  least one handle is ready.
 * \return 0 if there was an event on at least one handle, negative error code otherwise
 */
int DkStreamsWaitEvents(PAL_NUM count, PAL_HANDLE* handle_array, pal_wait_flags_t* events,
                        pal_wait_flags_t* ret_events, PAL_NUM timeout_us);

/*!
 * \brief Close (deallocate) a PAL handle.
 */
void DkObjectClose(PAL_HANDLE object_handle);

/*
 * MISC
 */

/*!
 * \brief Output a message to the debug stream.
 *
 * \param buffer message to write.
 * \param[in] size \p buffer size.
 *
 * \return 0 on success, negative error code on failure.
 */
int DkDebugLog(const void* buffer, PAL_NUM size);

/*!
 * \brief Get the current time
 *
 * \param[out] time on success holds the current time in microseconds
 */
int DkSystemTimeQuery(PAL_NUM* time);

/*!
 * \brief Cryptographically secure random.
 *
 * \param[out] buffer is filled with cryptographically-secure random values
 * \param[in] size buffer size
 * \return 0 on success, negative on failure
 */
int DkRandomBitsRead(void* buffer, PAL_NUM size);

enum pal_segment_reg {
    PAL_SEGMENT_FS,
    PAL_SEGMENT_GS,
};

/*!
 * \brief Get segment register base
 *
 * \param reg the register base to get (#pal_segment_reg)
 * \param addr the address where result will be stored
 *
 * \return 0 on success, negative error value on failure
 */
int DkSegmentBaseGet(enum pal_segment_reg reg, uintptr_t* addr);

/*!
 * \brief Set segment register
 *
 * \param reg the register base to be set (#pal_segment_reg)
 * \param addr the address to be set
 *
 * \return 0 on success, negative error value on failure
 */
int DkSegmentBaseSet(enum pal_segment_reg reg, uintptr_t addr);

/*!
 * \brief Return the amount of currently available memory for LibOS/application
 * usage.
 */
PAL_NUM DkMemoryAvailableQuota(void);

/*!
 * \brief Obtain the attestation report (local) with `user_report_data` embedded into it.
 *
 * Currently works only for Linux-SGX PAL, where `user_report_data` is a blob of exactly 64B,
 * `target_info` is an SGX target_info struct of exactly 512B, and `report` is an SGX report
 * obtained via the EREPORT instruction (exactly 432B). If `target_info` contains all zeros,
 * then this function additionally returns this enclave's target info in `target_info`. Useful
 * for local attestation.
 *
 * The caller may specify `*user_report_data_size`, `*target_info_size`, and `*report_size` as 0
 * and other fields as NULL to get PAL-enforced sizes of these three structs.
 *
 * \param[in]     user_report_data       Report data with arbitrary contents (typically uniquely
 *                                       identifies this Gramine instance). Must be a 64B buffer
 *                                       in case of SGX PAL.
 * \param[in,out] user_report_data_size  Caller specifies size of `user_report_data`; on return,
 *                                       contains PAL-enforced size of `user_report_data` (64B in
 *                                       case of SGX PAL).
 * \param[in,out] target_info            Target info of target enclave for attestation. If it
 *                                       contains all zeros, it is populated with this enclave's
 *                                       target info. Must be a 512B buffer in case of SGX PAL.
 * \param[in,out] target_info_size       Caller specifies size of `target_info`; on return,
 *                                       contains PAL-enforced size of `target_info` (512B in case
 *                                       of SGX PAL).
 * \param[out]    report                 Attestation report with `user_report_data` embedded,
 *                                       targeted for an enclave with provided `target_info`. Must
 *                                       be a 432B buffer in case of SGX PAL.
 * \param[in,out] report_size            Caller specifies size of `report`; on return, contains
 *                                       PAL-enforced size of `report` (432B in case of SGX PAL).
 */
int DkAttestationReport(const void* user_report_data, PAL_NUM* user_report_data_size,
                        void* target_info, PAL_NUM* target_info_size, void* report,
                        PAL_NUM* report_size);

/*!
 * \brief Obtain the attestation quote with `user_report_data` embedded into it.
 *
 * Currently works only for Linux-SGX PAL, where `user_report_data` is a blob of exactly 64B
 * and `quote` is an SGX quote obtained from Quoting Enclave via AESM service.
 *
 * \param[in]     user_report_data       Report data with arbitrary contents (typically uniquely
 *                                       identifies this Gramine instance). Must be a 64B buffer
 *                                       in case of SGX PAL.
 * \param[in]     user_report_data_size  Size in bytes of `user_report_data`. Must be exactly 64B
 *                                       in case of SGX PAL.
 * \param[out]    quote                  Attestation quote with `user_report_data` embedded.
 * \param[in,out] quote_size             Caller specifies maximum size allocated for `quote`; on
 *                                       return, contains actual size of obtained quote.
 */
int DkAttestationQuote(const void* user_report_data, PAL_NUM user_report_data_size, void* quote,
                       PAL_NUM* quote_size);

/*!
 * \brief Set wrap key (master key) for protected files.
 *
 * Currently works only for Linux-SGX PAL. This function is supposed to be called during
 * remote attestation and secret provisioning, before the user application starts.
 *
 * \param[in]     pf_key_hex       Wrap key for protected files. Must be a 32-char null-terminated
 *                                 hex string in case of SGX PAL (AES-GCM encryption key).
 */
int DkSetProtectedFilesKey(const char* pf_key_hex);

#ifdef __GNUC__
#define symbol_version_default(real, name, version) \
    __asm__(".symver " #real "," #name "@@" #version "\n")
#else
#define symbol_version_default(real, name, version)
#endif

#if defined(__i386__) || defined(__x86_64__)
/*!
 * \brief Return CPUID information, based on the leaf/subleaf.
 *
 * \param[out] values the array of the results
 */
int DkCpuIdRetrieve(PAL_IDX leaf, PAL_IDX subleaf, PAL_IDX values[CPUID_WORD_NUM]);
#endif

void DkDebugMapAdd(const char* uri, PAL_PTR start_addr);
void DkDebugMapRemove(PAL_PTR start_addr);

/* Describe the code under given address (see `describe_location()` in `callbacks.h`). Without
 * DEBUG, falls back to raw value ("0x1234"). */
void DkDebugDescribeLocation(uintptr_t addr, char* buf, size_t buf_size);

#endif /* PAL_H */
