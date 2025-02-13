#pragma once

#include <asm/stat.h>
#include <linux/time.h>
#include <linux/un.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

#include "pal.h"

char* get_main_exec_path(void);

/* Usable only for blocking FDs */
int read_all(int fd, void* buf, size_t size);
int write_all(int fd, const void* buf, size_t size);

/* Not suitable for `/proc/` files (uses `lseek` to determine file size) */
int read_text_file_to_cstr(const char* path, char** out);

/* Iterates over a text file line by line; suitable for `/proc/` files. To stop iteration early, set
 * `*out_stop` to true. */
int read_text_file_iter_lines(const char* path, int (*callback)(const char* line, void* arg,
                                                                bool* out_stop),
                              void* arg);

/* Represents a parsed line of `/proc/<pid>/maps` */
struct proc_maps_range {
    uintptr_t start;
    uintptr_t end;
    pal_prot_flags_t prot;
    size_t offset;
    const char* name; /* NULL if no name */
};

/* Parse `/proc/<pid>/maps`. Unfortunately, the function is pretty fragile w.r.t. the exact
 * format. */
int parse_proc_maps(const char* path, int (*callback)(struct proc_maps_range* r, void* arg),
                    void* arg);

/* Returns current time + `addend_ns` nanoseconds in `ts`. */
void time_get_now_plus_ns(struct timespec* ts, uint64_t addend_ns);
/* Returns time difference (in nanoseconds) between current time and `ts`. Note that the difference
 * can be negative! */
int64_t time_ns_diff_from_now(struct timespec* ts);

int get_gramine_unix_socket_addr(const char* name, struct sockaddr_un* out_addr);

int file_stat_type(struct stat* stat);

/* copy attr content from POSIX stat struct to PAL_STREAM_ATTR */
void file_attrcopy(PAL_STREAM_ATTR* attr, struct stat* stat);

int create_reserved_mem_ranges_fd(void* reserved_mem_ranges, size_t reserved_mem_ranges_size);

void probe_stack(size_t pages_count);
