#ifndef _LINUX_UTILS_H
#define _LINUX_UTILS_H

#include <linux/time.h>
#include <linux/un.h>
#include <stddef.h>
#include <stdint.h>
#include <stdnoreturn.h>

double get_bogomips_from_cpuinfo_buf(const char* buf);
double sanitize_bogomips_value(double);

char* get_main_exec_path(void);

/* Usable only for blocking FDs */
int read_all(int fd, void* buf, size_t size);
int write_all(int fd, const void* buf, size_t size);

/* Not suitable for `/proc/` files (uses `lseek` to determine file size) */
int read_text_file_to_cstr(const char* path, char** out);

/* Iterate over a text file line by line; suitable for `/proc/` files */
int read_text_file_iter_lines(const char* path, int (*callback)(const char* line, void* arg),
                              void* arg);

/* Represents a parsed line of `/proc/<pid>/maps` */
struct proc_maps_range {
    uintptr_t start;
    uintptr_t end;
    int prot;
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

int get_gramine_unix_socket_addr(uint64_t instance_id, const char* name,
                                 struct sockaddr_un* out_addr);

/* Runs a command in a subprocess (fork + execve), and reads its stdout. */
int run_command(const char* pathname, const char** argv, char* buf, size_t buf_size,
                size_t* out_len);

#endif // _LINUX_UTILS_H
