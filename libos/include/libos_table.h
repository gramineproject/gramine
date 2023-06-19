/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#pragma once

#include "libos_types.h"

typedef void (*libos_syscall_t)(void);

extern libos_syscall_t libos_syscall_table[];

/* syscall implementation */
long libos_syscall_read(int fd, void* buf, size_t count);
long libos_syscall_write(int fd, const void* buf, size_t count);
long libos_syscall_open(const char* file, int flags, mode_t mode);
long libos_syscall_close(int fd);
long libos_syscall_stat(const char* file, struct stat* statbuf);
long libos_syscall_fstat(int fd, struct stat* statbuf);
long libos_syscall_lstat(const char* file, struct stat* stat);
long libos_syscall_statfs(const char* path, struct statfs* buf);
long libos_syscall_fstatfs(int fd, struct statfs* buf);
long libos_syscall_poll(struct pollfd* fds, unsigned int nfds, int timeout);
long libos_syscall_lseek(int fd, off_t offset, int origin);
void* libos_syscall_mmap(void* addr, size_t length, int prot, int flags, int fd,
                         unsigned long offset);
long libos_syscall_mprotect(void* addr, size_t len, int prot);
long libos_syscall_munmap(void* addr, size_t len);
void* libos_syscall_brk(void* brk);
long libos_syscall_rt_sigaction(int signum, const struct __kernel_sigaction* act,
                                struct __kernel_sigaction* oldact, size_t sigsetsize);
long libos_syscall_rt_sigprocmask(int how, const __sigset_t* set, __sigset_t* oldset,
                                  size_t sigsetsize);
long libos_syscall_rt_sigreturn(void);
long libos_syscall_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);
long libos_syscall_pread64(int fd, char* buf, size_t count, loff_t pos);
long libos_syscall_pwrite64(int fd, char* buf, size_t count, loff_t pos);
long libos_syscall_readv(unsigned long fd, struct iovec* vec, unsigned long vlen);
long libos_syscall_writev(unsigned long fd, struct iovec* vec, unsigned long vlen);
long libos_syscall_access(const char* file, mode_t mode);
long libos_syscall_pipe(int* fildes);
long libos_syscall_select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* errorfds,
                          struct __kernel_timeval* timeout);
long libos_syscall_sched_yield(void);
long libos_syscall_msync(unsigned long start, size_t len, int flags);
long libos_syscall_mincore(void* start, size_t len, unsigned char* vec);
long libos_syscall_madvise(unsigned long start, size_t len_in, int behavior);
long libos_syscall_dup(unsigned int fd);
long libos_syscall_dup2(unsigned int oldfd, unsigned int newfd);
long libos_syscall_pause(void);
long libos_syscall_nanosleep(struct __kernel_timespec* req, struct __kernel_timespec* rem);
long libos_syscall_getitimer(int which, struct __kernel_itimerval* value);
long libos_syscall_alarm(unsigned int seconds);
long libos_syscall_setitimer(int which, struct __kernel_itimerval* value,
                             struct __kernel_itimerval* ovalue);
long libos_syscall_getpid(void);
long libos_syscall_sendfile(int out_fd, int in_fd, off_t* offset, size_t count);
long libos_syscall_socket(int family, int type, int protocol);
long libos_syscall_connect(int fd, void* addr, int addrlen);
long libos_syscall_accept(int fd, void* addr, int* addrlen);
long libos_syscall_sendto(int fd, void* buf, size_t len, unsigned int flags, void* addr,
                          int addrlen);
long libos_syscall_recvfrom(int fd, void* buf, size_t len, unsigned int flags, void* addr,
                            int* addrlen);
long libos_syscall_bind(int fd, void* addr, int addrlen);
long libos_syscall_listen(int fd, int backlog);
long libos_syscall_sendmsg(int fd, struct msghdr* msg, unsigned int flags);
long libos_syscall_recvmsg(int fd, struct msghdr* msg, unsigned int flags);
long libos_syscall_shutdown(int fd, int how);
long libos_syscall_getsockname(int fd, void* addr, int* addrlen);
long libos_syscall_getpeername(int fd, void* addr, int* addrlen);
long libos_syscall_socketpair(int domain, int type, int protocol, int* sv);
long libos_syscall_setsockopt(int fd, int level, int optname, char* optval, int optlen);
long libos_syscall_getsockopt(int fd, int level, int optname, char* optval, int* optlen);
long libos_syscall_clone(unsigned long flags, unsigned long user_stack_addr, int* parent_tidptr,
                         int* child_tidptr, unsigned long tls);
long libos_syscall_fork(void);
long libos_syscall_vfork(void);
long libos_syscall_execve(const char* file, const char* const* argv, const char* const* envp);
long libos_syscall_exit(int error_code);
long libos_syscall_waitid(int which, pid_t id, siginfo_t* infop, int options,
                          struct __kernel_rusage* ru);
long libos_syscall_wait4(pid_t pid, int* stat_addr, int options, struct __kernel_rusage* ru);
long libos_syscall_kill(pid_t pid, int sig);
long libos_syscall_uname(struct new_utsname* buf);
long libos_syscall_fcntl(int fd, int cmd, unsigned long arg);
long libos_syscall_flock(int fd, unsigned int cmd);
long libos_syscall_fsync(int fd);
long libos_syscall_fdatasync(int fd);
long libos_syscall_truncate(const char* path, loff_t length);
long libos_syscall_ftruncate(int fd, loff_t length);
long libos_syscall_fallocate(int fd, int mode, loff_t offset, loff_t len);
long libos_syscall_getdents(int fd, struct linux_dirent* buf, unsigned int count);
long libos_syscall_getcwd(char* buf, size_t size);
long libos_syscall_chdir(const char* filename);
long libos_syscall_fchdir(int fd);
long libos_syscall_rename(const char* oldname, const char* newname);
long libos_syscall_mkdir(const char* pathname, int mode);
long libos_syscall_rmdir(const char* pathname);
long libos_syscall_creat(const char* path, mode_t mode);
long libos_syscall_unlink(const char* file);
long libos_syscall_readlink(const char* file, char* buf, int bufsize);
long libos_syscall_chmod(const char* filename, mode_t mode);
long libos_syscall_fchmod(int fd, mode_t mode);
long libos_syscall_chown(const char* filename, uid_t user, gid_t group);
long libos_syscall_fchown(int fd, uid_t user, gid_t group);
long libos_syscall_umask(mode_t mask);
long libos_syscall_gettimeofday(struct __kernel_timeval* tv, struct __kernel_timezone* tz);
long libos_syscall_getrlimit(int resource, struct __kernel_rlimit* rlim);
long libos_syscall_getuid(void);
long libos_syscall_getgid(void);
long libos_syscall_setuid(uid_t uid);
long libos_syscall_setgid(gid_t gid);
long libos_syscall_setgroups(int gidsetsize, gid_t* grouplist);
long libos_syscall_getgroups(int gidsetsize, gid_t* grouplist);
long libos_syscall_geteuid(void);
long libos_syscall_getegid(void);
long libos_syscall_getppid(void);
long libos_syscall_setpgid(pid_t pid, pid_t pgid);
long libos_syscall_getpgrp(void);
long libos_syscall_setsid(void);
long libos_syscall_getpgid(pid_t pid);
long libos_syscall_getsid(pid_t pid);
long libos_syscall_rt_sigpending(__sigset_t* set, size_t sigsetsize);
long libos_syscall_rt_sigtimedwait(const __sigset_t* unblocked_ptr, siginfo_t* info,
                                   struct __kernel_timespec* timeout, size_t setsize);
long libos_syscall_sigaltstack(const stack_t* ss, stack_t* oss);
long libos_syscall_setpriority(int which, int who, int niceval);
long libos_syscall_getpriority(int which, int who);
long libos_syscall_sched_setparam(pid_t pid, struct __kernel_sched_param* param);
long libos_syscall_sched_getparam(pid_t pid, struct __kernel_sched_param* param);
long libos_syscall_sched_setscheduler(pid_t pid, int policy, struct __kernel_sched_param* param);
long libos_syscall_sched_getscheduler(pid_t pid);
long libos_syscall_sched_get_priority_max(int policy);
long libos_syscall_sched_get_priority_min(int policy);
long libos_syscall_sched_rr_get_interval(pid_t pid, struct timespec* interval);
long libos_syscall_mlock(unsigned long start, size_t len);
long libos_syscall_munlock(unsigned long start, size_t len);
long libos_syscall_mlockall(int flags);
long libos_syscall_munlockall(void);
long libos_syscall_rt_sigsuspend(const __sigset_t* mask, size_t setsize);
long libos_syscall_arch_prctl(int code, unsigned long addr);
long libos_syscall_setrlimit(int resource, struct __kernel_rlimit* rlim);
long libos_syscall_chroot(const char* filename);
long libos_syscall_sethostname(char* name, int len);
long libos_syscall_setdomainname(char* name, int len);
long libos_syscall_gettid(void);
long libos_syscall_tkill(int pid, int sig);
long libos_syscall_time(time_t* tloc);
long libos_syscall_futex(int* uaddr, int op, int val, void* utime, int* uaddr2, int val3);
long libos_syscall_sched_setaffinity(pid_t pid, unsigned int user_mask_size,
                                     unsigned long* user_mask_ptr);
long libos_syscall_sched_getaffinity(pid_t pid, unsigned int user_mask_size,
                                     unsigned long* user_mask_ptr);
long libos_syscall_set_tid_address(int* tidptr);
long libos_syscall_fadvise64(int fd, loff_t offset, size_t len, int advice);
long libos_syscall_epoll_create(int size);
long libos_syscall_getdents64(int fd, struct linux_dirent64* buf, size_t count);
long libos_syscall_epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout_ms);
long libos_syscall_epoll_ctl(int epfd, int op, int fd, struct epoll_event* event);
long libos_syscall_clock_gettime(clockid_t which_clock, struct timespec* tp);
long libos_syscall_clock_getres(clockid_t which_clock, struct timespec* tp);
long libos_syscall_clock_nanosleep(clockid_t clock_id, int flags, struct __kernel_timespec* req,
                                   struct __kernel_timespec* rem);
long libos_syscall_exit_group(int error_code);
long libos_syscall_tgkill(int tgid, int pid, int sig);
long libos_syscall_mbind(void* start, unsigned long len, int mode, unsigned long* nmask,
                         unsigned long maxnode, int flags);
long libos_syscall_openat(int dfd, const char* filename, int flags, int mode);
long libos_syscall_mkdirat(int dfd, const char* pathname, int mode);
long libos_syscall_newfstatat(int dirfd, const char* pathname, struct stat* statbuf, int flags);
long libos_syscall_unlinkat(int dfd, const char* pathname, int flag);
long libos_syscall_readlinkat(int dirfd, const char* file, char* buf, int bufsize);
long libos_syscall_renameat(int olddfd, const char* pathname, int newdfd, const char* newname);
long libos_syscall_fchmodat(int dfd, const char* filename, mode_t mode);
long libos_syscall_fchownat(int dfd, const char* filename, uid_t user, gid_t group, int flags);
long libos_syscall_faccessat(int dfd, const char* filename, mode_t mode);
long libos_syscall_pselect6(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds,
                            struct __kernel_timespec* tsp, void* sigmask_argpack);
long libos_syscall_ppoll(struct pollfd* fds, unsigned int nfds, struct timespec* tsp,
                         const __sigset_t* sigmask_ptr, size_t sigsetsize);
long libos_syscall_set_robust_list(struct robust_list_head* head, size_t len);
long libos_syscall_get_robust_list(pid_t pid, struct robust_list_head** head, size_t* len);
long libos_syscall_epoll_pwait(int epfd, struct epoll_event* events, int maxevents, int timeout_ms,
                               const __sigset_t* sigmask, size_t sigsetsize);
long libos_syscall_accept4(int fd, void* addr, int* addrlen, int flags);
long libos_syscall_dup3(unsigned int oldfd, unsigned int newfd, int flags);
long libos_syscall_epoll_create1(int flags);
long libos_syscall_pipe2(int* fildes, int flags);
long libos_syscall_mknod(const char* pathname, mode_t mode, dev_t dev);
long libos_syscall_mknodat(int dirfd, const char* pathname, mode_t mode, dev_t dev);
long libos_syscall_recvmmsg(int fd, struct mmsghdr* msg, unsigned int vlen, unsigned int flags,
                            struct __kernel_timespec* timeout);
long libos_syscall_prlimit64(pid_t pid, int resource, const struct __kernel_rlimit64* new_rlim,
                             struct __kernel_rlimit64* old_rlim);
long libos_syscall_sendmmsg(int fd, struct mmsghdr* msg, unsigned int vlen, unsigned int flags);
long libos_syscall_eventfd2(unsigned int count, int flags);
long libos_syscall_eventfd(unsigned int count);
long libos_syscall_getcpu(unsigned* cpu, unsigned* node, void* unused_cache);
long libos_syscall_getrandom(char* buf, size_t count, unsigned int flags);
long libos_syscall_mlock2(unsigned long start, size_t len, int flags);
long libos_syscall_sysinfo(struct sysinfo* info);
