/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Michał Kowalczyk <mkow@invisiblethingslab.com>
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

/*
 * This file contains the system call table.
 */

#include <asm/unistd.h>

#include "libos_internal.h"
#include "libos_table.h"

libos_syscall_t libos_syscall_table[LIBOS_SYSCALL_BOUND] = {
    [__NR_read]                    = (libos_syscall_t)libos_syscall_read,
    [__NR_write]                   = (libos_syscall_t)libos_syscall_write,
    [__NR_open]                    = (libos_syscall_t)libos_syscall_open,
    [__NR_close]                   = (libos_syscall_t)libos_syscall_close,
    [__NR_stat]                    = (libos_syscall_t)libos_syscall_stat,
    [__NR_fstat]                   = (libos_syscall_t)libos_syscall_fstat,
    [__NR_lstat]                   = (libos_syscall_t)libos_syscall_lstat,
    [__NR_poll]                    = (libos_syscall_t)libos_syscall_poll,
    [__NR_lseek]                   = (libos_syscall_t)libos_syscall_lseek,
    [__NR_mmap]                    = (libos_syscall_t)libos_syscall_mmap,
    [__NR_mprotect]                = (libos_syscall_t)libos_syscall_mprotect,
    [__NR_munmap]                  = (libos_syscall_t)libos_syscall_munmap,
    [__NR_brk]                     = (libos_syscall_t)libos_syscall_brk,
    [__NR_rt_sigaction]            = (libos_syscall_t)libos_syscall_rt_sigaction,
    [__NR_rt_sigprocmask]          = (libos_syscall_t)libos_syscall_rt_sigprocmask,
    [__NR_rt_sigreturn]            = (libos_syscall_t)libos_syscall_rt_sigreturn,
    [__NR_ioctl]                   = (libos_syscall_t)libos_syscall_ioctl,
    [__NR_pread64]                 = (libos_syscall_t)libos_syscall_pread64,
    [__NR_pwrite64]                = (libos_syscall_t)libos_syscall_pwrite64,
    [__NR_readv]                   = (libos_syscall_t)libos_syscall_readv,
    [__NR_writev]                  = (libos_syscall_t)libos_syscall_writev,
    [__NR_access]                  = (libos_syscall_t)libos_syscall_access,
    [__NR_pipe]                    = (libos_syscall_t)libos_syscall_pipe,
    [__NR_select]                  = (libos_syscall_t)libos_syscall_select,
    [__NR_sched_yield]             = (libos_syscall_t)libos_syscall_sched_yield,
    [__NR_mremap]                  = (libos_syscall_t)0, // libos_syscall_mremap
    [__NR_msync]                   = (libos_syscall_t)libos_syscall_msync,
    [__NR_mincore]                 = (libos_syscall_t)libos_syscall_mincore,
    [__NR_madvise]                 = (libos_syscall_t)libos_syscall_madvise,
    [__NR_shmget]                  = (libos_syscall_t)0, // libos_syscall_shmget
    [__NR_shmat]                   = (libos_syscall_t)0, // libos_syscall_shmat
    [__NR_shmctl]                  = (libos_syscall_t)0, // libos_syscall_shmctl
    [__NR_dup]                     = (libos_syscall_t)libos_syscall_dup,
    [__NR_dup2]                    = (libos_syscall_t)libos_syscall_dup2,
    [__NR_pause]                   = (libos_syscall_t)libos_syscall_pause,
    [__NR_nanosleep]               = (libos_syscall_t)libos_syscall_nanosleep,
    [__NR_getitimer]               = (libos_syscall_t)libos_syscall_getitimer,
    [__NR_alarm]                   = (libos_syscall_t)libos_syscall_alarm,
    [__NR_setitimer]               = (libos_syscall_t)libos_syscall_setitimer,
    [__NR_getpid]                  = (libos_syscall_t)libos_syscall_getpid,
    [__NR_sendfile]                = (libos_syscall_t)libos_syscall_sendfile,
    [__NR_socket]                  = (libos_syscall_t)libos_syscall_socket,
    [__NR_connect]                 = (libos_syscall_t)libos_syscall_connect,
    [__NR_accept]                  = (libos_syscall_t)libos_syscall_accept,
    [__NR_sendto]                  = (libos_syscall_t)libos_syscall_sendto,
    [__NR_recvfrom]                = (libos_syscall_t)libos_syscall_recvfrom,
    [__NR_sendmsg]                 = (libos_syscall_t)libos_syscall_sendmsg,
    [__NR_recvmsg]                 = (libos_syscall_t)libos_syscall_recvmsg,
    [__NR_shutdown]                = (libos_syscall_t)libos_syscall_shutdown,
    [__NR_bind]                    = (libos_syscall_t)libos_syscall_bind,
    [__NR_listen]                  = (libos_syscall_t)libos_syscall_listen,
    [__NR_getsockname]             = (libos_syscall_t)libos_syscall_getsockname,
    [__NR_getpeername]             = (libos_syscall_t)libos_syscall_getpeername,
    [__NR_socketpair]              = (libos_syscall_t)libos_syscall_socketpair,
    [__NR_setsockopt]              = (libos_syscall_t)libos_syscall_setsockopt,
    [__NR_getsockopt]              = (libos_syscall_t)libos_syscall_getsockopt,
    [__NR_clone]                   = (libos_syscall_t)libos_syscall_clone,
    [__NR_fork]                    = (libos_syscall_t)libos_syscall_fork,
    [__NR_vfork]                   = (libos_syscall_t)libos_syscall_vfork,
    [__NR_execve]                  = (libos_syscall_t)libos_syscall_execve,
    [__NR_exit]                    = (libos_syscall_t)libos_syscall_exit,
    [__NR_wait4]                   = (libos_syscall_t)libos_syscall_wait4,
    [__NR_kill]                    = (libos_syscall_t)libos_syscall_kill,
    [__NR_uname]                   = (libos_syscall_t)libos_syscall_uname,
    [__NR_semget]                  = (libos_syscall_t)0, // libos_syscall_semget,
    [__NR_semop]                   = (libos_syscall_t)0, // libos_syscall_semop,
    [__NR_semctl]                  = (libos_syscall_t)0, // libos_syscall_semctl,
    [__NR_shmdt]                   = (libos_syscall_t)0, // libos_syscall_shmdt
    [__NR_msgget]                  = (libos_syscall_t)0, // libos_syscall_msgget,
    [__NR_msgsnd]                  = (libos_syscall_t)0, // libos_syscall_msgsnd,
    [__NR_msgrcv]                  = (libos_syscall_t)0, // libos_syscall_msgrcv,
    [__NR_msgctl]                  = (libos_syscall_t)0, // libos_syscall_msgctl,
    [__NR_fcntl]                   = (libos_syscall_t)libos_syscall_fcntl,
    [__NR_flock]                   = (libos_syscall_t)libos_syscall_flock,
    [__NR_fsync]                   = (libos_syscall_t)libos_syscall_fsync,
    [__NR_fdatasync]               = (libos_syscall_t)libos_syscall_fdatasync,
    [__NR_truncate]                = (libos_syscall_t)libos_syscall_truncate,
    [__NR_ftruncate]               = (libos_syscall_t)libos_syscall_ftruncate,
    [__NR_getdents]                = (libos_syscall_t)libos_syscall_getdents,
    [__NR_getcwd]                  = (libos_syscall_t)libos_syscall_getcwd,
    [__NR_chdir]                   = (libos_syscall_t)libos_syscall_chdir,
    [__NR_fchdir]                  = (libos_syscall_t)libos_syscall_fchdir,
    [__NR_rename]                  = (libos_syscall_t)libos_syscall_rename,
    [__NR_mkdir]                   = (libos_syscall_t)libos_syscall_mkdir,
    [__NR_rmdir]                   = (libos_syscall_t)libos_syscall_rmdir,
    [__NR_creat]                   = (libos_syscall_t)libos_syscall_creat,
    [__NR_link]                    = (libos_syscall_t)0, // libos_syscall_link
    [__NR_unlink]                  = (libos_syscall_t)libos_syscall_unlink,
    [__NR_symlink]                 = (libos_syscall_t)0, // libos_syscall_symlink
    [__NR_readlink]                = (libos_syscall_t)libos_syscall_readlink,
    [__NR_chmod]                   = (libos_syscall_t)libos_syscall_chmod,
    [__NR_fchmod]                  = (libos_syscall_t)libos_syscall_fchmod,
    [__NR_chown]                   = (libos_syscall_t)libos_syscall_chown,
    [__NR_fchown]                  = (libos_syscall_t)libos_syscall_fchown,
    [__NR_lchown]                  = (libos_syscall_t)0, // libos_syscall_lchown
    [__NR_umask]                   = (libos_syscall_t)libos_syscall_umask,
    [__NR_gettimeofday]            = (libos_syscall_t)libos_syscall_gettimeofday,
    [__NR_getrlimit]               = (libos_syscall_t)libos_syscall_getrlimit,
    [__NR_getrusage]               = (libos_syscall_t)0, // libos_syscall_getrusage
    [__NR_sysinfo]                 = (libos_syscall_t)libos_syscall_sysinfo,
    [__NR_times]                   = (libos_syscall_t)0, // libos_syscall_times
    [__NR_ptrace]                  = (libos_syscall_t)0, // libos_syscall_ptrace
    [__NR_getuid]                  = (libos_syscall_t)libos_syscall_getuid,
    [__NR_syslog]                  = (libos_syscall_t)0, // libos_syscall_syslog
    [__NR_getgid]                  = (libos_syscall_t)libos_syscall_getgid,
    [__NR_setuid]                  = (libos_syscall_t)libos_syscall_setuid,
    [__NR_setgid]                  = (libos_syscall_t)libos_syscall_setgid,
    [__NR_geteuid]                 = (libos_syscall_t)libos_syscall_geteuid,
    [__NR_getegid]                 = (libos_syscall_t)libos_syscall_getegid,
    [__NR_setpgid]                 = (libos_syscall_t)libos_syscall_setpgid,
    [__NR_getppid]                 = (libos_syscall_t)libos_syscall_getppid,
    [__NR_getpgrp]                 = (libos_syscall_t)libos_syscall_getpgrp,
    [__NR_setsid]                  = (libos_syscall_t)libos_syscall_setsid,
    [__NR_setreuid]                = (libos_syscall_t)0, // libos_syscall_setreuid
    [__NR_setregid]                = (libos_syscall_t)0, // libos_syscall_setregid
    [__NR_getgroups]               = (libos_syscall_t)libos_syscall_getgroups,
    [__NR_setgroups]               = (libos_syscall_t)libos_syscall_setgroups,
    [__NR_setresuid]               = (libos_syscall_t)0, // libos_syscall_setresuid
    [__NR_getresuid]               = (libos_syscall_t)0, // libos_syscall_getresuid
    [__NR_setresgid]               = (libos_syscall_t)0, // libos_syscall_setresgid
    [__NR_getresgid]               = (libos_syscall_t)0, // libos_syscall_getresgid
    [__NR_getpgid]                 = (libos_syscall_t)libos_syscall_getpgid,
    [__NR_setfsuid]                = (libos_syscall_t)0, // libos_syscall_setfsuid
    [__NR_setfsgid]                = (libos_syscall_t)0, // libos_syscall_setfsgid
    [__NR_getsid]                  = (libos_syscall_t)libos_syscall_getsid,
    [__NR_capget]                  = (libos_syscall_t)0, // libos_syscall_capget
    [__NR_capset]                  = (libos_syscall_t)0, // libos_syscall_capset
    [__NR_rt_sigpending]           = (libos_syscall_t)libos_syscall_rt_sigpending,
    [__NR_rt_sigtimedwait]         = (libos_syscall_t)libos_syscall_rt_sigtimedwait,
    [__NR_rt_sigqueueinfo]         = (libos_syscall_t)0, // libos_syscall_rt_sigqueueinfo
    [__NR_rt_sigsuspend]           = (libos_syscall_t)libos_syscall_rt_sigsuspend,
    [__NR_sigaltstack]             = (libos_syscall_t)libos_syscall_sigaltstack,
    [__NR_utime]                   = (libos_syscall_t)0, // libos_syscall_utime
    [__NR_mknod]                   = (libos_syscall_t)libos_syscall_mknod,
    [__NR_uselib]                  = (libos_syscall_t)0, // libos_syscall_uselib
    [__NR_personality]             = (libos_syscall_t)0, // libos_syscall_personality
    [__NR_ustat]                   = (libos_syscall_t)0, // libos_syscall_ustat
    [__NR_statfs]                  = (libos_syscall_t)libos_syscall_statfs,
    [__NR_fstatfs]                 = (libos_syscall_t)libos_syscall_fstatfs,
    [__NR_sysfs]                   = (libos_syscall_t)0, // libos_syscall_sysfs
    [__NR_getpriority]             = (libos_syscall_t)libos_syscall_getpriority,
    [__NR_setpriority]             = (libos_syscall_t)libos_syscall_setpriority,
    [__NR_sched_setparam]          = (libos_syscall_t)libos_syscall_sched_setparam,
    [__NR_sched_getparam]          = (libos_syscall_t)libos_syscall_sched_getparam,
    [__NR_sched_setscheduler]      = (libos_syscall_t)libos_syscall_sched_setscheduler,
    [__NR_sched_getscheduler]      = (libos_syscall_t)libos_syscall_sched_getscheduler,
    [__NR_sched_get_priority_max]  = (libos_syscall_t)libos_syscall_sched_get_priority_max,
    [__NR_sched_get_priority_min]  = (libos_syscall_t)libos_syscall_sched_get_priority_min,
    [__NR_sched_rr_get_interval]   = (libos_syscall_t)libos_syscall_sched_rr_get_interval,
    [__NR_mlock]                   = (libos_syscall_t)libos_syscall_mlock,
    [__NR_munlock]                 = (libos_syscall_t)libos_syscall_munlock,
    [__NR_mlockall]                = (libos_syscall_t)libos_syscall_mlockall,
    [__NR_munlockall]              = (libos_syscall_t)libos_syscall_munlockall,
    [__NR_vhangup]                 = (libos_syscall_t)0, // libos_syscall_vhangup
    [__NR_modify_ldt]              = (libos_syscall_t)0, // libos_syscall_modify_ldt
    [__NR_pivot_root]              = (libos_syscall_t)0, // libos_syscall_pivot_root
    [__NR__sysctl]                 = (libos_syscall_t)0, // libos_syscall__sysctl
    [__NR_prctl]                   = (libos_syscall_t)0, // libos_syscall_prctl
    [__NR_arch_prctl]              = (libos_syscall_t)libos_syscall_arch_prctl,
    [__NR_adjtimex]                = (libos_syscall_t)0, // libos_syscall_adjtimex
    [__NR_setrlimit]               = (libos_syscall_t)libos_syscall_setrlimit,
    [__NR_chroot]                  = (libos_syscall_t)libos_syscall_chroot,
    [__NR_sync]                    = (libos_syscall_t)0, // libos_syscall_sync
    [__NR_acct]                    = (libos_syscall_t)0, // libos_syscall_acct
    [__NR_settimeofday]            = (libos_syscall_t)0, // libos_syscall_settimeofday
    [__NR_mount]                   = (libos_syscall_t)0, // libos_syscall_mount
    [__NR_umount2]                 = (libos_syscall_t)0, // libos_syscall_umount2
    [__NR_swapon]                  = (libos_syscall_t)0, // libos_syscall_swapon
    [__NR_swapoff]                 = (libos_syscall_t)0, // libos_syscall_swapoff
    [__NR_reboot]                  = (libos_syscall_t)0, // libos_syscall_reboot
    [__NR_sethostname]             = (libos_syscall_t)libos_syscall_sethostname,
    [__NR_setdomainname]           = (libos_syscall_t)libos_syscall_setdomainname,
    [__NR_iopl]                    = (libos_syscall_t)0, // libos_syscall_iopl
    [__NR_ioperm]                  = (libos_syscall_t)0, // libos_syscall_ioperm
    [__NR_create_module]           = (libos_syscall_t)0, // libos_syscall_create_module
    [__NR_init_module]             = (libos_syscall_t)0, // libos_syscall_init_module
    [__NR_delete_module]           = (libos_syscall_t)0, // libos_syscall_delete_module
    [__NR_get_kernel_syms]         = (libos_syscall_t)0, // libos_syscall_get_kernel_syms,
    [__NR_query_module]            = (libos_syscall_t)0, // libos_syscall_query_module
    [__NR_quotactl]                = (libos_syscall_t)0, // libos_syscall_quotactl
    [__NR_nfsservctl]              = (libos_syscall_t)0, // libos_syscall_nfsservctl,
    [__NR_getpmsg]                 = (libos_syscall_t)0, // libos_syscall_getpmsg,
    [__NR_putpmsg]                 = (libos_syscall_t)0, // libos_syscall_putpmsg,
    [__NR_afs_syscall]             = (libos_syscall_t)0, // libos_syscall_afs_syscall,
    [__NR_tuxcall]                 = (libos_syscall_t)0, // libos_syscall_tuxcall,
    [__NR_security]                = (libos_syscall_t)0, // libos_syscall_security,
    [__NR_gettid]                  = (libos_syscall_t)libos_syscall_gettid,
    [__NR_readahead]               = (libos_syscall_t)0, // libos_syscall_readahead
    [__NR_setxattr]                = (libos_syscall_t)0, // libos_syscall_setxattr
    [__NR_lsetxattr]               = (libos_syscall_t)0, // libos_syscall_lsetxattr
    [__NR_fsetxattr]               = (libos_syscall_t)0, // libos_syscall_fsetxattr
    [__NR_getxattr]                = (libos_syscall_t)0, // libos_syscall_getxattr
    [__NR_lgetxattr]               = (libos_syscall_t)0, // libos_syscall_lgetxattr
    [__NR_fgetxattr]               = (libos_syscall_t)0, // libos_syscall_fgetxattr
    [__NR_listxattr]               = (libos_syscall_t)0, // libos_syscall_listxattr
    [__NR_llistxattr]              = (libos_syscall_t)0, // libos_syscall_llistxattr
    [__NR_flistxattr]              = (libos_syscall_t)0, // libos_syscall_flistxattr
    [__NR_removexattr]             = (libos_syscall_t)0, // libos_syscall_removexattr
    [__NR_lremovexattr]            = (libos_syscall_t)0, // libos_syscall_lremovexattr
    [__NR_fremovexattr]            = (libos_syscall_t)0, // libos_syscall_fremovexattr
    [__NR_tkill]                   = (libos_syscall_t)libos_syscall_tkill,
    [__NR_time]                    = (libos_syscall_t)libos_syscall_time,
    [__NR_futex]                   = (libos_syscall_t)libos_syscall_futex,
    [__NR_sched_setaffinity]       = (libos_syscall_t)libos_syscall_sched_setaffinity,
    [__NR_sched_getaffinity]       = (libos_syscall_t)libos_syscall_sched_getaffinity,
    [__NR_set_thread_area]         = (libos_syscall_t)0, // libos_syscall_set_thread_area
    [__NR_io_setup]                = (libos_syscall_t)0, // libos_syscall_io_setup
    [__NR_io_destroy]              = (libos_syscall_t)0, // libos_syscall_io_destroy
    [__NR_io_getevents]            = (libos_syscall_t)0, // libos_syscall_io_getevents
    [__NR_io_submit]               = (libos_syscall_t)0, // libos_syscall_io_submit
    [__NR_io_cancel]               = (libos_syscall_t)0, // libos_syscall_io_cancel
    [__NR_get_thread_area]         = (libos_syscall_t)0, // libos_syscall_get_thread_area
    [__NR_lookup_dcookie]          = (libos_syscall_t)0, // libos_syscall_lookup_dcookie
    [__NR_epoll_create]            = (libos_syscall_t)libos_syscall_epoll_create,
    [__NR_epoll_ctl_old]           = (libos_syscall_t)0, // libos_syscall_epoll_ctl_old,
    [__NR_epoll_wait_old]          = (libos_syscall_t)0, // libos_syscall_epoll_wait_old,
    [__NR_remap_file_pages]        = (libos_syscall_t)0, // libos_syscall_remap_file_pages
    [__NR_getdents64]              = (libos_syscall_t)libos_syscall_getdents64,
    [__NR_set_tid_address]         = (libos_syscall_t)libos_syscall_set_tid_address,
    [__NR_restart_syscall]         = (libos_syscall_t)0, // libos_syscall_restart_syscall
    [__NR_semtimedop]              = (libos_syscall_t)0, // libos_syscall_semtimedop,
    [__NR_fadvise64]               = (libos_syscall_t)libos_syscall_fadvise64,
    [__NR_timer_create]            = (libos_syscall_t)0, // libos_syscall_timer_create
    [__NR_timer_settime]           = (libos_syscall_t)0, // libos_syscall_timer_settime
    [__NR_timer_gettime]           = (libos_syscall_t)0, // libos_syscall_timer_gettime
    [__NR_timer_getoverrun]        = (libos_syscall_t)0, // libos_syscall_timer_getoverrun
    [__NR_timer_delete]            = (libos_syscall_t)0, // libos_syscall_timer_delete
    [__NR_clock_settime]           = (libos_syscall_t)0, // libos_syscall_clock_settime
    [__NR_clock_gettime]           = (libos_syscall_t)libos_syscall_clock_gettime,
    [__NR_clock_getres]            = (libos_syscall_t)libos_syscall_clock_getres,
    [__NR_clock_nanosleep]         = (libos_syscall_t)libos_syscall_clock_nanosleep,
    [__NR_exit_group]              = (libos_syscall_t)libos_syscall_exit_group,
    [__NR_epoll_wait]              = (libos_syscall_t)libos_syscall_epoll_wait,
    [__NR_epoll_ctl]               = (libos_syscall_t)libos_syscall_epoll_ctl,
    [__NR_tgkill]                  = (libos_syscall_t)libos_syscall_tgkill,
    [__NR_utimes]                  = (libos_syscall_t)0, // libos_syscall_utimes
    [__NR_vserver]                 = (libos_syscall_t)0, // libos_syscall_vserver,
    [__NR_mbind]                   = (libos_syscall_t)libos_syscall_mbind,
    [__NR_set_mempolicy]           = (libos_syscall_t)0, // libos_syscall_set_mempolicy
    [__NR_get_mempolicy]           = (libos_syscall_t)0, // libos_syscall_get_mempolicy
    [__NR_mq_open]                 = (libos_syscall_t)0, // libos_syscall_mq_open
    [__NR_mq_unlink]               = (libos_syscall_t)0, // libos_syscall_mq_unlink
    [__NR_mq_timedsend]            = (libos_syscall_t)0, // libos_syscall_mq_timedsend
    [__NR_mq_timedreceive]         = (libos_syscall_t)0, // libos_syscall_mq_timedreceive
    [__NR_mq_notify]               = (libos_syscall_t)0, // libos_syscall_mq_notify
    [__NR_mq_getsetattr]           = (libos_syscall_t)0, // libos_syscall_mq_getsetattr
    [__NR_kexec_load]              = (libos_syscall_t)0, // libos_syscall_kexec_load,
    [__NR_waitid]                  = (libos_syscall_t)libos_syscall_waitid,
    [__NR_add_key]                 = (libos_syscall_t)0, // libos_syscall_add_key,
    [__NR_request_key]             = (libos_syscall_t)0, // libos_syscall_request_key,
    [__NR_keyctl]                  = (libos_syscall_t)0, // libos_syscall_keyctl,
    [__NR_ioprio_set]              = (libos_syscall_t)0, // libos_syscall_ioprio_set
    [__NR_ioprio_get]              = (libos_syscall_t)0, // libos_syscall_ioprio_get
    [__NR_inotify_init]            = (libos_syscall_t)0, // libos_syscall_inotify_init
    [__NR_inotify_add_watch]       = (libos_syscall_t)0, // libos_syscall_inotify_add_watch
    [__NR_inotify_rm_watch]        = (libos_syscall_t)0, // libos_syscall_inotify_rm_watch
    [__NR_migrate_pages]           = (libos_syscall_t)0, // libos_syscall_migrate_pages
    [__NR_openat]                  = (libos_syscall_t)libos_syscall_openat,
    [__NR_mkdirat]                 = (libos_syscall_t)libos_syscall_mkdirat,
    [__NR_mknodat]                 = (libos_syscall_t)libos_syscall_mknodat,
    [__NR_fchownat]                = (libos_syscall_t)libos_syscall_fchownat,
    [__NR_futimesat]               = (libos_syscall_t)0, // libos_syscall_futimesat
    [__NR_newfstatat]              = (libos_syscall_t)libos_syscall_newfstatat,
    [__NR_unlinkat]                = (libos_syscall_t)libos_syscall_unlinkat,
    [__NR_renameat]                = (libos_syscall_t)libos_syscall_renameat,
    [__NR_linkat]                  = (libos_syscall_t)0, // libos_syscall_linkat
    [__NR_symlinkat]               = (libos_syscall_t)0, // libos_syscall_symlinkat
    [__NR_readlinkat]              = (libos_syscall_t)libos_syscall_readlinkat,
    [__NR_fchmodat]                = (libos_syscall_t)libos_syscall_fchmodat,
    [__NR_faccessat]               = (libos_syscall_t)libos_syscall_faccessat,
    [__NR_pselect6]                = (libos_syscall_t)libos_syscall_pselect6,
    [__NR_ppoll]                   = (libos_syscall_t)libos_syscall_ppoll,
    [__NR_unshare]                 = (libos_syscall_t)0, // libos_syscall_unshare
    [__NR_set_robust_list]         = (libos_syscall_t)libos_syscall_set_robust_list,
    [__NR_get_robust_list]         = (libos_syscall_t)libos_syscall_get_robust_list,
    [__NR_splice]                  = (libos_syscall_t)0, // libos_syscall_splice
    [__NR_tee]                     = (libos_syscall_t)0, // libos_syscall_tee
    [__NR_sync_file_range]         = (libos_syscall_t)0, // libos_syscall_sync_file_range
    [__NR_vmsplice]                = (libos_syscall_t)0, // libos_syscall_vmsplice
    [__NR_move_pages]              = (libos_syscall_t)0, // libos_syscall_move_pages
    [__NR_utimensat]               = (libos_syscall_t)0, // libos_syscall_utimensat
    [__NR_epoll_pwait]             = (libos_syscall_t)libos_syscall_epoll_pwait,
    [__NR_signalfd]                = (libos_syscall_t)0, // libos_syscall_signalfd
    [__NR_timerfd_create]          = (libos_syscall_t)0, // libos_syscall_timerfd_create
    [__NR_eventfd]                 = (libos_syscall_t)libos_syscall_eventfd,
    [__NR_fallocate]               = (libos_syscall_t)libos_syscall_fallocate,
    [__NR_timerfd_settime]         = (libos_syscall_t)0, // libos_syscall_timerfd_settime
    [__NR_timerfd_gettime]         = (libos_syscall_t)0, // libos_syscall_timerfd_gettime
    [__NR_accept4]                 = (libos_syscall_t)libos_syscall_accept4,
    [__NR_signalfd4]               = (libos_syscall_t)0, // libos_syscall_signalfd4
    [__NR_eventfd2]                = (libos_syscall_t)libos_syscall_eventfd2,
    [__NR_epoll_create1]           = (libos_syscall_t)libos_syscall_epoll_create1,
    [__NR_dup3]                    = (libos_syscall_t)libos_syscall_dup3,
    [__NR_pipe2]                   = (libos_syscall_t)libos_syscall_pipe2,
    [__NR_inotify_init1]           = (libos_syscall_t)0, // libos_syscall_inotify_init1
    [__NR_preadv]                  = (libos_syscall_t)0, // libos_syscall_preadv
    [__NR_pwritev]                 = (libos_syscall_t)0, // libos_syscall_pwritev
    [__NR_rt_tgsigqueueinfo]       = (libos_syscall_t)0, // libos_syscall_rt_tgsigqueueinfo
    [__NR_perf_event_open]         = (libos_syscall_t)0, // libos_syscall_perf_event_open
    [__NR_recvmmsg]                = (libos_syscall_t)libos_syscall_recvmmsg,
    [__NR_fanotify_init]           = (libos_syscall_t)0, // libos_syscall_fanotify_init
    [__NR_fanotify_mark]           = (libos_syscall_t)0, // libos_syscall_fanotify_mark
    [__NR_prlimit64]               = (libos_syscall_t)libos_syscall_prlimit64,
    [__NR_name_to_handle_at]       = (libos_syscall_t)0, // libos_syscall_name_to_handle_at
    [__NR_open_by_handle_at]       = (libos_syscall_t)0, // libos_syscall_open_by_handle_at
    [__NR_clock_adjtime]           = (libos_syscall_t)0, // libos_syscall_clock_adjtime
    [__NR_syncfs]                  = (libos_syscall_t)0, // libos_syscall_syncfs
    [__NR_sendmmsg]                = (libos_syscall_t)libos_syscall_sendmmsg,
    [__NR_setns]                   = (libos_syscall_t)0, // libos_syscall_setns
    [__NR_getcpu]                  = (libos_syscall_t)libos_syscall_getcpu,
    [__NR_process_vm_readv]        = (libos_syscall_t)0, // libos_syscall_process_vm_readv
    [__NR_process_vm_writev]       = (libos_syscall_t)0, // libos_syscall_process_vm_writev
    [__NR_kcmp]                    = (libos_syscall_t)0, // libos_syscall_kcmp
    [__NR_finit_module]            = (libos_syscall_t)0, // libos_syscall_finit_module
    [__NR_sched_setattr]           = (libos_syscall_t)0, // libos_syscall_sched_setattr
    [__NR_sched_getattr]           = (libos_syscall_t)0, // libos_syscall_sched_getattr
    [__NR_renameat2]               = (libos_syscall_t)0, // libos_syscall_renameat2
    [__NR_seccomp]                 = (libos_syscall_t)0, // libos_syscall_seccomp
    [__NR_getrandom]               = (libos_syscall_t)libos_syscall_getrandom,
    [__NR_memfd_create]            = (libos_syscall_t)0, // libos_syscall_memfd_create
    [__NR_kexec_file_load]         = (libos_syscall_t)0, // libos_syscall_kexec_file_load
    [__NR_bpf]                     = (libos_syscall_t)0, // libos_syscall_bpf
    [__NR_execveat]                = (libos_syscall_t)0, // libos_syscall_execveat
    [__NR_userfaultfd]             = (libos_syscall_t)0, // libos_syscall_userfaultfd
    [__NR_membarrier]              = (libos_syscall_t)0, // libos_syscall_membarrier
    [__NR_mlock2]                  = (libos_syscall_t)libos_syscall_mlock2,
    [__NR_copy_file_range]         = (libos_syscall_t)0, // libos_syscall_copy_file_range
    [__NR_preadv2]                 = (libos_syscall_t)0, // libos_syscall_preadv2
    [__NR_pwritev2]                = (libos_syscall_t)0, // libos_syscall_pwritev2
    [__NR_pkey_mprotect]           = (libos_syscall_t)0, // libos_syscall_pkey_mprotect
    [__NR_pkey_alloc]              = (libos_syscall_t)0, // libos_syscall_pkey_alloc
    [__NR_pkey_free]               = (libos_syscall_t)0, // libos_syscall_pkey_free
    [__NR_statx]                   = (libos_syscall_t)0, // libos_syscall_statx
    [__NR_io_pgetevents]           = (libos_syscall_t)0, // libos_syscall_io_pgetevents
    [__NR_rseq]                    = (libos_syscall_t)0, // libos_syscall_rseq
    [__NR_pidfd_send_signal]       = (libos_syscall_t)0, // libos_syscall_pidfd_send_signal
    [__NR_io_uring_setup]          = (libos_syscall_t)0, // libos_syscall_io_uring_setup
    [__NR_io_uring_enter]          = (libos_syscall_t)0, // libos_syscall_io_uring_enter
    [__NR_io_uring_register]       = (libos_syscall_t)0, // libos_syscall_io_uring_register
    [__NR_open_tree]               = (libos_syscall_t)0, // libos_syscall_open_tree
    [__NR_move_mount]              = (libos_syscall_t)0, // libos_syscall_move_mount
    [__NR_fsopen]                  = (libos_syscall_t)0, // libos_syscall_fsopen
    [__NR_fsconfig]                = (libos_syscall_t)0, // libos_syscall_fsconfig
    [__NR_fsmount]                 = (libos_syscall_t)0, // libos_syscall_fsmount
    [__NR_fspick]                  = (libos_syscall_t)0, // libos_syscall_fspick
    [__NR_pidfd_open]              = (libos_syscall_t)0, // libos_syscall_pidfd_open
    [__NR_clone3]                  = (libos_syscall_t)0, // libos_syscall_clone3
    [__NR_close_range]             = (libos_syscall_t)0, // libos_syscall_close_range
    [__NR_openat2]                 = (libos_syscall_t)0, // libos_syscall_openat2
    [__NR_pidfd_getfd]             = (libos_syscall_t)0, // libos_syscall_pidfd_getfd
    [__NR_faccessat2]              = (libos_syscall_t)0, // libos_syscall_faccessat2
    [__NR_process_madvise]         = (libos_syscall_t)0, // libos_syscall_process_madvise
    [__NR_epoll_pwait2]            = (libos_syscall_t)0, // libos_syscall_epoll_pwait2
    [__NR_mount_setattr]           = (libos_syscall_t)0, // libos_syscall_mount_setattr
    [__NR_quotactl_fd]             = (libos_syscall_t)0, // libos_syscall_quotactl_fd
    [__NR_landlock_create_ruleset] = (libos_syscall_t)0, // libos_syscall_landlock_create_ruleset
    [__NR_landlock_add_rule]       = (libos_syscall_t)0, // libos_syscall_landlock_add_rule
    [__NR_landlock_restrict_self]  = (libos_syscall_t)0, // libos_syscall_landlock_restrict_self
    [__NR_memfd_secret]            = (libos_syscall_t)0, // libos_syscall_memfd_secret
    [__NR_process_mrelease]        = (libos_syscall_t)0, // libos_syscall_process_mrelease
    [__NR_futex_waitv]             = (libos_syscall_t)0, // libos_syscall_futex_waitv
    [__NR_set_mempolicy_home_node] = (libos_syscall_t)0, // libos_syscall_set_mempolicy_home_node
};
