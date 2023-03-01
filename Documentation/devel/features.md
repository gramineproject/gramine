<!-- Cannot render this doc in RestructedText as it has no support for nested inline markup. -->

# Gramine features

> :warning: This is a highly technical document, intended for software engineers with knowledge of
> OS kernels.

> :construction: This is a living document. The last major update happened in **Feb 2023**.

Gramine strives to **support native, unmodified Linux applications** on any platform. The SGX
backend additionally strives to **provide security guarantees**, in particular, protect against a
malicious host OS.

Gramine **intercepts all application requests** to the host OS. Some of these requests are processed
entirely inside Gramine, and some are forwarded to the host OS. Either way, each application's
request and each host's reply is verified for correctness and consistency. For these verifications,
Gramine maintains internal, "shadow" state. Thus, Gramine defends against [Iago
attacks](https://dl.acm.org/doi/10.1145/2490301.2451145).

Gramine strives to be **100% compatible with the Linux kernel**, even when it deviates from
standards like POSIX ("bug-for-bug compatibility"). At the same time, Gramine is minimalistic, and
implements **only the most important subset of Linux functionality**, enough to run portable,
hardware-independent applications.

Gramine currently has two backends: direct execution on the host Linux OS (called `gramine-direct`)
and execution inside an Intel SGX enclave (called `gramine-sgx`). If some feature has quirks and
pecularities in some backend, we describe it explicitly. More backends are possible in the future.

Features implemented in Gramine can be classified as:

- **Linux features**: features can be (1) implemented, (2) partially implemented, or (3) not
  implemented at all in Gramine. If the feature is partially implemented, then we also document the
  parts that are implemented and the parts that are implemented. If the feature is not implemented
  at all, we also specify whether there are plans to implement it in the future (and if not, the
  rationale why not).

  - Some features are **not implemented by design**: either they increase the Trusted Computing Base
    (TCB) of Gramine disproportionately, or they cannot be implemented securely.

  - Other features are **not implemented because they are unused**: some Linux features are
    deprecated or ill-conceived, and applications do not use them (or have fallbacks when these
    features are not detected).

- **Gramine-specific features**: additional features, e.g., attestation primitives. Note that this
  document covers only APIs exposed to applications (like additional system calls and pseudo-files)
  and doesn't cover Gramine features transparent to the app (exitless, ASLR, debugging, etc.).

Each feature has a list of related system calls and pseudo-files, for cross-reference.

### Table of Contents (abridged)

- [List of system calls](#list-of-system-calls)
- [List of pseudo-files](#list-of-pseudo-files)
- [Linux features](#linux-features)
- [Gramine-specific features](#gramine-specific-features)
- [Notes on System V ABI](#notes-on-system-v-abi)
- [Notes on application loading](#notes-on-application-loading)

## Terminology

Similarly to Linux, Gramine provides two interfaces to user applications:

- **Linux kernel-to-userspace API**, consisting of two sub-interfaces:

  - **Linux System Call Interface**: a set of system calls which allow applications to access system
    resources and services. Examples: `open()`, `fork()`, `gettimeofday()`.

  - **Pseudo filesystems**: a set of special directories with file contents containing information
    about the Gramine instance, system resources, hardware configuration, etc. These filesystems are
    generated on the fly upon Gramine startup. Examples: `/proc/cpuinfo`, `/dev/attestation/quote`.

- **Linux kernel-to-userspace ABI**, in particular, two standards:

  - **System V ABI**: defines how applications invoke system calls and receive signals.
  - **Executable and Linking Format (ELF)**: defines how applications are loaded from binary files.

---

Legend:

- :white_check_mark: implemented (no serious limitations)
- :ballot_box_with_check: partially implemented (serious limitations or quirks)
- :x: not implemented

## List of system calls

Gramine implements ~170 system calls out of ~360 system calls available on Linux. Many system calls
are implemented only partially, typically because real world workloads do not use the unimplemented
functionality (for example, `O_ASYNC` flag in `open()` is not used). Some system calls are not
implemented because they are deprecated in Linux, because they are unused by real world applications
or because they don't fit the purpose of Gramine ("virtualize a single application").

The list of implemented system calls grows with time, as Gramine adds functionality required by real
world workloads.

The below list is generated from the [syscall table of Linux
6.0](https://github.com/torvalds/linux/blob/v6.0/arch/x86/entry/syscalls/syscall_64.tbl).

<details><summary>:blue_book: Status of system call support in Gramine</summary>

- :white_check_mark: `read()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>
  <sup>[5](#event-notifications-eventfd)</sup>

- :white_check_mark: `write()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>
  <sup>[5](#event-notifications-eventfd)</sup>

- :ballot_box_with_check: `open()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `close()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>
  <sup>[5](#event-notifications-eventfd)</sup>

- :ballot_box_with_check: `stat()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `fstat()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>

- :ballot_box_with_check: `lstat()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `poll()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>
  <sup>[5](#io-multiplexing)</sup>
  <sup>[6](#event-notifications-eventfd)</sup>

- :ballot_box_with_check: `lseek()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `mmap()`
  <sup>[1](#memory-management)</sup>
  <sup>[2](#file-system-operations)</sup>

- :ballot_box_with_check: `mprotect()`
  <sup>[1](#memory-management)</sup>

- :white_check_mark: `munmap()`
  <sup>[1](#memory-management)</sup>

- :white_check_mark: `brk()`
  <sup>[1](#memory-management)</sup>
  <sup>[2](#system-information-and-resource-accounting)</sup>

- :white_check_mark: `rt_sigaction()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :white_check_mark: `rt_sigprocmask()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :white_check_mark: `rt_sigreturn()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :ballot_box_with_check: `ioctl()`
  <sup>[1](#pipes-and-fifos-named-pipes)</sup>
  <sup>[2](#tcpip-and-udpip-sockets)</sup>
  <sup>[3](#unix-domain-sockets)</sup>
  <sup>[4](#ioctls)</sup>

- :white_check_mark: `pread64()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `pwrite64()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `readv()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>

- :white_check_mark: `writev()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>

- :ballot_box_with_check: `access()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `pipe()`
  <sup>[1](#pipes-and-fifos-named-pipes)</sup>

- :ballot_box_with_check: `select()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>
  <sup>[5](#io-multiplexing)</sup>
  <sup>[6](#event-notifications-eventfd)</sup>

- :white_check_mark: `sched_yield()`
  <sup>[1](#scheduling)</sup>

- :x: `mremap()`
  <sup>[1](#memory-management)</sup>

- :ballot_box_with_check: `msync()`
  <sup>[1](#memory-management)</sup>
  <sup>[2](#file-system-operations)</sup>

- :ballot_box_with_check: `mincore()`
  <sup>[1](#memory-management)</sup>

- :ballot_box_with_check: `madvise()`
  <sup>[1](#memory-management)</sup>

- :x: `shmget()`
  <sup>[1](#shared-memory)</sup>

- :x: `shmat()`
  <sup>[1](#shared-memory)</sup>

- :x: `shmctl()`
  <sup>[1](#shared-memory)</sup>

- :white_check_mark: `dup()`
  <sup>[1](#misc)</sup>

- :white_check_mark: `dup2()`
  <sup>[1](#misc)</sup>

- :white_check_mark: `pause()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :white_check_mark: `nanosleep()`
  <sup>[1](#sleeps-timers-and-alarms)</sup>

- :ballot_box_with_check: `getitimer()`
  <sup>[1](#sleeps-timers-and-alarms)</sup>

- :white_check_mark: `alarm()`
  <sup>[1](#sleeps-timers-and-alarms)</sup>

- :ballot_box_with_check: `setitimer()`
  <sup>[1](#sleeps-timers-and-alarms)</sup>

- :white_check_mark: `getpid()`
  <sup>[1](#process-and-thread-identifiers)</sup>

- :ballot_box_with_check: `sendfile()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>

- :ballot_box_with_check: `socket()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :white_check_mark: `connect()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :white_check_mark: `accept()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :ballot_box_with_check: `sendto()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :ballot_box_with_check: `recvfrom()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :ballot_box_with_check: `sendmsg()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :ballot_box_with_check: `recvmsg()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :white_check_mark: `shutdown()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :white_check_mark: `bind()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :white_check_mark: `listen()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :white_check_mark: `getsockname()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :white_check_mark: `getpeername()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :white_check_mark: `socketpair()`
  <sup>[1](#unix-domain-sockets)</sup>

- :white_check_mark: `setsockopt()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :white_check_mark: `getsockopt()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :white_check_mark: `clone()`
  <sup>[1](#processes)</sup>
  <sup>[2](#threads)</sup>

- :white_check_mark: `fork()`
  <sup>[1](#processes)</sup>

- :white_check_mark: `vfork()`
  <sup>[1](#processes)</sup>

- :white_check_mark: `execve()`
  <sup>[1](#processes)</sup>

- :white_check_mark: `exit()`
  <sup>[1](#processes)</sup>
  <sup>[2](#threads)</sup>

- :ballot_box_with_check: `wait4()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :ballot_box_with_check: `kill()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :ballot_box_with_check: `uname()`
  <sup>[1](#system-information-and-resource-accounting)</sup>

- :x: `semget()`
  <sup>[1](#semaphores)</sup>

- :x: `semop()`
  <sup>[1](#semaphores)</sup>

- :x: `semctl()`
  <sup>[1](#semaphores)</sup>

- :x: `shmdt()`
  <sup>[1](#shared-memory)</sup>

- :x: `msgget()`
  <sup>[1](#message-queues)</sup>

- :x: `msgsnd()`
  <sup>[1](#message-queues)</sup>

- :x: `msgrcv()`
  <sup>[1](#message-queues)</sup>

- :x: `msgctl()`
  <sup>[1](#message-queues)</sup>

- :ballot_box_with_check: `fcntl()`
  <sup>[1](#file-locking)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>
  <sup>[5](#misc)</sup>

- :x: `flock()`
  <sup>[1](#file-locking)</sup>

- :white_check_mark: `fsync()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `fdatasync()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `truncate()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `ftruncate()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `getdents()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `getcwd()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `chdir()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `fchdir()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `rename()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `mkdir()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `rmdir()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `creat()`
  <sup>[1](#file-system-operations)</sup>

- :x: `link()`
  <sup>[1](#hard-links-and-soft-links-symbolic-links)</sup>

- :white_check_mark: `unlink()`
  <sup>[1](#file-system-operations)</sup>

- :x: `symlink()`
  <sup>[1](#hard-links-and-soft-links-symbolic-links)</sup>

- :ballot_box_with_check: `readlink()`
  <sup>[1](#hard-links-and-soft-links-symbolic-links)</sup>

- :white_check_mark: `chmod()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `fchmod()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `chown()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `fchown()`
  <sup>[1](#file-system-operations)</sup>

- :x: `lchown()`
  <sup>[1](#hard-links-and-soft-links-symbolic-links)</sup>

- :white_check_mark: `umask()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `gettimeofday()`
  <sup>[1](#date-and-time)</sup>
  <sup>[2](#misc)</sup>

- :ballot_box_with_check: `getrlimit()`
  <sup>[1](#system-information-and-resource-accounting)</sup>

- :x: `getrusage()`
  <sup>[1](#system-information-and-resource-accounting)</sup>

- :ballot_box_with_check: `sysinfo()`
  <sup>[1](#system-information-and-resource-accounting)</sup>

- :x: `times()`
  <sup>[1](#date-and-time)</sup>

- :x: `ptrace()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :ballot_box_with_check: `getuid()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :x: `syslog()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :ballot_box_with_check: `getgid()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :ballot_box_with_check: `setuid()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :ballot_box_with_check: `setgid()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :ballot_box_with_check: `geteuid()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :ballot_box_with_check: `getegid()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :ballot_box_with_check: `setpgid()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :white_check_mark: `getppid()`
  <sup>[1](#process-and-thread-identifiers)</sup>

- :ballot_box_with_check: `getpgrp()`
  <sup>[1](#process-and-thread-identifiers)</sup>

- :x: `setsid()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `setreuid()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :x: `setregid()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :ballot_box_with_check: `getgroups()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :ballot_box_with_check: `setgroups()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :x: `setresuid()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :x: `getresuid()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :x: `setresgid()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :x: `getresgid()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :ballot_box_with_check: `getpgid()`
  <sup>[1](#process-and-thread-identifiers)</sup>

- :x: `setfsuid()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :x: `setfsgid()`
  <sup>[1](#user-and-group-identifiers)</sup>

- :x: `getsid()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `capget()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `capset()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :white_check_mark: `rt_sigpending()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :white_check_mark: `rt_sigtimedwait()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :x: `rt_sigqueueinfo()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :white_check_mark: `rt_sigsuspend()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :white_check_mark: `sigaltstack()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :x: `utime()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `mknod()`
  <sup>[1](#pipes-and-fifos-named-pipes)</sup>

- :x: `uselib()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `personality()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `ustat()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `statfs()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `fstatfs()`
  <sup>[1](#file-system-operations)</sup>

- :x: `sysfs()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `getpriority()`
  <sup>[1](#scheduling)</sup>

- :ballot_box_with_check: `setpriority()`
  <sup>[1](#scheduling)</sup>

- :ballot_box_with_check: `sched_setparam()`
  <sup>[1](#scheduling)</sup>

- :ballot_box_with_check: `sched_getparam()`
  <sup>[1](#scheduling)</sup>

- :ballot_box_with_check: `sched_setscheduler()`
  <sup>[1](#scheduling)</sup>

- :ballot_box_with_check: `sched_getscheduler()`
  <sup>[1](#scheduling)</sup>

- :ballot_box_with_check: `sched_get_priority_max()`
  <sup>[1](#scheduling)</sup>

- :ballot_box_with_check: `sched_get_priority_min()`
  <sup>[1](#scheduling)</sup>

- :ballot_box_with_check: `sched_rr_get_interval()`
  <sup>[1](#scheduling)</sup>

- :ballot_box_with_check: `mlock()`
  <sup>[1](#memory-management)</sup>

- :ballot_box_with_check: `munlock()`
  <sup>[1](#memory-management)</sup>

- :ballot_box_with_check: `mlockall()`
  <sup>[1](#memory-management)</sup>

- :ballot_box_with_check: `munlockall()`
  <sup>[1](#memory-management)</sup>

- :x: `vhangup()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `modify_ldt()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `pivot_root()`
  <sup>[1](#file-system-operations)</sup>

- :x: `_sysctl()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `prctl()`
  <sup>[1](#threads)</sup>

- :ballot_box_with_check: `arch_prctl()`
  <sup>[1](#threads)</sup>

- :x: `adjtimex()`
  <sup>[1](#date-and-time)</sup>

- :ballot_box_with_check: `setrlimit()`
  <sup>[1](#system-information-and-resource-accounting)</sup>

- :white_check_mark: `chroot()`
  <sup>[1](#file-system-operations)</sup>

- :x: `sync()`
  <sup>[1](#file-system-operations)</sup>

- :x: `acct()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `settimeofday()`
  <sup>[1](#date-and-time)</sup>

- :x: `mount()`
  <sup>[1](#file-system-operations)</sup>

- :x: `umount2()`
  <sup>[1](#file-system-operations)</sup>

- :x: `swapon()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `swapoff()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `reboot()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :ballot_box_with_check: `sethostname()`
  <sup>[1](#system-information-and-resource-accounting)</sup>

- :ballot_box_with_check: `setdomainname()`
  <sup>[1](#system-information-and-resource-accounting)</sup>

- :x: `iopl()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `ioperm()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `create_module()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `init_module()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `delete_module()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `get_kernel_syms()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `query_module()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x:`quotactl()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `nfsservctl()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `getpmsg()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `putpmsg()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `afs_syscall()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `tuxcall()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `security()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :white_check_mark: `gettid()`
  <sup>[1](#process-and-thread-identifiers)</sup>

- :x: `readahead()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `setxattr()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `lsetxattr()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `fsetxattr()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `getxattr()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `lgetxattr()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `fgetxattr()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `listxattr()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `llistxattr()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `flistxattr()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `removexattr()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `lremovexattr()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `fremovexattr()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :ballot_box_with_check: `tkill()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :white_check_mark: `time()`
  <sup>[1](#date-and-time)</sup>

- :ballot_box_with_check: `futex()`
  <sup>[1](#memory-synchronization-futexes)</sup>

- :white_check_mark: `sched_setaffinity()`
  <sup>[1](#scheduling)</sup>

- :white_check_mark: `sched_getaffinity()`
  <sup>[1](#scheduling)</sup>

- :x: `set_thread_area()`
  <sup>[1](#threads)</sup>

- :x: `io_setup()`
  <sup>[1](#asynchronous-io)</sup>

- :x: `io_destroy()`
  <sup>[1](#asynchronous-io)</sup>

- :x: `io_getevents()`
  <sup>[1](#asynchronous-io)</sup>

- :x: `io_submit()`
  <sup>[1](#asynchronous-io)</sup>

- :x: `io_cancel()`
  <sup>[1](#asynchronous-io)</sup>

- :x: `get_thread_area()`
  <sup>[1](#threads)</sup>

- :x: `lookup_dcookie()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :white_check_mark: `epoll_create()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>
  <sup>[5](#io-multiplexing)</sup>
  <sup>[6](#event-notifications-eventfd)</sup>

- :x: `remap_file_pages()`
  <sup>[1](#memory-management)</sup>

- :white_check_mark: `getdents64()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `set_tid_address()`
  <sup>[1](#process-and-thread-identifiers)</sup>

- :x: `restart_syscall()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `semtimedop()`
  <sup>[1](#semaphores)</sup>

- :ballot_box_with_check: `fadvise64()`
  <sup>[1](#file-system-operations)</sup>

- :x: `timer_create()`
  <sup>[1](#sleeps-timers-and-alarms)</sup>

- :x: `timer_settime()`
  <sup>[1](#sleeps-timers-and-alarms)</sup>

- :x: `timer_gettime()`
  <sup>[1](#sleeps-timers-and-alarms)</sup>

- :x: `timer_getoverrun()`
  <sup>[1](#sleeps-timers-and-alarms)</sup>

- :x: `timer_delete()`
  <sup>[1](#sleeps-timers-and-alarms)</sup>

- :x: `clock_settime()`
  <sup>[1](#date-and-time)</sup>

- :ballot_box_with_check: `clock_gettime()`
  <sup>[1](#date-and-time)</sup>

- :ballot_box_with_check: `clock_getres()`
  <sup>[1](#date-and-time)</sup>

- :ballot_box_with_check: `clock_nanosleep()`
  <sup>[1](#sleeps-timers-and-alarms)</sup>

- :white_check_mark: `exit_group()`
  <sup>[1](#processes)</sup>

- :white_check_mark: `epoll_wait()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>
  <sup>[5](#io-multiplexing)</sup>
  <sup>[6](#event-notifications-eventfd)</sup>

- :white_check_mark: `epoll_ctl()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>
  <sup>[5](#io-multiplexing)</sup>
  <sup>[6](#event-notifications-eventfd)</sup>

- :white_check_mark: `tgkill()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :x: `utimes()`
  <sup>[1](#file-system-operations)</sup>

- :x: `vserver()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :ballot_box_with_check: `mbind()`
  <sup>[1](#memory-management)</sup>

- :x: `set_mempolicy()`
  <sup>[1](#memory-management)</sup>

- :x: `get_mempolicy()`
  <sup>[1](#memory-management)</sup>

- :x: `mq_open()`
  <sup>[1](#message-queues)</sup>

- :x: `mq_unlink()`
  <sup>[1](#message-queues)</sup>

- :x: `mq_timedsend()`
  <sup>[1](#message-queues)</sup>

- :x: `mq_timedreceive()`
  <sup>[1](#message-queues)</sup>

- :x: `mq_notify()`
  <sup>[1](#message-queues)</sup>

- :x: `mq_getsetattr()`
  <sup>[1](#message-queues)</sup>

- :x: `kexec_load()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :ballot_box_with_check: `waitid()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :x: `add_key()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `request_key()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `keyctl()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `ioprio_set()`
  <sup>[1](#scheduling)</sup>

- :x: `ioprio_get()`
  <sup>[1](#scheduling)</sup>

- :x: `inotify_init()`
  <sup>[1](#monitoring-filesystem-events-inotify-fanotify)</sup>

- :x: `inotify_add_watch()`
  <sup>[1](#monitoring-filesystem-events-inotify-fanotify)</sup>

- :x: `inotify_rm_watch()`
  <sup>[1](#monitoring-filesystem-events-inotify-fanotify)</sup>

- :x: `migrate_pages()`
  <sup>[1](#memory-management)</sup>

- :ballot_box_with_check: `openat()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `mkdirat()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `mknodat()`
  <sup>[1](#pipes-and-fifos-named-pipes)</sup>

- :ballot_box_with_check: `fchownat()`
  <sup>[1](#file-system-operations)</sup>

- :x: `futimesat()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `newfstatat()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `unlinkat()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `renameat()`
  <sup>[1](#file-system-operations)</sup>

- :x: `linkat()`
  <sup>[1](#hard-links-and-soft-links-symbolic-links)</sup>

- :x: `symlinkat()`
  <sup>[1](#hard-links-and-soft-links-symbolic-links)</sup>

- :ballot_box_with_check: `readlinkat()`
  <sup>[1](#hard-links-and-soft-links-symbolic-links)</sup>

- :white_check_mark: `fchmodat()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `faccessat()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `pselect6()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>
  <sup>[5](#io-multiplexing)</sup>
  <sup>[6](#event-notifications-eventfd)</sup>

- :ballot_box_with_check: `ppoll()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>
  <sup>[5](#io-multiplexing)</sup>
  <sup>[6](#event-notifications-eventfd)</sup>

- :x: `unshare()`
  <sup>[1](#processes)</sup>
  <sup>[2](#advanced-unimplemented-features)</sup>

- :white_check_mark: `set_robust_list()`
  <sup>[1](#memory-synchronization-futexes)</sup>

- :white_check_mark: `get_robust_list()`
  <sup>[1](#memory-synchronization-futexes)</sup>

- :x: `splice()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `tee()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `sync_file_range()`
  <sup>[1](#file-system-operations)</sup>

- :x: `vmsplice()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `move_pages()`
  <sup>[1](#memory-management)</sup>

- :x: `utimensat()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `epoll_pwait()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>
  <sup>[5](#io-multiplexing)</sup>
  <sup>[6](#event-notifications-eventfd)</sup>

- :x: `signalfd()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :x: `timerfd_create()`
  <sup>[1](#sleeps-timers-and-alarms)</sup>

- :ballot_box_with_check: `eventfd()`
  <sup>[1](#event-notifications-eventfd)</sup>

- :ballot_box_with_check: `fallocate()`
  <sup>[1](#file-system-operations)</sup>

- :x: `timerfd_settime()`
  <sup>[1](#sleeps-timers-and-alarms)</sup>

- :x: `timerfd_gettime()`
  <sup>[1](#sleeps-timers-and-alarms)</sup>

- :white_check_mark: `accept4()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :x: `signalfd4()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :ballot_box_with_check: `eventfd2()`
  <sup>[1](#event-notifications-eventfd)</sup>

- :white_check_mark: `epoll_create1()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>
  <sup>[5](#io-multiplexing)</sup>
  <sup>[6](#event-notifications-eventfd)</sup>

- :white_check_mark: `dup3()`
  <sup>[1](#misc)</sup>

- :ballot_box_with_check: `pipe2()`
  <sup>[1](#pipes-and-fifos-named-pipes)</sup>

- :x: `inotify_init1()`
  <sup>[1](#monitoring-filesystem-events-inotify-fanotify)</sup>

- :white_check_mark: `preadv()`
  <sup>[1](#file-system-operations)</sup>

- :white_check_mark: `pwritev()`
  <sup>[1](#file-system-operations)</sup>

- :x: `rt_tgsigqueueinfo()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :x: `perf_event_open()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :ballot_box_with_check: `recvmmsg()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :x: `fanotify_init()`
  <sup>[1](#monitoring-filesystem-events-inotify-fanotify)</sup>

- :x: `fanotify_mark()`
  <sup>[1](#monitoring-filesystem-events-inotify-fanotify)</sup>

- :ballot_box_with_check: `prlimit64()`
  <sup>[1](#system-information-and-resource-accounting)</sup>

- :x: `name_to_handle_at()`
  <sup>[1](#file-system-operations)</sup>

- :x: `open_by_handle_at()`
  <sup>[1](#file-system-operations)</sup>

- :x: `clock_adjtime()`
  <sup>[1](#date-and-time)</sup>

- :x: `syncfs()`
  <sup>[1](#file-system-operations)</sup>

- :ballot_box_with_check: `sendmmsg()`
  <sup>[1](#tcpip-and-udpip-sockets)</sup>
  <sup>[2](#unix-domain-sockets)</sup>

- :x: `setns()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :ballot_box_with_check: `getcpu()`
  <sup>[1](#scheduling)</sup>
  <sup>[2](#misc)</sup>

- :x: `process_vm_readv()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `process_vm_writev()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `kcmp()`
  <sup>[1](#processes)</sup>

- :x: `finit_module()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `sched_setattr()`
  <sup>[1](#scheduling)</sup>

- :x: `sched_getattr()`
  <sup>[1](#scheduling)</sup>

- :x: `renameat2()`
  <sup>[1](#file-system-operations)</sup>

- :x: `seccomp()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :white_check_mark: `getrandom()`
  <sup>[1](#randomness)</sup>

- :x: `memfd_create()`
  <sup>[1](#memory-management)</sup>

- :x: `kexec_file_load()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `bpf()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `execveat()`
  <sup>[1](#processes)</sup>

- :x: `userfaultfd()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :x: `membarrier()`
  <sup>[1](#memory-management)</sup>

- :ballot_box_with_check: `mlock2()`
  <sup>[1](#memory-management)</sup>

- :x: `copy_file_range()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `preadv2()`
  <sup>[1](#file-system-operations)</sup>

- :x: `pwritev2()`
  <sup>[1](#file-system-operations)</sup>

- :x: `pkey_mprotect()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `pkey_alloc()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `pkey_free()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `statx()`
  <sup>[1](#file-system-operations)</sup>

- :x: `io_pgetevents()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `rseq()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `pidfd_send_signal()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :x: `io_uring_setup()`
  <sup>[1](#asynchronous-io)</sup>

- :x: `io_uring_enter()`
  <sup>[1](#asynchronous-io)</sup>

- :x: `io_uring_register()`
  <sup>[1](#asynchronous-io)</sup>

- :x: `open_tree()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `move_mount()`
  <sup>[1](#file-system-operations)</sup>

- :x: `fsopen()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `fsconfig()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `fsmount()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `fspick()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `pidfd_open()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :x: `clone3()`
  <sup>[1](#processes)</sup>
  <sup>[2](#threads)</sup>

- :x: `close_range()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `openat2()`
  <sup>[1](#file-system-operations)</sup>

- :x: `pidfd_getfd()`
  <sup>[1](#signals-and-process-state-changes)</sup>

- :x: `faccessat2()`
  <sup>[1](#file-system-operations)</sup>

- :x: `process_madvise()`
  <sup>[1](#memory-management)</sup>
  <sup>[2](#signals-and-process-state-changes)</sup>

- :x: `epoll_pwait2()`
  <sup>[1](#file-system-operations)</sup>
  <sup>[2](#pipes-and-fifos-named-pipes)</sup>
  <sup>[3](#tcpip-and-udpip-sockets)</sup>
  <sup>[4](#unix-domain-sockets)</sup>
  <sup>[5](#io-multiplexing)</sup>
  <sup>[6](#event-notifications-eventfd)</sup>

- :x: `mount_setattr()`
  <sup>[1](#file-system-operations)</sup>

- :x: `quotactl_fd()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `landlock_create_ruleset()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `landlock_add_rule()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `landlock_restrict_self()`
  <sup>[1](#advanced-unimplemented-features)</sup>

- :x: `memfd_secret()`
  <sup>[1](#memory-management)</sup>

- :x: `process_mrelease()`
  <sup>[1](#memory-management)</sup>
  <sup>[2](#signals-and-process-state-changes)</sup>

- :x: `futex_waitv()`
  <sup>[1](#memory-synchronization-futexes)</sup>

- :x: `set_mempolicy_home_node()`
  <sup>[1](#memory-management)</sup>

</details>

## List of pseudo-files

Gramine partially emulates Linux pseudo-filesystems: `/dev`, `/proc` and `/sys`.

Only a subset of most widely used pseudo-files is implemented. The list of implemented pseudo-files
grows with time, as Gramine adds functionality required by real world workloads.

<details><summary>:page_facing_up: List of all pseudo-files in Gramine</summary>

- :white_check_mark: `/dev/` <sup>[1](#hard-links-and-soft-links-symbolic-links)</sup>
  <sup>[2](#semaphores)</sup> <sup>[3](#shared-memory)</sup> <sup>[4](#attestation)</sup>

  - :white_check_mark: `/dev/attestation/` <sup>[1](#attestation)</sup>
    - :white_check_mark: `/dev/attestation/attestation_type` <sup>[1](#attestation)</sup>
    - :white_check_mark: `/dev/attestation/user_report_data` <sup>[1](#attestation)</sup>
    - :white_check_mark: `/dev/attestation/target_info` <sup>[1](#attestation)</sup>
    - :white_check_mark: `/dev/attestation/my_target_info` <sup>[1](#attestation)</sup>
    - :white_check_mark: `/dev/attestation/report` <sup>[1](#attestation)</sup>
    - :white_check_mark: `/dev/attestation/keys` <sup>[1](#attestation)</sup>
      - :white_check_mark: `/dev/attestation/keys/<key_name>` <sup>[1](#attestation)</sup>
    - :ballot_box_with_check: `/dev/attestation/protected_files_key`
      <sup>[1](#attestation)</sup>
  - :white_check_mark: `/dev/null` <sup>[1](#misc)</sup>
  - :white_check_mark: `/dev/zero` <sup>[1](#misc)</sup>
  - :white_check_mark: `/dev/random` <sup>[1](#randomness)</sup>
  - :white_check_mark: `/dev/urandom` <sup>[1](#randomness)</sup>
  - :x: `/dev/shm` <sup>[1](#semaphores)</sup> <sup>[2](#shared-memory)</sup>
  - :white_check_mark: `/dev/stdin` <sup>[1](#hard-links-and-soft-links-symbolic-links)</sup>
  - :white_check_mark: `/dev/stdout` <sup>[1](#hard-links-and-soft-links-symbolic-links)</sup>
  - :white_check_mark: `/dev/stderr` <sup>[1](#hard-links-and-soft-links-symbolic-links)</sup>

- :ballot_box_with_check: `/proc/`
  <sup>[1](#process-and-thread-identifiers)</sup>
  <sup>[2](#user-and-group-identifiers)</sup>
  <sup>[3](#hard-links-and-soft-links-symbolic-links)</sup>
  <sup>[4](#system-information-and-resource-accounting)</sup>
  <sup>[5](#tcpip-and-udpip-sockets)</sup> <sup>[6](#unix-domain-sockets)</sup>
  - :ballot_box_with_check: `/proc/[this-pid]/` (aka `/proc/self/`)
    <sup>[1](#process-and-thread-identifiers)</sup>
    <sup>[2](#hard-links-and-soft-links-symbolic-links)</sup>
    - :white_check_mark: `/proc/[this-pid]/cmdline` <sup>[1](#process-and-thread-identifiers)</sup>
    - :white_check_mark: `/proc/[this-pid]/cwd` <sup>[1](#process-and-thread-identifiers)</sup>
      <sup>[2](#hard-links-and-soft-links-symbolic-links)</sup>
    - :white_check_mark: `/proc/[this-pid]/exe` <sup>[1](#process-and-thread-identifiers)</sup>
      <sup>[2](#hard-links-and-soft-links-symbolic-links)</sup>
    - :white_check_mark: `/proc/[this-pid]/fd` <sup>[1](#process-and-thread-identifiers)</sup>
    - :white_check_mark: `/proc/[this-pid]/maps` <sup>[1](#process-and-thread-identifiers)</sup>
    - :white_check_mark: `/proc/[this-pid]/root` <sup>[1](#process-and-thread-identifiers)</sup>
      <sup>[2](#hard-links-and-soft-links-symbolic-links)</sup>
    - :ballot_box_with_check: `/proc/[this-pid]/stat`
      <sup>[1](#process-and-thread-identifiers)</sup>
    - :ballot_box_with_check: `/proc/[this-pid]/statm`
      <sup>[1](#process-and-thread-identifiers)</sup>
    - :ballot_box_with_check: `/proc/[this-pid]/status`
      <sup>[1](#process-and-thread-identifiers)</sup>
      <sup>[2](#user-and-group-identifiers)</sup>
    - :white_check_mark: `/proc/[this-pid]/task` <sup>[1](#process-and-thread-identifiers)</sup>

  - :ballot_box_with_check: `/proc/[remote-pid]/`
    <sup>[1](#process-and-thread-identifiers)</sup>
    <sup>[2](#hard-links-and-soft-links-symbolic-links)</sup>
    - :white_check_mark: `/proc/[remote-pid]/cwd` <sup>[1](#process-and-thread-identifiers)</sup>
      <sup>[2](#hard-links-and-soft-links-symbolic-links)</sup>
    - :white_check_mark: `/proc/[remote-pid]/exe` <sup>[1](#process-and-thread-identifiers)</sup>
      <sup>[2](#hard-links-and-soft-links-symbolic-links)</sup>
    - :white_check_mark: `/proc/[remote-pid]/root` <sup>[1](#process-and-thread-identifiers)</sup>
      <sup>[2](#hard-links-and-soft-links-symbolic-links)</sup>

  - :ballot_box_with_check: `/proc/[local-tid]/`
    <sup>[1](#process-and-thread-identifiers)</sup>

  - :x: `/proc/[remote-tid]/` <sup>[1](#process-and-thread-identifiers)</sup>

  - :ballot_box_with_check: `/proc/cpuinfo`
    <sup>[1](#system-information-and-resource-accounting)</sup>
  - :ballot_box_with_check: `/proc/meminfo`
    <sup>[1](#system-information-and-resource-accounting)</sup>
  - :ballot_box_with_check: `/proc/stat`
    <sup>[1](#system-information-and-resource-accounting)</sup>

  - :ballot_box_with_check: `/proc/sys/`
    <sup>[1](#process-and-thread-identifiers)</sup>
    <sup>[2](#tcpip-and-udpip-sockets)</sup> <sup>[3](#unix-domain-sockets)</sup>
    - :ballot_box_with_check: `/proc/sys/kernel/`
      <sup>[1](#process-and-thread-identifiers)</sup>
      - :white_check_mark: `/proc/sys/kernel/pid_max`
        <sup>[1](#process-and-thread-identifiers)</sup>
    - :x: `/proc/sys/net/` <sup>[1](#tcpip-and-udpip-sockets)</sup>
      <sup>[2](#unix-domain-sockets)</sup>
      - :x: `/proc/sys/net/core/` <sup>[1](#tcpip-and-udpip-sockets)</sup>
      - :x: `/proc/sys/net/ipv4/` <sup>[1](#tcpip-and-udpip-sockets)</sup>
      - :x: `/proc/sys/net/ipv6/` <sup>[1](#tcpip-and-udpip-sockets)</sup>
      - :x: `/proc/sys/net/unix/` <sup>[1](#unix-domain-sockets)</sup>

- :ballot_box_with_check: `/sys/devices/system/`
  <sup>[1](#system-information-and-resource-accounting)</sup>
  - :ballot_box_with_check: `/sys/devices/system/cpu/`
    <sup>[1](#system-information-and-resource-accounting)</sup>
    - :ballot_box_with_check: `/sys/devices/system/cpu/cpu[x]/`
      <sup>[1](#system-information-and-resource-accounting)</sup>
      - :ballot_box_with_check: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/`
        <sup>[1](#system-information-and-resource-accounting)</sup>
        - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/coherency_line_size`
          <sup>[1](#system-information-and-resource-accounting)</sup>
        - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/level`
          <sup>[1](#system-information-and-resource-accounting)</sup>
        - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/number_of_sets`
          <sup>[1](#system-information-and-resource-accounting)</sup>
        - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/physical_line_partition`
          <sup>[1](#system-information-and-resource-accounting)</sup>
        - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/shared_cpu_map`
          <sup>[1](#system-information-and-resource-accounting)</sup>
        - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/size`
          <sup>[1](#system-information-and-resource-accounting)</sup>
        - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/type`
          <sup>[1](#system-information-and-resource-accounting)</sup>
      - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/online`
        <sup>[1](#system-information-and-resource-accounting)</sup>
      - :ballot_box_with_check: `/sys/devices/system/cpu/cpu[x]/topology/`
        <sup>[1](#system-information-and-resource-accounting)</sup>
        - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/topology/core_id`
          <sup>[1](#system-information-and-resource-accounting)</sup>
        - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/topology/core_siblings`
          <sup>[1](#system-information-and-resource-accounting)</sup>
        - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/topology/physical_package_id`
          <sup>[1](#system-information-and-resource-accounting)</sup>
        - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/topology/thread_siblings`
          <sup>[1](#system-information-and-resource-accounting)</sup>
    - :white_check_mark: `/sys/devices/system/cpu/online`
      <sup>[1](#system-information-and-resource-accounting)</sup>
    - :white_check_mark: `/sys/devices/system/cpu/possible`
      <sup>[1](#system-information-and-resource-accounting)</sup>

  - :ballot_box_with_check: `/sys/devices/system/node/`
    <sup>[1](#system-information-and-resource-accounting)</sup>
    - :ballot_box_with_check: `/sys/devices/system/node/node[x]/`
      <sup>[1](#system-information-and-resource-accounting)</sup>
      - :white_check_mark: `/sys/devices/system/node/node[x]/cpumap`
        <sup>[1](#system-information-and-resource-accounting)</sup>
      - :white_check_mark: `/sys/devices/system/node/node[x]/distance`
        <sup>[1](#system-information-and-resource-accounting)</sup>
      - :white_check_mark: `/sys/devices/system/node/node[x]/hugepages/`
        <sup>[1](#system-information-and-resource-accounting)</sup>
        - :ballot_box_with_check:
          `/sys/devices/system/node/node[x]/hugepages/hugepages-[y]/nr_hugepages`
          <sup>[1](#system-information-and-resource-accounting)</sup>
      - :ballot_box_with_check: `/sys/devices/system/node/node[x]/meminfo`
        <sup>[1](#system-information-and-resource-accounting)</sup>

</details>

## Linux features

### Processes

Gramine supports multi-processing. A Gramine instance starts the first (main) process, as specified
in the entrypoint of the manifest. The first process can spawn child processes, which belong to the
same Gramine instance.

Gramine can execute ELF binaries (executables and libraries) and scripts (aka shebangs). Gramine
supports executing them as
[entrypoints](https://gramine.readthedocs.io/en/stable/manifest-syntax.html#libos-entrypoint) and
via `execve()` system call. In case of SGX backend, `execve()` execution replaces a calling program
with a new program *in the same SGX enclave*.

Gramine supports creating child processes using `fork()`, `vfork()` and `clone(..no CLONE_VM..)`
system calls. `vfork()` is emulated via `fork()`. `clone(..no CLONE_VM..)` always means a separate
process with its own address space (i.e., `CLONE_THREAD`, `CLONE_FILES`, etc. flags cannot be
specified). In case of SGX backend, child processes are created *in a new SGX enclave*.

Currently, Gramine does *not* fully support fork in multi-threaded applications. There is a known
bug in Gramine that if one thread is performing fork and another thread modifies the internal
Gramine state, the state may get corrupted (which may lead to failures).

Gramine supports process termination using `exit()` (if a single thread) and `exit_group()` (even if
multiple threads) system calls. If there are child processes executing and the first process exits,
Gramine currently does *not* kill child processes; this is however not a problem in practice because
the host OS cleans up these orphaned children.

All aforementioned system calls follow Linux semantics, barring the mentioned peculiarities.
However, properties of processes not supported by Gramine (e.g. namespaces, pidfd, etc.) are
ignored.

Gramine does *not* support disassociating parts of the process execution context (via `unshare()`
system call). Gramine does *not* support comparing two processes (via `kcmp()`).

<details><summary>:blue_book: Related system calls</summary>

- :white_check_mark: `execve()`
- :x: `execveat()`: not used by applications
- :white_check_mark: `clone()`: except exotic combination `CLONE_VM & !CLONE_THREAD`
- :white_check_mark: `fork()`
- :white_check_mark: `vfork()`: with the same semantics as `fork()`
- :white_check_mark: `exit()`
- :white_check_mark: `exit_group()`
- :x: `clone3()`: not used by applications
- :x: `unshare()`: not used by applications
- :x: `kcmp()`: not used by applications

</details>

<details><summary>:speech_balloon: Additional materials</summary>

- `LD_LIBRARY_PATH` environment variable is always propagated into new process, see
  https://github.com/gramineproject/graphene/issues/2081.

</details>

### Threads

Gramine implements multi-threading. In case of SGX backend, all threads of one Gramine process run
in the same SGX enclave.

Gramine implements per-thread:
- stack and signal (alternate) stack,
- user/group IDs,
- thread groups info,
- signal mask, signal dispositions, signal queue,
- futex robust list,
- CPU affinity mask.

Gramine supports creating threads using `clone(.. CLONE_VM | CLONE_THREAD ..)` system call and
destroying threads using `exit()` system call.

Gramine does *not* support manipulations of thread-local storage information (via
`get_thread_area()` and `set_thread_area()` system calls). Instead, Gramine supports setting
arch-specific (x86-specific) thread state via `arch_prctl(ARCH_GET_FS)` and
`arch_prctl(ARCH_SET_FS)`. Note that Gramine does *not* allow `arch_prctl(ARCH_GET_GS)` and
`arch_prctl(ARCH_SET_GS)` -- the GS register is reserved for Gramine internal usage.

<details><summary>:warning: Note on thread's stack size</summary>

Gramine sets the same stack size for each thread. In other words, Gramine does *not* support
dynamically-growing stacks (as Linux does). The stack size in Gramine can be configured via the
[`sys.stack.size` manifest
option](https://gramine.readthedocs.io/en/stable/manifest-syntax.html#stack-size).

</details>

<details><summary>:blue_book: Related system calls</summary>

- :white_check_mark: `clone()`: must have combination `CLONE_VM | CLONE_THREAD`
- :white_check_mark: `exit()`
- :x: `get_thread_area()`: not used by applications
- :x: `set_thread_area()`: not used by applications
- :x: `prctl()`: not used by applications
- :ballot_box_with_check: `arch_prctl()`: only x86-specific subset of flags
  - :white_check_mark: `ARCH_GET_FS`
  - :white_check_mark: `ARCH_SET_FS`
  - :x: `ARCH_GET_GS`
  - :x: `ARCH_SET_GS`
- :x: `clone3()`: not used by applications

</details>

### Process and thread identifiers

Gramine supports the following identifiers: Process IDs (PIDs), Parent Process IDs (PPIDs),
Thread IDs (TIDs). The corresponding system calls are `getpid()`, `getppid()`, `gettid()`,
`set_tid_address()`.

Gramine has dummy support for Process Group IDs (PGIDs): PGID can only be get/set for the current
process. It is impossible to get/set PGIDs of other (e.g. child) processes. The corresponding system
calls are `getpgid()`, `getpgrp()`, `setpgid()`.

Gramine virtualizes process/thread identifiers. In other words, in-Gramine PIDs and TIDs have no
correlation with host-OS PIDs and TIDs. Each Gramine instance starts a main process with PID 1.

Gramine implements a subset of pseudo-files under `/proc/[pid]`: more pseudo-files for the current
process (aka `/proc/self`) and its threads, less pseudo-files for remote processes (e.g. children),
and no pseudo-files for remote threads. See the list under "Related pseudo-files".

<details><summary>:blue_book: Related system calls</summary>

- :white_check_mark: `getpid()`
- :white_check_mark: `getppid()`
- :white_check_mark: `gettid()`
- :white_check_mark: `set_tid_address()`

- :ballot_box_with_check: `getpgid()`: dummy, see above
- :ballot_box_with_check: `setpgid()`: dummy, see above
- :ballot_box_with_check: `getpgrp()`: dummy, see above

</details>

<details><summary>:page_facing_up: Related pseudo-files</summary>

- :ballot_box_with_check: `/proc/[this-pid]/` (aka `/proc/self/`):
  only most important files implemented
  - :white_check_mark: `/proc/[this-pid]/cmdline`
  - :white_check_mark: `/proc/[this-pid]/cwd`
  - :white_check_mark: `/proc/[this-pid]/exe`
  - :white_check_mark: `/proc/[this-pid]/fd`
  - :white_check_mark: `/proc/[this-pid]/maps`
  - :white_check_mark: `/proc/[this-pid]/root`
  - :ballot_box_with_check: `/proc/[this-pid]/stat`: partially implemented
    - :white_check_mark: `pid`, `comm`, `ppid`, `pgrp`, `num_threads`, `vsize`, `rss`
    - :ballot_box_with_check: `state`: always indicates "R" (running)
    - :ballot_box_with_check: `flags`: indicates only `PF_RANDOMIZE`
    - :x: rest fields: always zero
  - :ballot_box_with_check: `/proc/[this-pid]/statm`: partially implemented
    - :white_check_mark: `size`/`VmSize`, `resident`/`VmRSS`
    - :x: rest fields: always zero
  - :ballot_box_with_check: `/proc/[this-pid]/status`: partially implemented
    - :white_check_mark: `VmPeak`
    - :x: rest fields: not printed
  - :white_check_mark: `/proc/[this-pid]/task`

- :ballot_box_with_check: `/proc/[remote-pid]/`: minimally implemented
  - :white_check_mark: `/proc/[remote-pid]/cwd`
  - :white_check_mark: `/proc/[remote-pid]/exe`
  - :white_check_mark: `/proc/[remote-pid]/root`

- :ballot_box_with_check: `/proc/[local-tid]/`: same as `/proc/[this-pid]`

- :x: `/proc/[remote-tid]/`: not used by applications

- :white_check_mark: `/proc/sys/kernel/pid_max`

</details>

### Scheduling

Gramine does *not* perform scheduling of threads, instead it relies on the host OS to perform
scheduling. In case of SGX backend, trying to perform or control scheduling would be futile because
SGX threat model has no means of control or verification of scheduling decisions of the host OS.

Gramine fully implements only a few scheduling system calls: `sched_yield()`, `sched_getaffinity()`,
`sched_setaffinity()`. Most other scheduling system calls in Gramine have dummy implementations:
they return some default sensible values and they do not send requests to the host OS. Finally,
`sched_getattr()` and `sched_setattr()` are not implemented in Gramine, as no applications use them.
In other words, applications running in Gramine cannot set scheduling policy or thread priorities,
and they cannot learn currently-used policy and priorities of the host OS. See the list under
"Related system calls".

These dummy implementations serve Gramine well. We have not yet encountered applications that would
significantly benefit from scheduling system calls being properly implemented in Gramine.

To support CPU affinity masks and expose NUMA/CPU topology, Gramine implements
`/sys/devices/system/cpu/` and `/sys/devices/system/node/` pseudo-files. See the list in the
["System information and resource accounting" section](#system-information-and-resource-accounting).

<details><summary>:blue_book: Related system calls</summary>

- :white_check_mark: `sched_yield()`
- :white_check_mark: `sched_getaffinity()`
- :white_check_mark: `sched_setaffinity()`

- :ballot_box_with_check: `getcpu()`: dummy, returns a random allowed CPU
- :ballot_box_with_check: `getpriority()`: dummy, returns default value
- :ballot_box_with_check: `setpriority()`: dummy, does nothing
- :ballot_box_with_check: `sched_getparam()`: dummy, returns default values
- :ballot_box_with_check: `sched_setparam()`: dummy, does nothing
- :ballot_box_with_check: `sched_getscheduler()`: dummy, returns default value
- :ballot_box_with_check: `sched_setscheduler()`: dummy, does nothing
- :ballot_box_with_check: `sched_get_priority_max()`: dummy, returns default
  value
- :ballot_box_with_check: `sched_get_priority_min()`: dummy, returns default
- :ballot_box_with_check: `sched_rr_get_interval()`: dummy, returns default
  value

- :x: `sched_getattr()`: not used by applications
- :x: `sched_setattr()`: not used by applications
- :x: `ioprio_get()`: not used by applications
- :x: `ioprio_set()`: not used by applications

</details>

### Memory synchronization (futexes)

Gramine partially implements futexes.

Current implementation is limited to one process, i.e., threads calling the `futex()` system call on
the same futex word must reside in the same process. Gramine does *not* support non-private futexes,
thus Gramine always assumes the `FUTEX_PRIVATE_FLAG` flag. We have not yet encountered applications
that would require inter-process futexes.

Gramine ignores the `FUTEX_CLOCK_REALTIME` flag.

Gramine supports the following futex operations: `FUTEX_WAIT`, `FUTEX_WAIT_BITSET`, `FUTEX_WAKE`,
`FUTEX_WAKE_BITSET`, `FUTEX_WAKE_OP`, `FUTEX_REQUEUE`, `FUTEX_CMP_REQUEUE`. Priority-inheritance
(PI) futexes and operations on them are *not* supported.

Gramine implements getting/setting the list of robust futexes, via `get_robust_list()` and
`set_robust_list()` system calls.

<details><summary>:blue_book: Related system calls</summary>

- :ballot_box_with_check: `futex()`: see notes above
- :white_check_mark: `get_robust_list()`
- :white_check_mark: `set_robust_list()`

- :x: `futex_waitv()`: not used by applications

</details>

### Memory management

Gramine implements memory-management system calls: `mmap()`, `mprotect()`, `munmap()`, `brk()`, etc.
Some exotic flags and features are not implemented, but we didn't observe any applications that
would fail or behave incorrectly because of that.

`mmap()` supports anonymous (`MAP_ANONYMOUS`) and file-backed (`MAP_FILE`) mappings. All commonly
used flags like `MAP_SHARED`, `MAP_PRIVATE`, `MAP_FIXED`, `MAP_FIXED_NOREPLACE`, `MAP_STACK`,
`MAP_GROWSDOWN`, `MAP_32BIT` are supported.

In case of SGX backend, `MAP_SHARED` flag is ignored for anonymous mappings, and for file-backed
mappings, it depends on the type of file:
- disallowed for trusted files (these files are read-only, thus the flag is meaningless),
- disallowed for allowed files (for security reasons: it would be easy to abuse it),
- allowed for encrypted files (but synchronization happens only on explicit system calls like
  `msync()` and `close()`).

`MAP_LOCKED`, `MAP_NORESERVE`, `MAP_POPULATE`, `MAP_NONBLOCK`, `MAP_HUGETLB`, `MAP_HUGE_2MB`,
`MAP_HUGE_1GB` flags are ignored (allowed but have no effect). `MAP_SYNC` flag is not supported.

`mprotect()` supports all flags except `PROT_SEM` and `PROT_GROWSUP`. We haven't encountered any
applications that would use these flags. In case of SGX backend, `mprotect()` behavior differs:
- on [EDMM-enabled systems](https://gramine.readthedocs.io/en/stable/sgx-intro.html#term-edmm),
  `mprotect()` correctly applies permissions;
- on non-EDMM-enabled systems, all enclave memory is allocated with Read-Write-Execute permissions,
  and `mprotect()` calls are silently ignored.

`madvise()` implements only a minimal subset of functionality:
- `MADV_DONTNEED` is partially supported:
  - resetting writable file-backed mappings is not implemented;
  - zeroing non-writable mappings is not implemented;
  - all other cases are implemented.
- `MADV_NORMAL`, `MADV_RANDOM`, `MADV_SEQUENTIAL`, `MADV_WILLNEED`, `MADV_FREE`,
  `MADV_SOFT_OFFLINE`, `MADV_MERGEABLE`, `MADV_UNMERGEABLE`, `MADV_HUGEPAGE`, `MADV_NOHUGEPAGE` are
  ignored (allowed but have no effect).
- All other advice values are not supported.

Gramine does *not* support anonymous files (created via `memfd_create()`).

Quick summary of other memory-management system calls:
- `munmap()` has nothing of note;
- `mremap()` is not implemented (not used by applications);
- `msync()` implements only `MS_SYNC` and `MS_ASYNC` (`MS_INVALIDATE` is not implemented);
- `mbind()` is a no-op;
- `mincore()` always tells that pages are *not* in RAM;
- `set_mempolicy()` and `get_mempolicy` are not implemented;
- `mlock()`, `munlock()`, `mlockall()`, `munlockall()`, `mlock2()` are dummy (always return
  success).

As can be seen from above, many performance-improving system calls, flags and features are currently
*not* implemented by Gramine. Keep it in mind when you observe application performance degradation.

<details><summary>:blue_book: Related system calls</summary>

- :white_check_mark: `brk()`
- :ballot_box_with_check: `mmap()`: see above for notes
- :ballot_box_with_check: `mprotect()`: see above for notes
- :white_check_mark: `munmap()`

- :ballot_box_with_check: `msync()`: does not implement `MS_INVALIDATE`
- :ballot_box_with_check: `madvise()`: see above for notes
- :ballot_box_with_check: `mbind()`: dummy
- :ballot_box_with_check: `mincore()`: dummy
- :ballot_box_with_check: `mlock()`: dummy
- :ballot_box_with_check: `munlock()`: dummy
- :ballot_box_with_check: `mlockall()`: dummy
- :ballot_box_with_check: `munlockall()`: dummy
- :ballot_box_with_check: `mlock2()`: dummy

- :x: `mremap()`: not used by applications
- :x: `remap_file_pages()`: not used by applications
- :x: `set_mempolicy()`: may be implemented in future
- :x: `get_mempolicy()`: may be implemented in future
- :x: `memfd_create()`: may be implemented in future
- :x: `memfd_secret()`: not used by applications
- :x: `membarrier()`: may be implemented in future
- :x: `move_pages()`: not used by applications
- :x: `migrate_pages()`: not used by applications
- :x: `process_madvise()`: not used by applications
- :x: `process_mrelease()`: not used by applications
- :x: `set_mempolicy_home_node()`: not used by applications

</details>

### Overview of Inter-Process Communication (IPC)

Gramine implements most of the Linux IPC mechanisms. In particular:

- :white_check_mark: Signals and process state changes
- :white_check_mark: Pipes
- :white_check_mark: FIFOs (named pipes)
- :ballot_box_with_check: UNIX domain sockets
- :ballot_box_with_check: File locking
- :x: Message queues
- :x: Semaphores
- :x: Shared memory

Gramine implements pipes, FIFOs and UNIX domain sockets (UDSes) via host-OS pipes. In case of SGX
backend, all pipe, FIFO and UDS communication is transparently encrypted.

For all other IPC mechanisms -- currently these are signals, process state changes, file locks --
Gramine emulates them via internal message passing (in case of SGX, all messages are encrypted).

Thus, Gramine implements all IPC primitives using a single host-OS primitive: pipes. This design
choice means that Gramine is a *distributed* Library OS, in contrast to the Linux kernel which is
monolithic. Each Gramine process knows only about its own state and must query peer Gramine
processes to learn their state; compare it to the Linux kernel which keeps a single state for all
processes running on top of it. Thus, all IPC in Gramine is performed using message passing over
host-OS pipes. To govern this message passing, the first Gramine process is designated a *leader*
which controls all message requests/responses among processes in one Gramine instance. For example,
if one Gramine process spawns a new child, it requests the leader to assign a PID for this child. As
another example, all POSIX-locking operations are synchronized using a special messaging protocol
that is managed by the leader.

Because of this Gramine peculiarity, IPC-intensive applications may experience performance
degradation. Also, some IPC-related system calls and pseudo-files are not implemented in Gramine due
to the complexity of message-passing implementation.

To learn more about Gramine support for each of the Linux IPC mechanisms, refer to corresponding
sections below.

<details><summary>:speech_balloon: Additional materials</summary>

- For Linux IPC overview, we recommend reading [Beej's Guide to Unix
  IPC](https://beej.us/guide/bgipc/html/single/bgipc.html).

- In case of SGX backend, pipes, FIFOs, UDSes and all other IPC communication are encrypted using
  the TLS-PSK (TLS with Pre-Shared Keys) protocol. The pre-shared key is randomly generated for each
  new Gramine instance. Before establishing any pipe/IPC communication, two Gramine processes (e.g.,
  parent and child) verify each other's trustworthiness using SGX local attestation.

</details>

### Signals and process state changes

Gramine partially implements signals (see below for some limitations). For local signals (Gramine
process signals itself, e.g. SIGABRT) and signals from the host OS (e.g. host sends SIGTERM),
message passing is not involved. For process-to-process signals (e.g. child process sends SIGCHLD to
the parent), message passing is used.

Gramine supports both standard signals and POSIX real-time signals. Queueing and delivery semantics
are the same as in Linux. Per-thread signal masks are supported. Restart of system calls after
signal handling (if flag `SA_RESTART` was specified) is supported.

Gramine implements signal dispositions, but some rarely used features are not implemented:
- core dump files are never produced,
- `SA_NOCLDSTOP` and `SA_NOCLDWAIT` signal-behavior flags are ignored,
- only fields `si_signo`, `si_code`, `si_pid`, `si_uid`, `si_status`, `si_addr` in the data type
  `siginfo_t` are populated.

Gramine supports injecting a [single SIGTERM signal from the
host](https://gramine.readthedocs.io/en/stable/manifest-syntax.html#external-sigterm-injection). No
other signals from the host are supported. By default, Gramine ignores all signals sent by the host
(including signals sent from other applications or from other Gramine instances). This limitation is
for security reasons, relevant on SGX backend.

Gramine has some limitations on sending signals to processes and threads:
- sending a signal to a process group is not supported (e.g. `kill(0)` sends the signal only to the
  current process but not to other processes),
- `tkill()` system call cannot send signals to threads in other processes.

Gramine supports waiting for signals (via `pause()`, `rt_sigsuspend()`, etc. system calls).

Gramine supports waiting for processes via `wait4()` and `waitid()` system calls. However,
`WSTOPPED` and `WCONTINUED` options are not supported (we didn't encounter applications that rely on
these options). Zombie processes are supported, though the "zombie" state is not reported in
`/proc/[pid]/stat` pseudo-file.

Gramine does *not* currently support file descriptors for signals (via `signalfd()`). Also, since
Gramine does not currently support pidfd, sending a signal via `pidfd_send_signal()` is not
implemented. Gramine also does *not* support file descriptors for handling page faults (via
`userfaultfd()`).

Gramine has limited support for pseudo-files that describe the state of remote processes/threads
(files under `/proc/[remote-pid]/` and `/proc/[remote-tid]/`). For details, refer to "Related
pseudo-files" in the ["Process and thread identifiers" section](#process-and-thread-identifiers).

<details><summary>:blue_book: Related system calls</summary>

- :white_check_mark: `pause()`
- :white_check_mark: `rt_sigaction()`
- :white_check_mark: `rt_sigpending()`
- :white_check_mark: `rt_sigprocmask()`
- :white_check_mark: `rt_sigreturn()`
- :white_check_mark: `rt_sigsuspend()`
- :white_check_mark: `rt_sigtimedwait()`
- :white_check_mark: `sigaltstack()`

- :x: `rt_sigqueueinfo()`: not used by applications
- :x: `rt_tgsigqueueinfo()`: not used by applications
- :x: `signalfd()`: not used by applications
- :x: `signalfd4()`: not used by applications
- :x: `pidfd_open()`: not used by applications
- :x: `pidfd_getfd()`: not used by applications
- :x: `pidfd_send_signal()`: not used by applications
- :x: `process_madvise()`: not used by applications
- :x: `process_mrelease()`: not used by applications
- :x: `userfaultfd()`: not used by applications

- :ballot_box_with_check: `kill()`: process groups not supported
- :ballot_box_with_check: `tkill()`: remote threads not supported
- :white_check_mark: `tgkill()`

- :ballot_box_with_check: `wait4()`: `WSTOPPED` and `WCONTINUED` not supported
- :ballot_box_with_check: `waitid()`: `WSTOPPED` and `WCONTINUED` not supported

</details>

### User and group identifiers

Gramine has dummy support for the following identifiers:
- Real user ID (UID) and Real group ID (GID),
- Effective user ID (EUID) and Effective group ID (EGID),
- Saved set-user-ID (SUID) and Saved set-group-ID (SGID).

The corresponding system calls are:
- `getuid()`, `getgid()`, `setuid()`, `setgid()` for UID and GID (implemented);
- `geteuid()`, `getegid()` for EUID and EGID (implemented);
- `setreuid()`, `setregid()` for UID + EUID and GID + EGID (not implemented);
- `getresuid()`, `setresuid()`, `getresgid()`, `setresgid()` for UID + EUID + SUID
  and GID + EGID + SGID (not implemented).

Gramine starts the application with UID = EUID = SUID and equal to
[`loader.uid`](https://gramine.readthedocs.io/en/stable/manifest-syntax.html#user-id-and-group-id).
Similarly, the application is started with GID = EGID = SGID and equal to `loader.gid`. If these
manifest options are not set, then all IDs are equal to zero, which means root user.

During execution, the application may modify these IDs, and the changes will be visible internally
in Gramine but will *not* propagate to the host OS.

Gramine does *not* support Filesystem user ID (FSUID) and filesystem group ID (FSGID). The
corresponding system calls are `setfsuid()` and `setfsgid()` (not implemented).

Gramine has dummy support for Supplementary group IDs. The corresponding system calls are
`getgroups()` and `setgroups()`. Gramine starts the applications with an empty set of supplementary
groups. The application may modify this set, and the changes will be visible internally in Gramine
but will *not* propagate to the host OS.

Currently, there are only two usages of user/group IDs in Gramine:
- changing ownership of a file via `chown()` and similar system calls;
- injecting SIGCHLD on terminated child processes.

Gramine does *not* currently implement user/group ID fields in the `/proc/[pid]/status` pseudo-file.

<details><summary>:blue_book: Related system calls</summary>

- :ballot_box_with_check: `getuid()`: dummy
- :ballot_box_with_check: `getgid()`: dummy
- :ballot_box_with_check: `setuid()`: dummy
- :ballot_box_with_check: `setgid()`: dummy
- :ballot_box_with_check: `geteuid()`: dummy
- :ballot_box_with_check: `getegid()`: dummy
- :ballot_box_with_check: `getgroups()`: dummy
- :ballot_box_with_check: `setgroups()`: dummy

- :x: `setreuid()`: not used by applications, may be implemented in future
- :x: `setregid()`: not used by applications, may be implemented in future
- :x: `getresuid()`: not used by applications, may be implemented in future
- :x: `setresuid()`: not used by applications, may be implemented in future
- :x: `getresgid()`: not used by applications, may be implemented in future
- :x: `setresgid()`: not used by applications, may be implemented in future
- :x: `setfsuid()`: not used by applications
- :x: `setfsgid()`: not used by applications

</details>

<details><summary>:page_facing_up: Related pseudo-files</summary>

- :x: `/proc/[this-pid]/status`: fields `Uid`, `Gid`, `Groups` are not implemented

</details>

### File systems

Gramine implements file system operations, but with several peculiarities and limitations.

The most important peculiarity is that Gramine does *not* simply mirror the host OS's directory
hierarchy. Instead, Gramine constructs its own view on the selected subset of host's directories and
files: this is controlled by the manifest's [FS mount points (`fs.mounts`)](
). This feature is similar to the *chroot* concept on Linux and *jail* concept on FreeBSD. This
Gramine feature is introduced for security.

Another peculiarity is that Gramine provides several types of files:
- plain files (unencrypted files, see below),
- encrypted files (files that are automatically encrypted and integrity-protected).

In case of SGX backend, plain files must be of one of two kinds:
- allowed files (insecure, not protected in any way, only for testing purposes),
- trusted files (secure, cryptographically hashed).

Additionally, files may be hosted in one of two ways:
- on the host OS (passthrough-to-host, in *chroot* mounts),
- inside the Gramine process (in *tmpfs* mounts).

The types of all files potentially used by the application must be specified in the manifest file.
Instead of single files, whole directories can be specified. Refer to the [manifest documentation for
more details](https://gramine.readthedocs.io/en/stable/manifest-syntax.html).

Gramine also provides a subset of pseudo-files that can be found in a Linux kernel. In particular,
Gramine automatically populates `/proc`, `/dev` and `/sys` pseudo-filesystems with most widely used
pseudo-files. The complete list can be found in the ["List of pseudo-files"
section](#list-of-pseudo-files).

The final peculiarity is that Gramine is a *distributed* Library OS, as discussed in ["Overview of
Inter-Process Communication (IPC)" section](#overview-of-inter-process-communication-ipc). This
means that each Gramine process knows only about its own FS state at any point in time, and must
consult the host OS and/or other Gramine processes to learn about any updates. Synchronizing the FS
state is a difficult task, and Gramine has only limited support for file sync. For example, two
Gramine processes may want to append data to the same file, but Gramine currently does not
synchronize such accesses, thus the file contents will be incorrectly overwritten.

Internally, FS implementation in Gramine follows the one in Linux kernel. Gramine implements a
Virtual File System (VFS), a uniform interface for various mount types. Gramine also has the
concepts of dentries (cached directory/file names for fast lookup) and inodes (metadata about
files).

Gramine does *not* implement full filesystem stack by design. Gramine relies on the host filesystem
for most operations. The only exceptions are the tmpfs filesystem and the pseudo-filesystems
(implemented entirely inside Gramine).

General FS limitations in Gramine include:
- no support for dynamic mounting: all mounts must be specified beforehand in the manifest;
- no operations across mounts (e.g. no rename of file located in one mount to another one);
- no synchronization of file offsets, file sizes, etc. between Gramine processes;
- tmpfs mounts (in-memory file systems) are not shared by Gramine processes;
- File timestamps (access, modified, change timestamps) are not set/updated.

<details><summary>:speech_balloon: Additional materials</summary>

A mechanism for FS synchronization, as well as a general redesign of certain FS components, is a
task Gramine will tackle in the future. Below are some discussions and RFCs:

- https://github.com/gramineproject/graphene/issues/2158
- https://github.com/gramineproject/gramine/issues/12
- https://github.com/gramineproject/gramine/issues/584
- https://github.com/gramineproject/gramine/issues/578

</details>

#### File system operations

Gramine implements all classic file system operations, but with limitations described below.

Gramine supports opening files and directories (via `open()` and `openat()` system calls).
`O_CLOEXEC`, `O_CREAT`, `O_DIRECTORY`, `O_EXCL`, `O_NOFOLLOW`, `O_PATH`, `O_TRUNC` flags are
supported. Other flags are ignored. Notable ignored flags are `O_APPEND` (not yet implemented in
Gramine) and `O_TMPFILE` (bug in Gramine: should not be silently ignored).

Trusted files can be opened only for read. Already-existing encrypted files can be opened only if
they were not moved or renamed on the host (this is for protection against file renaming attacks).

Gramine supports creating files and directories (via `creat()`, `mkdir()`, `mkdirat()` system
calls), reading directories (via `getdents()`), deleting files and directories (via `unlink()`,
`unlinkat()`, `rmdir()`), renaming files and directories (via `rename()` and `renameat()`).

Gramine supports read and write operations on files. Appending to files is currently unsupported.
Writing to trusted files is prohibited.

Gramine supports seek operations on files (`lseek()`). However, seek operation happens entirely
inside Gramine (by changing the file offset), and thus may behave incorrectly on host's device files
(which may reimplement the seek operation in a special way).

Gramine supports mmap and msync operations on files. For more information, see the ["Memory
management" section](#memory-management).

Gramine has dummy support for polling on files via `poll()`, `ppoll()`, `select()` system calls.
Regular files always return events "there is data to read" and "writing is possible".  Other files
return an error code.

Gramine does *not* support epoll on files.

Gramine supports file flushes (via `fsync()` and `fdatasync()`). However, flushing filesystem
metadata (`sync()` and `syncfs()`) is not supported. Similarly, `sync_file_range()` system call is
currently not supported.

Gramine supports file truncation (via `truncate()` and `ftruncate()`). There is one exception
currently: shrinking encrypted files to arbitrary size is not supported (only shrink-to-zero is
supported).

Gramine has very limited support of `fallocate()` system call. Only mode 0 is supported ("allocating
disk space"). The emulation of this mode simply extends the file size if applicable, otherwise does
nothing. In other words, this system call doesn't provide reliability or performance guarantees.

Gramine has dummy support of `fadvise64()` system call. The emulation does nothing and always
returns success. In other words, this system call doesn't provide any performance improvement.

Gramine has support for file mode bits. The `chmod()`, `fchmodat()`, `fchmod()` system calls
correctly set the file mode. The `umask()` system call is also supported.

Gramine has dummy support for file owner and group manipulations. In Gramine, users and groups are
dummy; see the ["User and group identifiers" section](#user-and-group-identifiers) for details.
Therefore, `chown()`, `fchownat()`, `fchown()` system calls updated UID and GID internally in
Gramine, but do not propagate these changes to the host.

Gramine supports checking permissions on the file via `access()` and `faccessat()` system calls.
Recall however that users and groups are dummy in Gramine, thus the checks are also largely
irrelevant.

Gramine implements `sendfile()` system call. However, this system call is emulated in an inefficient
way (for simplicity). Pay attention to this if your application relies heavily on `sendfile()`.

Gramine supports directory operations: `chdir()` and `fchdir()` to change the working directory, and
`getcwd()` to get the current working directory.

Gramine partially supports getting file status (information about files), via `stat()`, `lstat()`,
`fstat()`, `newfstatat()` system calls. The only fields populated in the output buffer are
`st_mode`, `st_size`, `st_uid`, `st_gid`, `st_blksize` (with hard-coded value), `st_nlink` (with
hard-coded value), `st_dev`, `st_ino`. Note that Gramine currently doesn't support links, so
`lstat()` always resolves to a file (never to a symlink).

Gramine has dummy support for getting filesystem statistics via `statfs()` and `fstatfs()`. The only
fields populated in the output buffer are `f_bsize`, `f_blocks`, `f_bfree` and `f_bavail`, and they
all have hard-coded values.

Gramine currently does *not* support changing file access/modification times, via `utime()`,
`utimes()`, `futimesat()`, `utimensat()` system calls.

<details><summary>:blue_book: Related system calls</summary>

- :ballot_box_with_check: `open()`: implemented, with limitations
- :ballot_box_with_check: `openat()`: implemented, with limitations
- :white_check_mark: `close()`
- :white_check_mark: `creat()`
- :white_check_mark: `mkdir()`
- :white_check_mark: `mkdirat()`
- :white_check_mark: `getdents()`
- :white_check_mark: `getdents64()`
- :white_check_mark: `unlink()`
- :white_check_mark: `unlinkat()`
- :white_check_mark: `rmdir()`
- :ballot_box_with_check: `rename()`: cannot rename across mounts
- :ballot_box_with_check: `renameat()`: cannot rename across mounts

- :white_check_mark: `read()`
- :white_check_mark: `pread64()`
- :white_check_mark: `readv()`
- :white_check_mark: `preadv()`
- :white_check_mark: `write()`
- :white_check_mark: `pwrite64()`
- :white_check_mark: `writev()`
- :white_check_mark: `pwritev()`

- :ballot_box_with_check: `lseek()`: see note above
- :ballot_box_with_check: `mmap()`: see notes above
- :ballot_box_with_check: `msync()`: see notes above
- :ballot_box_with_check: `select()`: dummy
- :ballot_box_with_check: `pselect6()`: dummy
- :ballot_box_with_check: `poll()`: dummy
- :ballot_box_with_check: `ppoll()`: dummy
- :white_check_mark: `fsync()`
- :white_check_mark: `fdatasync()`
- :ballot_box_with_check: `truncate()`: see note above
- :ballot_box_with_check: `ftruncate()`: see note above
- :ballot_box_with_check: `fallocate()`: dummy
- :ballot_box_with_check: `fadvise64()`: dummy

- :white_check_mark: `chmod()`
- :white_check_mark: `fchmod()`
- :white_check_mark: `fchmodat()`
- :ballot_box_with_check: `chown()`: dummy
- :ballot_box_with_check: `fchown()`: dummy
- :ballot_box_with_check: `fchownat()`: dummy
- :ballot_box_with_check: `access()`: dummy
- :ballot_box_with_check: `faccessat()`: dummy
- :white_check_mark: `umask()`

- :ballot_box_with_check: `sendfile()`: unoptimized

- :white_check_mark: `chdir()`
- :white_check_mark: `fchdir()`
- :white_check_mark: `getcwd()`

- :ballot_box_with_check: `stat()`: partially dummy
- :ballot_box_with_check: `fstat()`: partially dummy
- :ballot_box_with_check: `lstat()`: partially dummy, always resolves to actual
  file
- :ballot_box_with_check: `newfstatat()`: partially dummy
- :ballot_box_with_check: `statfs()`: partially dummy
- :ballot_box_with_check: `fstatfs()`: partially dummy

- :white_check_mark: `chroot()`

- :x: `name_to_handle_at()`: not used by applications
- :x: `open_by_handle_at()`: not used by applications
- :x: `openat2()`: not used by applications
- :x: `renameat2()`: not used by applications
- :x: `preadv2()`: not used by applications
- :x: `pwritev2()`: not used by applications
- :x: `epoll_create()`: not used by applications
- :x: `epoll_create1()`: not used by applications
- :x: `epoll_wait()`: not used by applications
- :x: `epoll_pwait()`: not used by applications
- :x: `epoll_pwait2()`: not used by applications
- :x: `epoll_ctl()`: not used by applications
- :x: `sync()`: not used by applications
- :x: `syncfs()`: not used by applications
- :x: `sync_file_range()`: not used by applications
- :x: `faccessat2()`: not used by applications
- :x: `statx()`: not used by applications
- :x: `sysfs()`: not used by applications
- :x: `ustat()`: not used by applications
- :x: `mount()`: not used by applications
- :x: `move_mount()`: not used by applications
- :x: `umount2()`: not used by applications
- :x: `mount_setattr()`: not used by applications
- :x: `pivot_root()`: not used by applications
- :x: `utime()`: may be implemented in future
- :x: `utimes()`: may be implemented in future
- :x: `futimesat()`: may be implemented in future
- :x: `utimensat()`: may be implemented in future

</details>

#### File locking

File locking operations can be considered one of the IPC mechanisms, as discussed in ["Overview of
Inter-Process Communication (IPC)" section](#overview-of-inter-process-communication-ipc). Thus,
file locks are implemented via message passing in Gramine, and all lock-requests are handled in the
main (leader) process.

Gramine currently implements POSIX locks aka Advisory record locks. In particular, the following
operations are implemented: `fcntl(F_SETLK)`, `fcntl(F_SETLKW)` and `fcntl(F_GETLK)`.

The current implementation has the following caveats:

- Lock requests from other processes will always have the overhead of IPC round-trip, even if the
  lock is uncontested.
- The main process has to be able to look up the same file, so locking will not work for files in
  local-process-only filesystems (e.g. tmpfs).
- There is no deadlock detection (`EDEADLK`).
- The lock requests cannot be interrupted (`EINTR`).
- The locks work only on regular files (no pipes, sockets etc.).

Gramine does *not* currently implement the `flock()` system call.

<details><summary>:blue_book: Related system calls</summary>

- :ballot_box_with_check: `fcntl()`
  - :ballot_box_with_check: `F_SETLK`: see notes above
  - :ballot_box_with_check: `F_SETLKW`: see notes above
  - :ballot_box_with_check: `F_GETLK`: see notes above

- :x: `flock()`: may be implemented in future

</details>

#### Monitoring filesystem events (inotify, fanotify)

Gramine does *not* currently implement inotify and fanotify APIs. Gramine could implement them in
the future, if need arises.

<details><summary>:blue_book: Related system calls</summary>

- :x: `inotify_init()`
- :x: `inotify_init1()`
- :x: `inotify_add_watch()`
- :x: `inotify_rm_watch()`
- :x: `fanotify_init()`
- :x: `fanotify_mark()`

</details>

#### Hard links and soft links (symbolic links)

There are two notions that must be discussed separately:

1. Host OS's links: Gramine sees them as normal files. These links are currently always followed
   during directory/file lookup.
2. In-Gramine links: Gramine has no support for links (i.e., applications cannot create links).
   - There is one exception: some pseudo-files like `/proc/[pid]/cwd` and `/proc/self`.

The above means that Gramine does not implement `link()` and `symlink()` system calls. Support for
`readlink()` system call is limited to only pseudo-files' links mentioned above.

Gramine may implement hard and soft links in the future.

<details><summary>:blue_book: Related system calls</summary>

- :x: `link()`
- :x: `symlink()`
- :ballot_box_with_check: `readlink()`: see note above
- :x: `linkat()`
- :x: `symlinkat()`
- :ballot_box_with_check: `readlinkat()`: see note above
- :x: `lchown()`

</details>

<details><summary>:page_facing_up: Related pseudo-files</summary>

The following pseudo-files are symlinks. See also "Related pseudo-files" in the ["Process and thread
identifiers" section](#process-and-thread-identifiers).

- :white_check_mark: `/dev/`
  - :white_check_mark: `/dev/stdin`
  - :white_check_mark: `/dev/stdout`
  - :white_check_mark: `/dev/stderr`

- :white_check_mark: `/proc/self/`

- :white_check_mark: `/proc/[pid]/`
  - :white_check_mark: `/proc/[pid]/cwd`
  - :white_check_mark: `/proc/[pid]/exe`
  - :white_check_mark: `/proc/[pid]/root`

</details>

### Pipes and FIFOs (named pipes)

Pipes and FIFOs are emulated in Gramine directly as host-level pipes (to be more specific, as
socketpairs for Linux hosts). In case of SGX backend, pipes and FIFOs are transparently encrypted.
For additional information on general properties of IPC in Gramine, see the ["Overview of
Inter-Process Communication (IPC)" section](#overview-of-inter-process-communication-ipc).

Gramine does *not* allow pipe/FIFO communication between Gramine processes and the host. Gramine
also does *not* allow communication between Gramine processes from two different Gramine instances.
Communication on pipes/FIFOs is possible only between two Gramine processes in the same Gramine
instance.

Gramine does *not* allow more than two parties on one pipe/FIFO. For example, it is impossible to
implement an SPMC (Single Producer Multiple Consumers) queue using a single pipe/FIFO. (We have not
encountered applications that would try to use such patterns though.)

Gramine supports creating pipes (via `pipe()` and `pipe2()`) and FIFOs (via `mknod(S_ISFIFO)` and
`mknodat(S_ISFIFO)`). The `O_DIRECT` flag while creating pipes with `pipe2()` is ignored. Blocking
and non-blocking pipes/FIFOs (`O_NONBLOCK` flag) are supported.

Gramine supports read and write operations on pipes and FIFOs. Gramine supports generation of the
`SIGPIPE` signal on write operation if the read end of a pipe has been closed. Polling on pipes and
FIFOs is supported.

Gramine supports getting information about pipes/FIFOs via the `fstat()` and `newfstatat()` system
calls. The only fields populated in the output buffer are `st_uid`, `st_gid` and `st_mode`. Gramine
also supports getting the number of unread bytes in the pipe via `ioctl(FIONREAD)`.

Gramine supports getting and setting pipe/FIFO status flags via `fcntl(F_GETFL)` and
`fcntl(F_SETFL)`. The only currently supported flag is `O_NONBLOCK`; `O_ASYNC` is not supported.
Gramine also supports setting blocking/non-blocking mode via `ioctl(FIONBIO)`.

<details><summary>:blue_book: Related system calls</summary>

- :white_check_mark: `pipe()`
- :ballot_box_with_check: `pipe2()`: `O_DIRECT` flag is ignored
- :ballot_box_with_check: `mknod()`: `S_ISFIFO` type is supported
- :ballot_box_with_check: `mknodat()`: `S_ISFIFO` type is supported
- :white_check_mark: `close()`

- :white_check_mark: `fstat()`

- :white_check_mark: `read()`
- :white_check_mark: `readv()`
- :white_check_mark: `write()`
- :white_check_mark: `writev()`

- :white_check_mark: `select()`
- :white_check_mark: `pselect6()`
- :white_check_mark: `poll()`
- :white_check_mark: `ppoll()`
- :white_check_mark: `epoll_create()`
- :white_check_mark: `epoll_create1()`
- :white_check_mark: `epoll_wait()`
- :white_check_mark: `epoll_pwait()`
- :white_check_mark: `epoll_ctl()`
- :x: `epoll_pwait2()`: not used by applications

- :ballot_box_with_check: `sendfile()`: unoptimized

- :ballot_box_with_check: `fcntl()`
  - :ballot_box_with_check: `F_GETFL`: only `O_NONBLOCK`
  - :ballot_box_with_check: `F_SETFL`: only `O_NONBLOCK`
  - :x: `F_GETPIPE_SZ`: not used by applications
  - :x: `F_SETPIPE_SZ`: not used by applications

- :ballot_box_with_check: `ioctl()`
  - :white_check_mark: `FIONREAD`
  - :white_check_mark: `FIONBIO`

</details>

### Networking (sockets)

Gramine supports the most important networking protocols. In particular, Gramine supports only the
following protocol families:
- `AF_INET` (IPv4 Internet protocols, e.g. TCP/IP and UDP/IP),
- `AF_INET6` (IPv6 Internet protocols, e.g. TCP/IP and UDP/IP),
- `AF_UNIX` aka `AF_LOCAL` (UNIX domain sockets).

Gramine supports only two types of sockets:
- `SOCK_STREAM` (connection-based byte streams),
- `SOCK_DGRAM` (connectionless datagrams).

Gramine supports TCP/IP sockets and UDP/IP sockets, i.e. the combinations `AF_INET`/`AF_INET6` +
`SOCK_STREAM` and `AF_INET`/`AF_INET6` + `SOCK_DGRAM` respectively. Gramine supports stream UNIX
domain sockets (`AF_UNIX` + `SOCK_STREAM`), but does *not* support datagram UNIX domain sockets
(`AF_UNIX` + `SOCK_DGRAM`).

Non-blocking sockets (`SOCK_NONBLOCK`) are supported. Generation of the `SIGPIPE` signal on send
operation if the receive end of a socket has been closed is supported.

Gramine does *not* implement full network stack by design. Gramine relies on the host network stack
for most operations.

Other networking limitations in Gramine include:
- no support for auto binding in the `listen()` system call;
- no support for ancillary data (aka control messages).

#### TCP/IP and UDP/IP sockets

TCP/IP and UDP/IP sockets (TCP and UDP for short) support all Berkeley sockets APIs, including
`socket()`, `bind()`, `listen()`, `connect()`, `accept()`, `send()`, `recv()`, `getsockopt()`,
`setsockopt()`, `getsockname()`, `getpeername()`, `shutdown()`, etc. system calls. Polling on TCP
and UDP sockets via `poll()`, `ppoll()`, `select()`, `epoll_*()` system calls is supported.

TCP sockets support only `MSG_NOSIGNAL`, `MSG_DONTWAIT` and `MSG_MORE` flags in `send()`,
`sendto()`, `sendmsg()`, `sendmmsg()` system calls. Note that `MSG_MORE` flag is ignored. UDP
sockets support only `MSG_NOSIGNAL` and `MSG_DONTWAIT` flags.

TCP sockets support only `MSG_PEEK`, `MSG_DONTWAIT` and `MSG_TRUNC` flags in `recv()`, `recvfrom()`,
`recvmsg()`, `recvmmsg()` system calls. UDP sockets support only `MSG_DONTWAIT` and `MSG_TRUNC`
flags.

TCP and UDP sockets support the following socket options:
- `SO_ACCEPTCONN`, `SO_DOMAIN`, `SO_TYPE`, `SO_PROTOCOL`, `SO_ERROR` (all read-only),
- `SO_RCVTIMEO`, `SO_SNDTIMEO`, `SO_REUSEADDR`, `SO_REUSEPORT`, `SO_BROADCAST`, `SO_KEEPALIVE`,
  `SO_LINGER`, `SO_RCVBUF`, `SO_SNDBUF`,
- `IPV6_V6ONLY`,
- `IP_RECVERR`, `IPV6_RECVERR` (allowed but ignored).

TCP sockets additionally support the following socket options: `TCP_CORK`, `TCP_KEEPIDLE`,
`TCP_KEEPINTVL`, `TCP_KEEPCNT`, `TCP_NODELAY` and `TCP_USER_TIMEOUT`.

<details><summary>:speech_balloon: Note on domain names configuration</summary>

- To use name-resolving Berkeley socket APIs like `gethostbyname()`, `gethostbyaddr()`,
  `getaddrinfo`, one must enable the [`sys.enable_extra_runtime_domain_names_conf` manifest
  option](https://gramine.readthedocs.io/en/stable/manifest-syntax.html#domain-names-configuration).

</details>

<details><summary>:blue_book: Related system calls</summary>

- :ballot_box_with_check: `socket()`: see notes above
- :white_check_mark: `bind()`
- :white_check_mark: `listen()`
- :white_check_mark: `accept()`
- :white_check_mark: `accept4()`
- :white_check_mark: `connect()`
- :white_check_mark: `close()`
- :white_check_mark: `shutdown()`

- :white_check_mark: `getsockname()`
- :white_check_mark: `getpeername()`
- :white_check_mark: `getsockopt()`
- :white_check_mark: `setsockopt()`

- :white_check_mark: `fstat()`

- :white_check_mark: `read()`
- :white_check_mark: `readv()`
- :white_check_mark: `write()`
- :white_check_mark: `writev()`

- :ballot_box_with_check: `recv()`: see supported flags above
- :ballot_box_with_check: `recvfrom()`: see supported flags above
- :ballot_box_with_check: `recvmsg()`: see supported flags above
- :ballot_box_with_check: `recvmmsg()`: see supported flags above
- :ballot_box_with_check: `send()`: see supported flags above
- :ballot_box_with_check: `sendto()`: see supported flags above
- :ballot_box_with_check: `sendmsg()`: see supported flags above
- :ballot_box_with_check: `sendmmsg()`: see supported flags above

- :white_check_mark: `select()`
- :white_check_mark: `pselect6()`
- :white_check_mark: `poll()`
- :white_check_mark: `ppoll()`
- :white_check_mark: `epoll_create()`
- :white_check_mark: `epoll_create1()`
- :white_check_mark: `epoll_wait()`
- :white_check_mark: `epoll_pwait()`
- :white_check_mark: `epoll_ctl()`
- :x: `epoll_pwait2()`: not used by applications

- :ballot_box_with_check: `sendfile()`: unoptimized

- :ballot_box_with_check: `fcntl()`
  - :ballot_box_with_check: `F_GETFL`: only `O_NONBLOCK`
  - :ballot_box_with_check: `F_SETFL`: only `O_NONBLOCK`

- :ballot_box_with_check: `ioctl()`
  - :white_check_mark: `FIONREAD`
  - :white_check_mark: `FIONBIO`

</details>

<details><summary>:page_facing_up: Related pseudo-files</summary>

- :x: `/proc/sys/net/core/`
- :x: `/proc/sys/net/ipv4/`
- :x: `/proc/sys/net/ipv6/`

</details>

#### UNIX domain sockets

UNIX domain sockets (UDSes) are emulated in Gramine directly as host-level pipes (to be more
specific, as socketpairs for Linux hosts). In case of SGX backend, UDSes are transparently
encrypted. For additional information on general properties of IPC in Gramine, see the ["Overview of
Inter-Process Communication (IPC)" section](#overview-of-inter-process-communication-ipc).

Gramine does *not* allow UDS communication between Gramine processes and the host. Gramine also does
*not* allow communication between Gramine processes from two different Gramine instances.
Communication on UDSes is possible only between two Gramine processes in the same Gramine instance.
See also the ["Pipes and FIFOs (named pipes)" section](#pipes-and-fifos-named-pipes).

UDSes support all Berkeley sockets APIs, including `socket()`, `bind()`, `listen()`, `connect()`,
`accept()`, `send()`, `recv()`, `getsockopt()`, `setsockopt()`, `getsockname()`, `getpeername()`,
`shutdown()`, etc. system calls. Polling on UDSes via `poll()`, `ppoll()`, `select()`, `epoll_*()`
system calls is supported.

Named UDSes are currently not visible on the Gramine filesystem (they do not have a corresponding
dentry). This may be implemented in near future, please see the note below.

UDSes do *not* support ancillary data (aka control messages) in `sendmsg()` and `recvmsg()` system
calls. In particular, the `SCM_RIGHTS` type is not supported; support for this type may be added in
the future.

Gramine does *not* support `connect()` system call on an already bound UDS (via `bind()`).

UDSes support only `MSG_NOSIGNAL`, `MSG_DONTWAIT` and `MSG_MORE` flags in `send()`, `sendto()`,
`sendmsg()`, `sendmmsg()` system calls. Note that `MSG_MORE` flag is ignored.

UDSes support only `MSG_PEEK`, `MSG_DONTWAIT` and `MSG_TRUNC` flags in `recv()`, `recvfrom()`,
`recvmsg()`, `recvmmsg()` system calls.

UDSes support the following socket options:
- `SO_ACCEPTCONN`, `SO_DOMAIN`, `SO_TYPE`, `SO_PROTOCOL`, `SO_ERROR` (all read-only),
- `SO_REUSEADDR` (ignored, same as in Linux).

<details><summary>:speech_balloon: Note on named UDSes</summary>

- There is an effort to make named UDSes visible on the Gramine filesystem, see
  https://github.com/gramineproject/gramine/pull/1021.

</details>

<details><summary>:blue_book: Related system calls</summary>

- :white_check_mark: `socketpair()`
- For other system calls, see ["TCP/IP and UDP/IP sockets" subsection](#tcpip-and-udpip-sockets)
  above.

</details>

<details><summary>:page_facing_up: Related pseudo-files</summary>

- :x: `/proc/sys/net/unix/`
- For other pseudo-files, see ["TCP/IP and UDP/IP sockets" subsection](#tcpip-and-udpip-sockets)
  above.

</details>

### I/O multiplexing

Gramine implements I/O multiplexing system calls: `select()`, `pselect6()`, `poll()`, `ppoll()`, as
well as the epoll family of system calls (`epoll_*()`). All these system calls are emulated via the
`ppoll()` Linux-host system call.

Gramine supports I/O multiplexing on pipes, FIFOs, sockets and eventfd. For peculiarities of
regular-files support, see the ["File system operations" section](#file-system-operations).

Timeouts and signal masks are honoured. Timeout is updated on return from corresponding system
calls.

Edge-triggered and level-triggered events in epoll are supported (the `EPOLLET` flag).
`EPOLLONESHOT`, `EPOLL_NEEDS_REARM` flags are supported. `EPOLLWAKEUP` flag is ignored because
Gramine does not implement autosleep.

Select and poll families of system calls are implemented in Gramine.

Epoll family of system calls has the following limitations:
- No sharing of an epoll instance between processes; updates in one process (e.g. adding an fd to be
  monitored) won't be visible in the other process.
- `EPOLLEXCLUSIVE` is a no-op; this is correct semantically, but may reduce performance of apps
  using this flag.
- Adding an epoll to another epoll instance is not currently supported.
- `EPOLLRDHUP` is not reported and `EPOLLHUP` is always reported together with `EPOLLERR`.

<details><summary>:construction: Note on EPOLLERR/EPOLLHUP/EPOLLRDHUP</summary>

There is a pending [GitHub pull request](https://github.com/gramineproject/gramine/pull/1073) to
distinguish between the three error conditions.

</details>

<details><summary>:blue_book: Related system calls</summary>

- :white_check_mark: `select()`
- :white_check_mark: `pselect6()`
- :white_check_mark: `poll()`
- :white_check_mark: `ppoll()`
- :ballot_box_with_check: `epoll_create()`: see notes above
- :ballot_box_with_check: `epoll_create1()`: see notes above
- :ballot_box_with_check: `epoll_wait()`: see notes above
- :ballot_box_with_check: `epoll_pwait()`: see notes above
- :ballot_box_with_check: `epoll_ctl()`: see notes above
- :x: `epoll_pwait2()`: not used by applications

</details>

### Asynchronous I/O

There are two asynchronous I/O APIs in Linux kernel:
- Linux POSIX asynchronous I/O (Linux AIO, older API with `io_setup()` etc.),
- I/O uring (io_uring, newer API with `io_uring_setup()` etc.).

Gramine does *not* currently implement either of these APIs. Gramine could implement them in the
future, if need arises.

Note that AIO provided in userspace by glibc (`aio_read()`, `aio_write()`, etc.) does not depend on
Gramine and is supported.

<details><summary>:blue_book: Related system calls</summary>

- :x: `io_setup()`
- :x: `io_destroy()`
- :x: `io_getevents()`
- :x: `io_submit()`
- :x: `io_cancel()`

- :x: `io_uring_setup()`
- :x: `io_uring_enter()`
- :x: `io_uring_register()`

</details>

### Event notifications (eventfd)

Gramine currently implements an *insecure* version of the `eventfd()` system call. It is considered
insecure in the context of SGX backend because it relies on the host OS, which could for example
maliciously drop an event or inject a random one. To enable this `eventfd()` implementation, the
manifest file must contain [`sys.insecure__allow_eventfd =
true`](https://gramine.readthedocs.io/en/stable/manifest-syntax.html#allowing-eventfd).

Gramine supports polling on eventfd via `poll()`, `ppoll()`, `select()`, `epoll_*()` system calls.

Gramine may implement a secure version of `eventfd()` for communication between Gramine processes in
the future. Such secure version will *not* be able to receive events from the host OS.

<details><summary>:blue_book: Related system calls</summary>

- :ballot_box_with_check: `eventfd()`: insecure implementation
- :ballot_box_with_check: `eventfd2()`: insecure implementation
- :white_check_mark: `close()`

- :white_check_mark: `read()`
- :white_check_mark: `write()`

- :white_check_mark: `select()`
- :white_check_mark: `pselect6()`
- :white_check_mark: `poll()`
- :white_check_mark: `ppoll()`
- :white_check_mark: `epoll_create()`
- :white_check_mark: `epoll_create1()`
- :white_check_mark: `epoll_wait()`
- :white_check_mark: `epoll_pwait()`
- :white_check_mark: `epoll_ctl()`
- :x: `epoll_pwait2()`: not used by applications

</details>

### Semaphores

There are two semaphore APIs in Linux kernel:
- System V semaphores (older API),
- POSIX semaphores (newer API).

POSIX semaphores are technically not a Linux kernel API. Instead, they are implemented on top of the
POSIX shared memory functionality of Linux (i.e., via `/dev/shm` pseudo-filesystem).

Gramine does *not* currently implement either of these APIs. Gramine could implement them in
the future, if need arises.

<details><summary>:blue_book: Related system calls</summary>

- :x: `semget()`
- :x: `semop()`
- :x: `semtimedop()`
- :x: `semctl()`

</details>

<details><summary>:page_facing_up: Related pseudo-files</summary>

- :x: `/dev/shm`

</details>

### Message queues

There are two message-queue APIs in Linux kernel:
- System V message queue (older API),
- POSIX message queue (newer API).

Gramine does *not* currently implement either of these APIs. Gramine could implement them in
the future, if need arises.

<details><summary>:blue_book: Related system calls</summary>

- :x: `msgget()`
- :x: `msgctl()`
- :x: `msgrcv()`
- :x: `msgsnd()`

- :x: `mq_open()`
- :x: `mq_getsetattr()`
- :x: `mq_notify()`
- :x: `mq_timedreceive()`
- :x: `mq_timedsend()`
- :x: `mq_unlink()`

</details>

### Shared memory

There are two shared-memory APIs in Linux kernel:
- System V shared memory (older API),
- POSIX shared memory (newer API).

Gramine does *not* currently implement either of these APIs.

In case of SGX backend, implementation of shared memory would be *insecure*, as shared memory by
design would be allocated in untrusted non-enclave memory, and there is no way for Gramine to
intercept memory accesses to shared memory regions (to provide some security guarantees).

<details><summary>:construction: Adding limited POSIX shared memory support</summary>

There is an effort to add limited support for POSIX shared memory, targeted for special use cases
like communication with hardware accelerators (e.g. GPUs):
- [Whitepaper](https://arxiv.org/abs/2203.01813),
- [GitHub issue](https://github.com/gramineproject/gramine/issues/757),
- [GitHub pull request](https://github.com/gramineproject/gramine/pull/827).

</details>

<details><summary>:blue_book: Related system calls</summary>

- :x: `shmget()`
- :x: `shmat()`
- :x: `shmctl()`
- :x: `shmdt()`

</details>

<details><summary>:page_facing_up: Related pseudo-files</summary>

- :x: `/dev/shm`: may be implemented in future (in a limited insecure way, see note above)

</details>

### IOCTLs

Gramine currently implements only a minimal set of IOCTL request codes. See the list under
"Related system calls".

<details><summary>:construction: Adding support for arbitrary IOCTLs </summary>

There is an effort to add support for specifying arbitrary IOCTLs (with arbitrary request codes and
corresponding IOCTL data structures), targeted for special use cases like communication with
hardware accelerators (e.g. GPUs):
- [Whitepaper](https://arxiv.org/abs/2203.01813),
- [GitHub issue](https://github.com/gramineproject/gramine/issues/353),
- [GitHub pull request](https://github.com/gramineproject/gramine/pull/671).

</details>

<details><summary>:blue_book: Related system calls</summary>

- :ballot_box_with_check: `ioctl()`
  - :ballot_box_with_check: `TIOCGPGRP`: dummy
  - :white_check_mark: `FIONBIO`
  - :white_check_mark: `FIONCLEX`
  - :white_check_mark: `FIOCLEX`
  - :white_check_mark: `FIOASYNC`
  - :white_check_mark: `FIONREAD`

</details>

### Date and time

Gramine partially implements getting date/time: `gettimeofday()`, `time()`, `clock_gettime()`,
`clock_getres()` system calls.

Gramine does *not* distinguish between different clocks available for `clock_gettime()` and
`clock_getres()`. All clocks are emulated via the `CLOCK_REALTIME` clock.

Gramine does *not* support setting or adjusting date/time: `settimeofday()`, `clock_settime()`,
`adjtimex()`, `clock_adjtime()`.

Gramine does *not* currently support getting process times (like user time, system time): `times()`.

<details><summary>:warning: Note on trustworthiness of date/time on SGX</summary>

In case of SGX backend, date/time cannot be trusted because it is queried from the possibly
malicious host OS. There is currently no solution to this limitation.

</details>

<details><summary>:blue_book: Related system calls</summary>

- :white_check_mark: `gettimeofday()`
- :white_check_mark: `time()`
- :ballot_box_with_check: `clock_gettime()`: all clocks emulated via
  `CLOCK_REALTIME`
- :ballot_box_with_check: `clock_getres()`: all clocks emulated via
  `CLOCK_REALTIME`

- :x: `settimeofday()`: not used by applications
- :x: `clock_settime()`: not used by applications
- :x: `adjtimex()`: not used by applications
- :x: `clock_adjtime()`: not used by applications
- :x: `times()`: may be implemented in future

</details>

### Sleeps, timers and alarms

Gramine implements sleep system calls: `nanosleep()` and `clock_nanosleep()`. For the latter system
call, all clocks are emulated via the `CLOCK_REALTIME` clock. `TIMER_ABSTIME` is supported. Both
system calls correctly update the remaining time if they were interrupted by a signal handler.

Gramine implements getting and setting the interval timer: `getitimer()` and `setitimer()`. Only
`ITIMER_REAL` is supported.

Gramine implements alarm clocks via `alarm()`.

Gramine does *not* currently implement the POSIX per-process timer: `timer_create()`, etc. Gramine
also does not currently implement timers that notify via file descriptors. Gramine could implement
these timers in the future, if need arises.

<details><summary>:blue_book: Related system calls</summary>

- :white_check_mark: `nanosleep()`
- :ballot_box_with_check: `clock_nanosleep()`: all clocks emulated via
  `CLOCK_REALTIME`
- :ballot_box_with_check: `getitimer()`: only `ITIMER_REAL`
- :ballot_box_with_check: `setitimer()`: only `ITIMER_REAL`
- :white_check_mark: `alarm()`

- :x: `timer_create()`: may be implemented in future
- :x: `timer_settime()`: may be implemented in future
- :x: `timer_gettime()`: may be implemented in future
- :x: `timer_getoverrun()`: may be implemented in future
- :x: `timer_delete()`: may be implemented in future

- :x: `timerfd_create()`: may be implemented in future
- :x: `timerfd_settime()`: may be implemented in future
- :x: `timerfd_gettime()`: may be implemented in future

</details>

### Randomness

Gramine implements obtaining random bytes via two Linux APIs:
- `getrandom()` system call,
- `/dev/random` and `/dev/urandom` pseudo-files.

In case of SGX backend, Gramine always uses only one source of random bytes: the RDRAND x86
instruction. This is a secure source of randomness.

<details><summary>:blue_book: Related system calls</summary>

- :white_check_mark: `getrandom()`

</details>

<details><summary>:page_facing_up: Related pseudo-files</summary>

- :white_check_mark: `/dev/random`
- :white_check_mark: `/dev/urandom`

</details>

### System information and resource accounting

Gramine does *not* support getting resource usage metrics via the `getrusage()` system call.

Gramine reports only minimal set of system information via the `sysinfo()` system call: only
`totalram`, `totalhigh`, `freeram` and `freehigh` fields are populated.

Gramine reports only minimal set of kernel information via the `uname()` system call: only
`sysname`, `nodename`, `release`, `version`, `machine` and `domainname` fields are populated. Out of
these, only `nodename` is populated with host-provided name. The rest fields are hard-coded (e.g.
`release` is currently hard-coded to `3.10.0`).

Gramine has dummy support for setting hostname and domain name via `sethostname()` and
`setdomainname()`. The set names are *not* propagated to the host OS or other Gramine processes.

Gramine has minimal and mostly dummy support for getting and setting resource limits, via
`getrlimit()`, `setrlimit()`, `prlimit64()`. The `prlimit64()` syscall can be issued only on the
current process. The following resources are supported:
- `RLIMIT_CPU` -- dummy, no limit by default
- `RLIMIT_FSIZE` -- dummy, no limit by default
- `RLIMIT_DATA` -- implemented, affects `brk()` system call
- `RLIMIT_STACK` -- dummy, equal to
  [`sys.stack.size`](https://gramine.readthedocs.io/en/stable/manifest-syntax.html#stack-size) by
  default
- `RLIMIT_CORE` -- dummy, zero by default
- `RLIMIT_RSS` -- dummy, no limit by default
- `RLIMIT_NPROC` -- dummy, no limit by default
- `RLIMIT_NOFILE` -- implemented, default soft limit is 900, default hard limit is 65K
- `RLIMIT_MEMLOCK` -- dummy, no limit by default
- `RLIMIT_AS` -- dummy, no limit by default
- `RLIMIT_LOCKS` -- dummy, no limit by default
- `RLIMIT_SIGPENDING` -- dummy, no limit by default
- `RLIMIT_MSGQUEUE` -- dummy, ~800K by default
- `RLIMIT_NICE` -- dummy, zero by default
- `RLIMIT_RTPRIO` -- dummy, zero by default
- `RLIMIT_RTTIME` -- dummy, no limit by default

Gramine supports the `/proc/cpuinfo`, `/proc/meminfo`, `/proc/stat` pseudo-files with system
information. In addition, Gramine supports CPU- and NUMA-node-specific pseudo-files under
`/sys/devices/system/cpu/` and `/sys/devices/system/node/`. See the list under "Related
pseudo-files". For additional pseudo-files containing process-specific information, see the
["Process and thread identifiers" section](#process-and-thread-identifiers).

<details><summary>:blue_book: Related system calls</summary>

- :x: `getrusage()`
- :ballot_box_with_check: `sysinfo()`: only `totalram`, `totalhigh`, `freeram`
  and `freehigh`
- :ballot_box_with_check: `uname()`: only `sysname`, `nodename`, `release`,
  `version`, `machine` and `domainname`
- :ballot_box_with_check: `sethostname()`: dummy
- :ballot_box_with_check: `setdomainname()`: dummy
- :ballot_box_with_check: `getrlimit()`: see notes above
- :ballot_box_with_check: `setrlimit()`: see notes above
- :ballot_box_with_check: `prlimit64()`: see notes above

</details>

<details><summary>:page_facing_up: Related pseudo-files</summary>

- :ballot_box_with_check: `/proc/cpuinfo`: partially implemented
    - :white_check_mark: `processor`, `vendor_id`, `cpu family`, `model`, `model name`, `stepping`,
      `physical id`, `core id`, `cpu cores`, `bogomips`
    - :white_check_mark: `flags`: all known CPU flags

- :ballot_box_with_check: `/proc/meminfo`: partially implemented
    - :white_check_mark: `MemTotal`, `MemFree`, `MemAvailable`, `Committed_AS`, `VmallocTotal`
    - :x: rest fields: always zero

- :ballot_box_with_check: `/proc/stat`: dummy
    - :ballot_box_with_check: `cpu` line: all fields are zeros
    - :ballot_box_with_check: `cpuX` lines: all fields are zeros
    - :ballot_box_with_check: `ctxt` line: always zero
    - :ballot_box_with_check: `btime` line: always zero
    - :ballot_box_with_check: `processes` line: always one
    - :ballot_box_with_check: `procs_running` line: always one
    - :ballot_box_with_check: `procs_blocked` line: always zero
    - :x: `intr` line
    - :x: `softirq` line

- :ballot_box_with_check: `/sys/devices/system/cpu/`: only most important files
  implemented
  - :ballot_box_with_check: `/sys/devices/system/cpu/cpu[x]/`
    - :ballot_box_with_check: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/`
      - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/coherency_line_size`
      - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/level`
      - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/number_of_sets`
      - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/physical_line_partition`
      - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/shared_cpu_map`
      - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/size`
      - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/cache/index[x]/type`
    - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/online`
    - :ballot_box_with_check: `/sys/devices/system/cpu/cpu[x]/topology/`
      - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/topology/core_id`
      - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/topology/core_siblings`
      - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/topology/physical_package_id`
      - :white_check_mark: `/sys/devices/system/cpu/cpu[x]/topology/thread_siblings`
  - :white_check_mark: `/sys/devices/system/cpu/online`
  - :white_check_mark: `/sys/devices/system/cpu/possible`

- :ballot_box_with_check: `/sys/devices/system/node/`: only most important files
  implemented
  - :ballot_box_with_check: `/sys/devices/system/node/node[x]/`
    - :white_check_mark: `/sys/devices/system/node/node[x]/cpumap`
    - :white_check_mark: `/sys/devices/system/node/node[x]/distance`
    - :white_check_mark: `/sys/devices/system/node/node[x]/hugepages/`
      - :ballot_box_with_check:
        `/sys/devices/system/node/node[x]/hugepages/hugepages-[y]/nr_hugepages`: always zero
    - :ballot_box_with_check: `/sys/devices/system/node/node[x]/meminfo`:
      partially implemented
      - :white_check_mark: `MemTotal`, `MemFree`, `MemUsed`
      - :x: rest fields: always zero

</details>

### Misc

Gramine implements vDSO, with four functions: `__vdso_clock_gettime()`, `__vdso_gettimeofday()`,
`__vdso_time()`, `__vdso_getcpu()`. These functions invoke the corresponding system calls, see the
["Date and time" section](#date-and-time) and the ["Scheduling" section](#scheduling).

Gramine implements operations on file descriptors (FDs):
- duplicating FDs via `dup()`, `dup2()`, `dup3()`, `fcntl(F_DUPFD)`, `fcntl(F_DUPFD_CLOEXEC)`,
- getting/setting FD flags via `fcntl(F_GETFD)` and `fcntl(F_SETFD)`; the only flag is `FD_CLOEXEC`.

Gramine implements several arch-specific (x86-64) operations:
- getting/setting the FS segment register via `arch_prctl(ARCH_GET_FS)` and
  `arch_prctl(ARCH_SET_FS)`,
- getting/setting the Intel AMX feature via `arch_prctl(ARCH_GET_XCOMP_SUPP)`,
  `arch_prctl(ARCH_GET_XCOMP_PERM)` and `arch_prctl(ARCH_REQ_XCOMP_PERM)`.

Gramine implements the `/dev/null` and `/dev/zero` pseudo-files.

<details><summary>:blue_book: Related system calls</summary>

- :white_check_mark: `gettimeofday()`: implemented in vDSO
- :ballot_box_with_check: `clock_gettime()`: implemented in vDSO
- :white_check_mark: `time()`: implemented in vDSO
- :ballot_box_with_check: `getcpu()`: implemented in vDSO

- :white_check_mark: `dup()`
- :white_check_mark: `dup2()`
- :white_check_mark: `dup3()`

- :ballot_box_with_check: `fcntl()`
  - :white_check_mark: `F_DUPFD`
  - :white_check_mark: `F_DUPFD_CLOEXEC`
  - :white_check_mark: `F_GETFD`
  - :white_check_mark: `F_SETFD`

- :ballot_box_with_check: `arch_prctl()`
  - :white_check_mark: `ARCH_GET_XCOMP_SUPP`
  - :white_check_mark: `ARCH_GET_XCOMP_PERM`
  - :white_check_mark: `ARCH_REQ_XCOMP_PERM`

</details>

<details><summary>:page_facing_up: Related pseudo-files</summary>

- :white_check_mark: `/dev/`
  - :white_check_mark: `/dev/null`
  - :white_check_mark: `/dev/zero`

</details>

### Advanced (unimplemented) features

Gramine does not implement the following classes of features. This is by design, to keep the
codebase of Gramine minimal.

- Berkeley Packet Filters (BPF) and eBPF: `bpf()`
- Capabilities: `capget()`, `capset()`
- Execution control and debugging: `ptrace()`, `syslog()`, `perf_event_open()`, `acct()`
- Extended attributes for files and directories (xattr): `setxattr()`, `lsetxattr()`,
  `fsetxattr()`, `getxattr()`, `lgetxattr()`, `fgetxattr()`, `listxattr()`, `llistxattr()`,
  `flistxattr()`, `removexattr()`, `lremovexattr()`, `fremovexattr()`
- In-kernel key management (keyrings): `add_key()`, `request_key()`, `keyctl()`
- Kernel modules: `create_module()`, `init_module()`, `finit_module()`, `delete_module()`,
  `query_module()`, `get_kernel_syms()`
- Memory Protection Keys: `pkey_alloc()`, `pkey_mprotect()`, `pkey_free()`
- Namespaces: `setns()`, `unshare()`
- Paging and swapping: `swapon()`, `swapoff()`, `readahead()`
- Process execution domain: `personality()`
- Secure Computing (seccomp) state: `seccomp()`
- Session management: `getsid()`, `setsid()`
- Zero-copy transfer of data: `splice()`, `tee()`, `vmsplice()`, `copy_file_range()`
- Transfer of data between processes: `process_vm_readv()`, `process_vm_writev()`
- Filesystem configuration context: `fsopen()`, `fsconfig()`, `fspick()`, `fsmount()`
- Landlock: `landlock_create_ruleset()`, `landlock_add_rule()`, `landlock_restrict_self()`

- Misc: `vhangup()`, `modify_ldt()`, `kexec_load()`, `kexec_file_load()`, `reboot()`, `iopl()`,
  `ioperm()`, `uselib()`, `_sysctl()`, `quotactl()`, `quotactl_fd()`, `nfsservctl()`, `getpmsg()`,
  `putpmsg()`, `afs_syscall()`, `tuxcall()`, `security()`, `lookup_dcookie()`, `restart_syscall()`,
  `vserver()`, `io_pgetevents()`, `rseq()`, `open_tree()`, `close_range()`

<details><summary>:blue_book: Related system calls</summary>

- :x: `_sysctl()`
- :x: `acct()`
- :x: `add_key()`
- :x: `afs_syscall()`
- :x: `bpf()`
- :x: `capget()`
- :x: `capset()`
- :x: `close_range()`
- :x: `copy_file_range()`
- :x: `create_module()`
- :x: `delete_module()`
- :x: `fgetxattr()`
- :x: `finit_module()`
- :x: `flistxattr()`
- :x: `fremovexattr()`
- :x: `fsconfig()`
- :x: `fsetxattr()`
- :x: `fsmount()`
- :x: `fsopen()`
- :x: `fspick()`
- :x: `get_kernel_syms()`
- :x: `getpmsg()`
- :x: `getsid()`
- :x: `getxattr()`
- :x: `init_module()`
- :x: `io_pgetevents()`
- :x: `ioperm()`
- :x: `iopl()`
- :x: `kexec_file_load()`
- :x: `kexec_load()`
- :x: `keyctl()`
- :x: `landlock_add_rule()`
- :x: `landlock_create_ruleset()`
- :x: `landlock_restrict_self()`
- :x: `lgetxattr()`
- :x: `listxattr()`
- :x: `llistxattr()`
- :x: `lookup_dcookie()`
- :x: `lremovexattr()`
- :x: `lsetxattr()`
- :x: `modify_ldt()`
- :x: `nfsservctl()`
- :x: `nfsservctl()`
- :x: `open_tree()`
- :x: `perf_event_open()`
- :x: `personality()`
- :x: `pkey_alloc()`
- :x: `pkey_free()`
- :x: `pkey_mprotect()`
- :x: `process_vm_readv()`
- :x: `process_vm_writev()`
- :x: `ptrace()`
- :x: `putpmsg()`
- :x: `query_module()`
- :x: `quotactl()`
- :x: `quotactl_fd()`
- :x: `readahead()`
- :x: `reboot()`
- :x: `removexattr()`
- :x: `request_key()`
- :x: `restart_syscall()`
- :x: `rseq()`
- :x: `seccomp()`
- :x: `security()`
- :x: `setns()`
- :x: `setsid()`
- :x: `setxattr()`
- :x: `splice()`
- :x: `swapoff()`
- :x: `swapon()`
- :x: `syslog()`
- :x: `tee()`
- :x: `tuxcall()`
- :x: `unshare()`
- :x: `uselib()`
- :x: `vhangup()`
- :x: `vmsplice()`
- :x: `vserver()`

</details>

## Gramine-specific features

### Attestation

Gramine exposes low-level abstractions of attestation report and attestation quote objects (*SGX
Report* and *SGX Quote* accordingly, in case of SGX backend) through the `/dev/attestation/`
pseudo-filesystem. Manipulating with the `/dev/attestation/` pseudo-files allows to program local
attestation and remote attestation flows. Additionally, the `dev/attestation/` pseudo-filesystem
exposes pseudo-files to set encryption keys (in particular, for encrypted files).

For detailed information, refer to the ["Attestation and Secret Provisioning" documentation of
Gramine](https://gramine.readthedocs.io/en/stable/attestation.html#low-level-dev-attestation-interface).

<details><summary>:page_facing_up: Related pseudo-files</summary>

- :white_check_mark: `/dev/attestation/`
  - :white_check_mark: `/dev/attestation/attestation_type`
  - :white_check_mark: `/dev/attestation/user_report_data`
  - :white_check_mark: `/dev/attestation/target_info`
  - :white_check_mark: `/dev/attestation/my_target_info`
  - :white_check_mark: `/dev/attestation/report`
  - :white_check_mark: `/dev/attestation/quote`

  - :white_check_mark: `/dev/attestation/keys`
    - :white_check_mark: `/dev/attestation/keys/<key_name>`
  - :ballot_box_with_check: `/dev/attestation/protected_files_key`: deprecated

</details>

## Notes on System V ABI

> :warning: Below description assumes x86-64 architecture.

Gramine implements the system-call entry point (analogous to the `SYSCALL` x86 instruction).
Instead of performing a context switch from userland (ring-3) to kernelspace (ring-0), Gramine
relies on the system call being routed directly into Gramine process. There are two paths how the
application's system call requests end up in Gramine emulation:

1. Fast path, through patched C standard library (e.g. Glibc or musl): Gramine ships patched Glibc
   and musl where raw `SYSCALL` instructions are replaced with function calls into Gramine's syscall
   entry point.

2. Slow path, through an exception-handling mechanism:
   - In case of Linux backend, Gramine sets up a seccomp policy that redirects all syscall requests
     from the Linux kernel back into the Gramine process.
   - In case of SGX backend, Intel SGX hardware itself forbids the `SYSCALL` instruction and instead
     generates a `#UD` (illegal instruction) exception, which is delivered into the Gramine process.

The fast path is recommended for all applications. However, some applications bypass Glibc/musl and
issue raw `SYSCALL` instructions (e.g., Golang statically compiled binaries); in this case the slow
path is activated.

Gramine's syscall entry point implementation first saves the CPU context of the current application
thread on the internal stack, then calls the syscall-emulation function, which, upon returning,
calls context restoring function, which passes control back to the application thread.  The context
consists of GPRs, FP control word (fpcw) and the SSE/AVX/... control word (mxcsr).

Note that Gramine may clobber all FP/SSE/AVX/... (extended) state except the control words. We rely
on the fact that applications do *not* assume that this extended state is preserved across system
calls. Indeed, the extended state (bar control words) is explicitly described as *not* preserved by
the System V ABI, and we assume that no sane application issues syscalls in a non-System-V compliant
manner. See [System V ABI docs, "Register Usage"](https://uclibc.org/docs/psABI-x86_64.pdf) for more
information.

Gramine supports Linux x86-64 signal frames.

## Notes on application loading

Gramine can execute only ELF binaries (executables and libraries) and scripts (aka shebangs). Other
formats are not supported.

Gramine does *not* perform any dynamic linking during binary loading. Instead it just executes load
commands and transfers control to the dynamic linker (ld).

In case of SGX backend, Gramine needs a hint whether the first loaded binary is PIE or non-PIE. This
hint may be provided via the [`sgx.nonpie_binary` manifest
option](https://gramine.readthedocs.io/en/stable/manifest-syntax.html#non-pie-binaries).
