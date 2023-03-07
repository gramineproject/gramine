<!-- Cannot render this doc in reStructuredText as it has no support for nested inline markup. -->

<!-- If this document is moved to another dir, relative links must be modified. -->

# Gramine features

> ⚠ This is a highly technical document intended for software engineers with knowledge of OS
> kernels.

> ⛏ This is a living document. The last major update happened in **March 2023**.

Gramine strives to **run native, unmodified Linux applications** on any platform. The SGX backend
additionally strives to **provide security guarantees**, in particular, protect against a malicious
host OS.

Gramine **intercepts all application requests** to the host OS. Some of these requests are processed
entirely inside Gramine, and some are funneled through a thin API to the host OS. Either way, each
application's request and each host's reply are verified for correctness and consistency. For these
verifications, Gramine maintains internal, "shadow" state. Thus, Gramine defends against [Iago
attacks](https://dl.acm.org/doi/10.1145/2490301.2451145).

Gramine strives to be **100% compatible with the Linux kernel**, even when it deviates from
standards like POSIX ("bug-for-bug compatibility"). At the same time, Gramine is minimalistic, and
implements **only the most important subset of Linux functionality**, enough to run portable,
hardware-independent applications.

Gramine currently has two backends: execution on the host Linux OS (called `gramine-direct`) and
execution inside an Intel SGX enclave (called `gramine-sgx`). If some feature has quirks and
peculiarities in some backend, we describe it explicitly. More backends are possible in the future.

Features implemented in Gramine can be classified as:

- **Linux features**: features can be (1) implemented, (2) partially implemented, or (3) not
  implemented at all in Gramine. If the feature is partially implemented, then we also document the
  parts that are implemented and the parts that are not implemented. If the feature is not
  implemented at all, we also specify whether there are plans to implement it in the future (and if
  not, the rationale why not).

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

- **Linux userspace-to-kernel interface**, consisting of two sub-interfaces:

  - **Linux System Call Interface**: a set of system calls which allow applications to access system
    resources and services. Examples: `open()`, `fork()`, `gettimeofday()`.

  - **Pseudo filesystems**: a set of special directories with file contents containing information
    about the Gramine instance, system resources, hardware configuration, etc. These filesystems are
    generated on the fly upon Gramine startup. Examples: `/proc/cpuinfo`, `/dev/attestation/quote`.

- **Linux kernel-to-userspace interface**, in particular, two standards:

  - **System V ABI**: defines how applications invoke system calls and receive signals.
  - **Executable and Linking Format (ELF)**: defines how applications are loaded from binary files.

---

Legend:

- ☑ implemented (no serious limitations)
- ▣ partially implemented (serious limitations or quirks)
- ☒ not implemented

## List of system calls

Gramine implements ~170 system calls out of ~360 system calls available on Linux. Many system calls
are implemented only partially, typically because real world workloads do not use the unimplemented
functionality (for example, `O_ASYNC` flag in `open()` is not used widely). Some system calls are
not implemented because they are deprecated in Linux, because they are unused by real world
applications or because they don't fit the purpose of Gramine ("virtualize a single application").

The list of implemented system calls grows with time, as Gramine adds functionality required by real
world workloads.

The below list is generated from the [syscall table of Linux
6.0](https://github.com/torvalds/linux/blob/v6.0/arch/x86/entry/syscalls/syscall_64.tbl).

<details><summary>Status of system call support in Gramine</summary>

- ☑ `read()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>
  <sup>[14](#event-notifications-eventfd)</sup>

- ☑ `write()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>
  <sup>[14](#event-notifications-eventfd)</sup>

- ▣ `open()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `close()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>
  <sup>[14](#event-notifications-eventfd)</sup>

- ▣ `stat()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `fstat()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ▣ `lstat()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `poll()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>
  <sup>[12](#i-o-multiplexing)</sup>
  <sup>[14](#event-notifications-eventfd)</sup>

- ▣ `lseek()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `mmap()`
  <sup>[6](#memory-management)</sup>
  <sup>[9a](#file-system-operations)</sup>

- ▣ `mprotect()`
  <sup>[6](#memory-management)</sup>

- ☑ `munmap()`
  <sup>[6](#memory-management)</sup>

- ☑ `brk()`
  <sup>[6](#memory-management)</sup>
  <sup>[22](#system-information-and-resource-accounting)</sup>

- ☑ `rt_sigaction()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☑ `rt_sigprocmask()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☑ `rt_sigreturn()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ▣ `ioctl()`
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>
  <sup>[18](#ioctls)</sup>

- ☑ `pread64()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `pwrite64()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `readv()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ☑ `writev()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ▣ `access()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `pipe()`
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>

- ▣ `select()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>
  <sup>[12](#i-o-multiplexing)</sup>
  <sup>[14](#event-notifications-eventfd)</sup>

- ☑ `sched_yield()`
  <sup>[4](#scheduling)</sup>

- ☒ `mremap()`
  <sup>[6](#memory-management)</sup>

- ▣ `msync()`
  <sup>[6](#memory-management)</sup>
  <sup>[9a](#file-system-operations)</sup>

- ▣ `mincore()`
  <sup>[6](#memory-management)</sup>

- ▣ `madvise()`
  <sup>[6](#memory-management)</sup>

- ☒ `shmget()`
  <sup>[17](#shared-memory)</sup>

- ☒ `shmat()`
  <sup>[17](#shared-memory)</sup>

- ☒ `shmctl()`
  <sup>[17](#shared-memory)</sup>

- ☑ `dup()`
  <sup>[23](#misc)</sup>

- ☑ `dup2()`
  <sup>[23](#misc)</sup>

- ☑ `pause()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☑ `nanosleep()`
  <sup>[20](#sleeps-timers-and-alarms)</sup>

- ▣ `getitimer()`
  <sup>[20](#sleeps-timers-and-alarms)</sup>

- ☑ `alarm()`
  <sup>[20](#sleeps-timers-and-alarms)</sup>

- ▣ `setitimer()`
  <sup>[20](#sleeps-timers-and-alarms)</sup>

- ☑ `getpid()`
  <sup>[3](#process-and-thread-identifiers)</sup>

- ▣ `sendfile()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ▣ `socket()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ☑ `connect()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ☑ `accept()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ▣ `sendto()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ▣ `recvfrom()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ▣ `sendmsg()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ▣ `recvmsg()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ☑ `shutdown()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ☑ `bind()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ☑ `listen()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ☑ `getsockname()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ☑ `getpeername()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ☑ `socketpair()`
  <sup>[11b](#unix-domain-sockets)</sup>

- ☑ `setsockopt()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ☑ `getsockopt()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ☑ `clone()`
  <sup>[1](#processes)</sup>
  <sup>[2](#threads)</sup>

- ☑ `fork()`
  <sup>[1](#processes)</sup>

- ☑ `vfork()`
  <sup>[1](#processes)</sup>

- ☑ `execve()`
  <sup>[1](#processes)</sup>

- ☑ `exit()`
  <sup>[1](#processes)</sup>
  <sup>[2](#threads)</sup>

- ▣ `wait4()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ▣ `kill()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ▣ `uname()`
  <sup>[22](#system-information-and-resource-accounting)</sup>

- ☒ `semget()`
  <sup>[15](#semaphores)</sup>

- ☒ `semop()`
  <sup>[15](#semaphores)</sup>

- ☒ `semctl()`
  <sup>[15](#semaphores)</sup>

- ☒ `shmdt()`
  <sup>[17](#shared-memory)</sup>

- ☒ `msgget()`
  <sup>[16](#message-queues)</sup>

- ☒ `msgsnd()`
  <sup>[16](#message-queues)</sup>

- ☒ `msgrcv()`
  <sup>[16](#message-queues)</sup>

- ☒ `msgctl()`
  <sup>[16](#message-queues)</sup>

- ▣ `fcntl()`
  <sup>[9b](#file-locking)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>
  <sup>[23](#misc)</sup>

- ☒ `flock()`
  <sup>[9b](#file-locking)</sup>

- ☑ `fsync()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `fdatasync()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `truncate()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `ftruncate()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `getdents()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `getcwd()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `chdir()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `fchdir()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `rename()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `mkdir()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `rmdir()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `creat()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `link()`
  <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>

- ☑ `unlink()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `symlink()`
  <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>

- ▣ `readlink()`
  <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>

- ☑ `chmod()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `fchmod()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `chown()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `fchown()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `lchown()`
  <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>

- ☑ `umask()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `gettimeofday()`
  <sup>[19](#date-and-time)</sup>
  <sup>[23](#misc)</sup>

- ▣ `getrlimit()`
  <sup>[22](#system-information-and-resource-accounting)</sup>

- ☒ `getrusage()`
  <sup>[22](#system-information-and-resource-accounting)</sup>

- ▣ `sysinfo()`
  <sup>[22](#system-information-and-resource-accounting)</sup>

- ☒ `times()`
  <sup>[19](#date-and-time)</sup>

- ☒ `ptrace()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ▣ `getuid()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ☒ `syslog()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ▣ `getgid()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ▣ `setuid()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ▣ `setgid()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ▣ `geteuid()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ▣ `getegid()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ▣ `setpgid()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ☑ `getppid()`
  <sup>[3](#process-and-thread-identifiers)</sup>

- ▣ `getpgrp()`
  <sup>[3](#process-and-thread-identifiers)</sup>

- ☒ `setsid()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `setreuid()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ☒ `setregid()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ▣ `getgroups()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ▣ `setgroups()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ☒ `setresuid()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ☒ `getresuid()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ☒ `setresgid()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ☒ `getresgid()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ▣ `getpgid()`
  <sup>[3](#process-and-thread-identifiers)</sup>

- ☒ `setfsuid()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ☒ `setfsgid()`
  <sup>[8](#user-and-group-identifiers)</sup>

- ☒ `getsid()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `capget()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `capset()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☑ `rt_sigpending()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☑ `rt_sigtimedwait()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☒ `rt_sigqueueinfo()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☑ `rt_sigsuspend()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☑ `sigaltstack()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☒ `utime()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `mknod()`
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>

- ☒ `uselib()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `personality()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `ustat()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `statfs()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `fstatfs()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `sysfs()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `getpriority()`
  <sup>[4](#scheduling)</sup>

- ▣ `setpriority()`
  <sup>[4](#scheduling)</sup>

- ▣ `sched_setparam()`
  <sup>[4](#scheduling)</sup>

- ▣ `sched_getparam()`
  <sup>[4](#scheduling)</sup>

- ▣ `sched_setscheduler()`
  <sup>[4](#scheduling)</sup>

- ▣ `sched_getscheduler()`
  <sup>[4](#scheduling)</sup>

- ▣ `sched_get_priority_max()`
  <sup>[4](#scheduling)</sup>

- ▣ `sched_get_priority_min()`
  <sup>[4](#scheduling)</sup>

- ▣ `sched_rr_get_interval()`
  <sup>[4](#scheduling)</sup>

- ▣ `mlock()`
  <sup>[6](#memory-management)</sup>

- ▣ `munlock()`
  <sup>[6](#memory-management)</sup>

- ▣ `mlockall()`
  <sup>[6](#memory-management)</sup>

- ▣ `munlockall()`
  <sup>[6](#memory-management)</sup>

- ☒ `vhangup()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `modify_ldt()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `pivot_root()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `_sysctl()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `prctl()`
  <sup>[2](#threads)</sup>

- ▣ `arch_prctl()`
  <sup>[2](#threads)</sup>

- ☒ `adjtimex()`
  <sup>[19](#date-and-time)</sup>

- ▣ `setrlimit()`
  <sup>[22](#system-information-and-resource-accounting)</sup>

- ☑ `chroot()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `sync()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `acct()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `settimeofday()`
  <sup>[19](#date-and-time)</sup>

- ☒ `mount()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `umount2()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `swapon()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `swapoff()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `reboot()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ▣ `sethostname()`
  <sup>[22](#system-information-and-resource-accounting)</sup>

- ▣ `setdomainname()`
  <sup>[22](#system-information-and-resource-accounting)</sup>

- ☒ `iopl()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `ioperm()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `create_module()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `init_module()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `delete_module()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `get_kernel_syms()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `query_module()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `quotactl()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `nfsservctl()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `getpmsg()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `putpmsg()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `afs_syscall()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `tuxcall()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `security()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☑ `gettid()`
  <sup>[3](#process-and-thread-identifiers)</sup>

- ☒ `readahead()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `setxattr()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `lsetxattr()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `fsetxattr()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `getxattr()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `lgetxattr()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `fgetxattr()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `listxattr()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `llistxattr()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `flistxattr()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `removexattr()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `lremovexattr()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `fremovexattr()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ▣ `tkill()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☑ `time()`
  <sup>[19](#date-and-time)</sup>

- ▣ `futex()`
  <sup>[5](#memory-synchronization-futexes)</sup>

- ☑ `sched_setaffinity()`
  <sup>[4](#scheduling)</sup>

- ☑ `sched_getaffinity()`
  <sup>[4](#scheduling)</sup>

- ☒ `set_thread_area()`
  <sup>[2](#threads)</sup>

- ☒ `io_setup()`
  <sup>[13](#asynchronous-i-o)</sup>

- ☒ `io_destroy()`
  <sup>[13](#asynchronous-i-o)</sup>

- ☒ `io_getevents()`
  <sup>[13](#asynchronous-i-o)</sup>

- ☒ `io_submit()`
  <sup>[13](#asynchronous-i-o)</sup>

- ☒ `io_cancel()`
  <sup>[13](#asynchronous-i-o)</sup>

- ☒ `get_thread_area()`
  <sup>[2](#threads)</sup>

- ☒ `lookup_dcookie()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☑ `epoll_create()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>
  <sup>[12](#i-o-multiplexing)</sup>
  <sup>[14](#event-notifications-eventfd)</sup>

- ☒ `remap_file_pages()`
  <sup>[6](#memory-management)</sup>

- ☑ `getdents64()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `set_tid_address()`
  <sup>[3](#process-and-thread-identifiers)</sup>

- ☒ `restart_syscall()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `semtimedop()`
  <sup>[15](#semaphores)</sup>

- ▣ `fadvise64()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `timer_create()`
  <sup>[20](#sleeps-timers-and-alarms)</sup>

- ☒ `timer_settime()`
  <sup>[20](#sleeps-timers-and-alarms)</sup>

- ☒ `timer_gettime()`
  <sup>[20](#sleeps-timers-and-alarms)</sup>

- ☒ `timer_getoverrun()`
  <sup>[20](#sleeps-timers-and-alarms)</sup>

- ☒ `timer_delete()`
  <sup>[20](#sleeps-timers-and-alarms)</sup>

- ☒ `clock_settime()`
  <sup>[19](#date-and-time)</sup>

- ▣ `clock_gettime()`
  <sup>[19](#date-and-time)</sup>

- ▣ `clock_getres()`
  <sup>[19](#date-and-time)</sup>

- ▣ `clock_nanosleep()`
  <sup>[20](#sleeps-timers-and-alarms)</sup>

- ☑ `exit_group()`
  <sup>[1](#processes)</sup>

- ☑ `epoll_wait()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>
  <sup>[12](#i-o-multiplexing)</sup>
  <sup>[14](#event-notifications-eventfd)</sup>

- ☑ `epoll_ctl()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>
  <sup>[12](#i-o-multiplexing)</sup>
  <sup>[14](#event-notifications-eventfd)</sup>

- ☑ `tgkill()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☒ `utimes()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `vserver()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ▣ `mbind()`
  <sup>[6](#memory-management)</sup>

- ☒ `set_mempolicy()`
  <sup>[6](#memory-management)</sup>

- ☒ `get_mempolicy()`
  <sup>[6](#memory-management)</sup>

- ☒ `mq_open()`
  <sup>[16](#message-queues)</sup>

- ☒ `mq_unlink()`
  <sup>[16](#message-queues)</sup>

- ☒ `mq_timedsend()`
  <sup>[16](#message-queues)</sup>

- ☒ `mq_timedreceive()`
  <sup>[16](#message-queues)</sup>

- ☒ `mq_notify()`
  <sup>[16](#message-queues)</sup>

- ☒ `mq_getsetattr()`
  <sup>[16](#message-queues)</sup>

- ☒ `kexec_load()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ▣ `waitid()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☒ `add_key()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `request_key()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `keyctl()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `ioprio_set()`
  <sup>[4](#scheduling)</sup>

- ☒ `ioprio_get()`
  <sup>[4](#scheduling)</sup>

- ☒ `inotify_init()`
  <sup>[9c](#monitoring-filesystem-events-inotify-fanotify)</sup>

- ☒ `inotify_add_watch()`
  <sup>[9c](#monitoring-filesystem-events-inotify-fanotify)</sup>

- ☒ `inotify_rm_watch()`
  <sup>[9c](#monitoring-filesystem-events-inotify-fanotify)</sup>

- ☒ `migrate_pages()`
  <sup>[6](#memory-management)</sup>

- ▣ `openat()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `mkdirat()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `mknodat()`
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>

- ▣ `fchownat()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `futimesat()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `newfstatat()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `unlinkat()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `renameat()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `linkat()`
  <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>

- ☒ `symlinkat()`
  <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>

- ▣ `readlinkat()`
  <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>

- ☑ `fchmodat()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `faccessat()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `pselect6()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>
  <sup>[12](#i-o-multiplexing)</sup>
  <sup>[14](#event-notifications-eventfd)</sup>

- ▣ `ppoll()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>
  <sup>[12](#i-o-multiplexing)</sup>
  <sup>[14](#event-notifications-eventfd)</sup>

- ☒ `unshare()`
  <sup>[1](#processes)</sup>
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☑ `set_robust_list()`
  <sup>[5](#memory-synchronization-futexes)</sup>

- ☑ `get_robust_list()`
  <sup>[5](#memory-synchronization-futexes)</sup>

- ☒ `splice()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `tee()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `sync_file_range()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `vmsplice()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `move_pages()`
  <sup>[6](#memory-management)</sup>

- ☒ `utimensat()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `epoll_pwait()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>
  <sup>[12](#i-o-multiplexing)</sup>
  <sup>[14](#event-notifications-eventfd)</sup>

- ☒ `signalfd()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☒ `timerfd_create()`
  <sup>[20](#sleeps-timers-and-alarms)</sup>

- ▣ `eventfd()`
  <sup>[14](#event-notifications-eventfd)</sup>

- ▣ `fallocate()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `timerfd_settime()`
  <sup>[20](#sleeps-timers-and-alarms)</sup>

- ☒ `timerfd_gettime()`
  <sup>[20](#sleeps-timers-and-alarms)</sup>

- ☑ `accept4()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ☒ `signalfd4()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ▣ `eventfd2()`
  <sup>[14](#event-notifications-eventfd)</sup>

- ☑ `epoll_create1()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>
  <sup>[12](#i-o-multiplexing)</sup>
  <sup>[14](#event-notifications-eventfd)</sup>

- ☑ `dup3()`
  <sup>[23](#misc)</sup>

- ▣ `pipe2()`
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>

- ☒ `inotify_init1()`
  <sup>[9c](#monitoring-filesystem-events-inotify-fanotify)</sup>

- ☑ `preadv()`
  <sup>[9a](#file-system-operations)</sup>

- ☑ `pwritev()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `rt_tgsigqueueinfo()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☒ `perf_event_open()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ▣ `recvmmsg()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ☒ `fanotify_init()`
  <sup>[9c](#monitoring-filesystem-events-inotify-fanotify)</sup>

- ☒ `fanotify_mark()`
  <sup>[9c](#monitoring-filesystem-events-inotify-fanotify)</sup>

- ▣ `prlimit64()`
  <sup>[22](#system-information-and-resource-accounting)</sup>

- ☒ `name_to_handle_at()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `open_by_handle_at()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `clock_adjtime()`
  <sup>[19](#date-and-time)</sup>

- ☒ `syncfs()`
  <sup>[9a](#file-system-operations)</sup>

- ▣ `sendmmsg()`
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>

- ☒ `setns()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ▣ `getcpu()`
  <sup>[4](#scheduling)</sup>
  <sup>[23](#misc)</sup>

- ☒ `process_vm_readv()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `process_vm_writev()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `kcmp()`
  <sup>[1](#processes)</sup>

- ☒ `finit_module()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `sched_setattr()`
  <sup>[4](#scheduling)</sup>

- ☒ `sched_getattr()`
  <sup>[4](#scheduling)</sup>

- ☒ `renameat2()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `seccomp()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☑ `getrandom()`
  <sup>[21](#randomness)</sup>

- ☒ `memfd_create()`
  <sup>[6](#memory-management)</sup>

- ☒ `kexec_file_load()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `bpf()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `execveat()`
  <sup>[1](#processes)</sup>

- ☒ `userfaultfd()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☒ `membarrier()`
  <sup>[6](#memory-management)</sup>

- ▣ `mlock2()`
  <sup>[6](#memory-management)</sup>

- ☒ `copy_file_range()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `preadv2()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `pwritev2()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `pkey_mprotect()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `pkey_alloc()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `pkey_free()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `statx()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `io_pgetevents()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `rseq()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `pidfd_send_signal()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☒ `io_uring_setup()`
  <sup>[13](#asynchronous-i-o)</sup>

- ☒ `io_uring_enter()`
  <sup>[13](#asynchronous-i-o)</sup>

- ☒ `io_uring_register()`
  <sup>[13](#asynchronous-i-o)</sup>

- ☒ `open_tree()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `move_mount()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `fsopen()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `fsconfig()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `fsmount()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `fspick()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `pidfd_open()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☒ `clone3()`
  <sup>[1](#processes)</sup>
  <sup>[2](#threads)</sup>

- ☒ `close_range()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `openat2()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `pidfd_getfd()`
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☒ `faccessat2()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `process_madvise()`
  <sup>[6](#memory-management)</sup>
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☒ `epoll_pwait2()`
  <sup>[9a](#file-system-operations)</sup>
  <sup>[10](#pipes-and-fifos-named-pipes)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
  <sup>[11b](#unix-domain-sockets)</sup>
  <sup>[12](#i-o-multiplexing)</sup>
  <sup>[14](#event-notifications-eventfd)</sup>

- ☒ `mount_setattr()`
  <sup>[9a](#file-system-operations)</sup>

- ☒ `quotactl_fd()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `landlock_create_ruleset()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `landlock_add_rule()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `landlock_restrict_self()`
  <sup>[24](#advanced-infeasible-unimplemented-features)</sup>

- ☒ `memfd_secret()`
  <sup>[6](#memory-management)</sup>

- ☒ `process_mrelease()`
  <sup>[6](#memory-management)</sup>
  <sup>[7](#signals-and-process-state-changes)</sup>

- ☒ `futex_waitv()`
  <sup>[5](#memory-synchronization-futexes)</sup>

- ☒ `set_mempolicy_home_node()`
  <sup>[6](#memory-management)</sup>

</details><br />

## List of pseudo-files

Gramine partially emulates Linux pseudo-filesystems: `/dev`, `/proc` and `/sys`.

Only a subset of most widely used pseudo-files is implemented. The list of implemented pseudo-files
grows with time, as Gramine adds functionality required by real-world workloads.

<details><summary>List of all pseudo-files in Gramine</summary>

- ☑ `/dev/` <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>
  <sup>[15](#semaphores)</sup> <sup>[17](#shared-memory)</sup> <sup>[25](#attestation)</sup>

  - ☑ `/dev/attestation/` <sup>[25](#attestation)</sup>
    - ☑ `/dev/attestation/attestation_type` <sup>[25](#attestation)</sup>
    - ☑ `/dev/attestation/user_report_data` <sup>[25](#attestation)</sup>
    - ☑ `/dev/attestation/target_info` <sup>[25](#attestation)</sup>
    - ☑ `/dev/attestation/my_target_info` <sup>[25](#attestation)</sup>
    - ☑ `/dev/attestation/report` <sup>[25](#attestation)</sup>
    - ☑ `/dev/attestation/keys` <sup>[25](#attestation)</sup>
      - ☑ `/dev/attestation/keys/<key_name>` <sup>[25](#attestation)</sup>
    - ▣ `/dev/attestation/protected_files_key`
      <sup>[25](#attestation)</sup>
  - ☑ `/dev/null` <sup>[23](#misc)</sup>
  - ☑ `/dev/zero` <sup>[23](#misc)</sup>
  - ☑ `/dev/random` <sup>[21](#randomness)</sup>
  - ☑ `/dev/urandom` <sup>[21](#randomness)</sup>
  - ☒ `/dev/shm` <sup>[15](#semaphores)</sup> <sup>[17](#shared-memory)</sup>
  - ☑ `/dev/stdin` <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>
  - ☑ `/dev/stdout` <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>
  - ☑ `/dev/stderr` <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>

- ▣ `/proc/`
  <sup>[3](#process-and-thread-identifiers)</sup>
  <sup>[8](#user-and-group-identifiers)</sup>
  <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>
  <sup>[22](#system-information-and-resource-accounting)</sup>
  <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup> <sup>[11b](#unix-domain-sockets)</sup>
  - ▣ `/proc/[this-pid]/` (aka `/proc/self/`)
    <sup>[3](#process-and-thread-identifiers)</sup>
    <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>
    - ☑ `/proc/[this-pid]/cmdline` <sup>[3](#process-and-thread-identifiers)</sup>
    - ☑ `/proc/[this-pid]/cwd` <sup>[3](#process-and-thread-identifiers)</sup>
      <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>
    - ☑ `/proc/[this-pid]/exe` <sup>[3](#process-and-thread-identifiers)</sup>
      <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>
    - ☑ `/proc/[this-pid]/fd` <sup>[3](#process-and-thread-identifiers)</sup>
    - ☑ `/proc/[this-pid]/maps` <sup>[3](#process-and-thread-identifiers)</sup>
    - ☑ `/proc/[this-pid]/root` <sup>[3](#process-and-thread-identifiers)</sup>
      <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>
    - ▣ `/proc/[this-pid]/stat`
      <sup>[3](#process-and-thread-identifiers)</sup>
    - ▣ `/proc/[this-pid]/statm`
      <sup>[3](#process-and-thread-identifiers)</sup>
    - ▣ `/proc/[this-pid]/status`
      <sup>[3](#process-and-thread-identifiers)</sup>
      <sup>[8](#user-and-group-identifiers)</sup>
    - ☑ `/proc/[this-pid]/task` <sup>[3](#process-and-thread-identifiers)</sup>

  - ▣ `/proc/[remote-pid]/`
    <sup>[3](#process-and-thread-identifiers)</sup>
    <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>
    - ☑ `/proc/[remote-pid]/cwd` <sup>[3](#process-and-thread-identifiers)</sup>
      <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>
    - ☑ `/proc/[remote-pid]/exe` <sup>[3](#process-and-thread-identifiers)</sup>
      <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>
    - ☑ `/proc/[remote-pid]/root` <sup>[3](#process-and-thread-identifiers)</sup>
      <sup>[9d](#hard-links-and-soft-links-symbolic-links)</sup>

  - ▣ `/proc/[local-tid]/`
    <sup>[3](#process-and-thread-identifiers)</sup>

  - ☒ `/proc/[remote-tid]/` <sup>[3](#process-and-thread-identifiers)</sup>

  - ▣ `/proc/cpuinfo`
    <sup>[22](#system-information-and-resource-accounting)</sup>
  - ▣ `/proc/meminfo`
    <sup>[22](#system-information-and-resource-accounting)</sup>
  - ▣ `/proc/stat`
    <sup>[22](#system-information-and-resource-accounting)</sup>

  - ▣ `/proc/sys/`
    <sup>[3](#process-and-thread-identifiers)</sup>
    <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup> <sup>[11b](#unix-domain-sockets)</sup>
    - ▣ `/proc/sys/kernel/`
      <sup>[3](#process-and-thread-identifiers)</sup>
      - ☑ `/proc/sys/kernel/pid_max`
        <sup>[3](#process-and-thread-identifiers)</sup>
    - ☒ `/proc/sys/net/` <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
      <sup>[11b](#unix-domain-sockets)</sup>
      - ☒ `/proc/sys/net/core/` <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
      - ☒ `/proc/sys/net/ipv4/` <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
      - ☒ `/proc/sys/net/ipv6/` <sup>[11a](#tcp-ip-and-udp-ip-sockets)</sup>
      - ☒ `/proc/sys/net/unix/` <sup>[11b](#unix-domain-sockets)</sup>

- ▣ `/sys/devices/system/`
  <sup>[22](#system-information-and-resource-accounting)</sup>
  - ▣ `/sys/devices/system/cpu/`
    <sup>[22](#system-information-and-resource-accounting)</sup>
    - ▣ `/sys/devices/system/cpu/cpu[x]/`
      <sup>[22](#system-information-and-resource-accounting)</sup>
      - ▣ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/`
        <sup>[22](#system-information-and-resource-accounting)</sup>
        - ☑ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/coherency_line_size`
          <sup>[22](#system-information-and-resource-accounting)</sup>
        - ☑ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/level`
          <sup>[22](#system-information-and-resource-accounting)</sup>
        - ☑ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/number_of_sets`
          <sup>[22](#system-information-and-resource-accounting)</sup>
        - ☑ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/physical_line_partition`
          <sup>[22](#system-information-and-resource-accounting)</sup>
        - ☑ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/shared_cpu_map`
          <sup>[22](#system-information-and-resource-accounting)</sup>
        - ☑ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/size`
          <sup>[22](#system-information-and-resource-accounting)</sup>
        - ☑ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/type`
          <sup>[22](#system-information-and-resource-accounting)</sup>
      - ☑ `/sys/devices/system/cpu/cpu[x]/online`
        <sup>[22](#system-information-and-resource-accounting)</sup>
      - ▣ `/sys/devices/system/cpu/cpu[x]/topology/`
        <sup>[22](#system-information-and-resource-accounting)</sup>
        - ☑ `/sys/devices/system/cpu/cpu[x]/topology/core_id`
          <sup>[22](#system-information-and-resource-accounting)</sup>
        - ☑ `/sys/devices/system/cpu/cpu[x]/topology/core_siblings`
          <sup>[22](#system-information-and-resource-accounting)</sup>
        - ☑ `/sys/devices/system/cpu/cpu[x]/topology/physical_package_id`
          <sup>[22](#system-information-and-resource-accounting)</sup>
        - ☑ `/sys/devices/system/cpu/cpu[x]/topology/thread_siblings`
          <sup>[22](#system-information-and-resource-accounting)</sup>
    - ☑ `/sys/devices/system/cpu/online`
      <sup>[22](#system-information-and-resource-accounting)</sup>
    - ☑ `/sys/devices/system/cpu/possible`
      <sup>[22](#system-information-and-resource-accounting)</sup>

  - ▣ `/sys/devices/system/node/`
    <sup>[22](#system-information-and-resource-accounting)</sup>
    - ▣ `/sys/devices/system/node/node[x]/`
      <sup>[22](#system-information-and-resource-accounting)</sup>
      - ☑ `/sys/devices/system/node/node[x]/cpumap`
        <sup>[22](#system-information-and-resource-accounting)</sup>
      - ☑ `/sys/devices/system/node/node[x]/distance`
        <sup>[22](#system-information-and-resource-accounting)</sup>
      - ☑ `/sys/devices/system/node/node[x]/hugepages/`
        <sup>[22](#system-information-and-resource-accounting)</sup>
        - ▣
          `/sys/devices/system/node/node[x]/hugepages/hugepages-[y]/nr_hugepages`
          <sup>[22](#system-information-and-resource-accounting)</sup>
      - ▣ `/sys/devices/system/node/node[x]/meminfo`
        <sup>[22](#system-information-and-resource-accounting)</sup>

</details><br />

## Linux features

### Processes

Gramine supports multi-processing. A Gramine instance starts the first (main) process, as specified
in the entrypoint of the manifest. The first process can spawn child processes, which belong to the
same Gramine instance.

Gramine can execute ELF binaries (executables and libraries) and executable scripts. Gramine
supports executing them as [entrypoints](../manifest-syntax.html#libos-entrypoint) and via
`execve()` system call. In case of SGX backend, `execve()` execution replaces a calling program with
a new program *in the same SGX enclave*.

Gramine supports creating child processes using `fork()`, `vfork()` and `clone()` system calls.
`vfork()` is emulated via `fork()`. `clone()` always means a separate process with its own address
space (i.e., `CLONE_THREAD`, `CLONE_FILES`, etc. flags cannot be specified). In case of SGX backend,
child processes are created *in a new SGX enclave*.

Currently, Gramine does *not* fully support fork in multi-threaded applications. There is a [known
bug in Gramine](https://github.com/gramineproject/gramine/issues/1156) that if one thread is
performing fork and another thread modifies the internal Gramine state, the state may get corrupted
(which may lead to failures).

Gramine supports process termination using `exit()` and `exit_group()` system calls. If there are
child processes executing and the first process exits, Gramine currently does *not* kill child
processes; this is however not a problem in practice because the host OS cleans up these orphaned
children.

All aforementioned system calls follow Linux semantics, barring the mentioned peculiarities.
However, properties of processes not supported by Gramine (e.g. namespaces, pidfd, etc.) are
ignored.

Gramine does *not* support disassociating parts of the process execution context (via `unshare()`
system call). Gramine does *not* support comparing two processes (via `kcmp()`).

<details><summary>Related system calls</summary>

- ☑ `execve()`
- ☒ `execveat()`: very rarely used by applications
- ☑ `clone()`: except exotic combination `CLONE_VM & !CLONE_THREAD & !CLONE_VFORK`
- ☑ `fork()`
- ☑ `vfork()`: with the same semantics as `fork()`
- ☑ `exit()`
- ☑ `exit_group()`
- ☒ `clone3()`: very rarely used by applications
- ☒ `unshare()`: very rarely used by applications
- ☒ `kcmp()`: very rarely used by applications

</details>

<details><summary>Additional materials</summary>

- `LD_LIBRARY_PATH` environment variable is always propagated into new process, see
  [the issue](https://github.com/gramineproject/graphene/issues/2081).

</details><br />

### Threads

Gramine implements multi-threading. In case of SGX backend, all threads of one Gramine process run
in the same SGX enclave.

Gramine implements per-thread:
- information about signal (alternate) stack,
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

<details><summary>Note on thread's stack size</summary>

Gramine sets the same stack size for each thread. Gramine does *not* support dynamic growth of the
first-thread stack (as Linux does). The stack size in Gramine can be configured via the
[`sys.stack.size` manifest option](../manifest-syntax.html#stack-size).

</details>

<details><summary>Related system calls</summary>

- ☑ `clone()`: must have combination `CLONE_VM | CLONE_THREAD`
- ☑ `exit()`
- ☒ `get_thread_area()`: very rarely used by applications
- ☒ `set_thread_area()`: very rarely used by applications
- ☒ `prctl()`: very rarely used by applications
- ▣ `arch_prctl()`: only x86-specific subset of flags
  - ☑ `ARCH_GET_FS`
  - ☑ `ARCH_SET_FS`
  - ☒ `ARCH_GET_GS`
  - ☒ `ARCH_SET_GS`
- ☒ `clone3()`: very rarely used by applications

</details><br />

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

<details><summary>Related system calls</summary>

- ☑ `getpid()`
- ☑ `getppid()`
- ☑ `gettid()`
- ☑ `set_tid_address()`

- ▣ `getpgid()`: dummy, see above
- ▣ `setpgid()`: dummy, see above
- ▣ `getpgrp()`: dummy, see above

</details>

<details><summary>Related pseudo-files</summary>

- ▣ `/proc/[this-pid]/` (aka `/proc/self/`):
  only most important files implemented
  - ☑ `/proc/[this-pid]/cmdline`
  - ☑ `/proc/[this-pid]/cwd`
  - ☑ `/proc/[this-pid]/exe`
  - ☑ `/proc/[this-pid]/fd`
  - ☑ `/proc/[this-pid]/maps`
  - ☑ `/proc/[this-pid]/root`
  - ▣ `/proc/[this-pid]/stat`: partially implemented
    - ☑ `pid`, `comm`, `ppid`, `pgrp`, `num_threads`, `vsize`, `rss`
    - ▣ `state`: always indicates "R" (running)
    - ▣ `flags`: indicates only `PF_RANDOMIZE`
    - ☒ rest fields: always zero
  - ▣ `/proc/[this-pid]/statm`: partially implemented
    - ☑ `size`/`VmSize`, `resident`/`VmRSS`
    - ☒ rest fields: always zero
  - ▣ `/proc/[this-pid]/status`: partially implemented
    - ☑ `VmPeak`
    - ☒ rest fields: not printed
  - ☑ `/proc/[this-pid]/task`

- ▣ `/proc/[remote-pid]/`: minimally implemented
  - ☑ `/proc/[remote-pid]/cwd`
  - ☑ `/proc/[remote-pid]/exe`
  - ☑ `/proc/[remote-pid]/root`

- ▣ `/proc/[local-tid]/`: same as `/proc/[this-pid]`

- ☒ `/proc/[remote-tid]/`: very rarely used by applications

- ☑ `/proc/sys/kernel/pid_max`

</details><br />

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

<details><summary>Related system calls</summary>

- ☑ `sched_yield()`
- ☑ `sched_getaffinity()`
- ☑ `sched_setaffinity()`

- ▣ `getcpu()`: dummy, returns a random allowed CPU
- ▣ `getpriority()`: dummy, returns default value
- ▣ `setpriority()`: dummy, does nothing
- ▣ `sched_getparam()`: dummy, returns default values
- ▣ `sched_setparam()`: dummy, does nothing
- ▣ `sched_getscheduler()`: dummy, returns default value
- ▣ `sched_setscheduler()`: dummy, does nothing
- ▣ `sched_get_priority_max()`: dummy, returns default
  value
- ▣ `sched_get_priority_min()`: dummy, returns default
- ▣ `sched_rr_get_interval()`: dummy, returns default
  value

- ☒ `sched_getattr()`: very rarely used by applications
- ☒ `sched_setattr()`: very rarely used by applications
- ☒ `ioprio_get()`: very rarely used by applications
- ☒ `ioprio_set()`: very rarely used by applications

</details><br />

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

<details><summary>Related system calls</summary>

- ▣ `futex()`: see notes above
- ☑ `get_robust_list()`
- ☑ `set_robust_list()`

- ☒ `futex_waitv()`: very rarely used by applications

</details><br />

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
- on [systems supporting EDMM](../sgx-intro.html#term-edmm), `mprotect()` correctly applies
  permissions;
- on systems not supporting EDMM, all enclave memory is allocated with Read-Write-Execute
  permissions, and `mprotect()` calls are silently ignored.

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
- `mremap()` is not implemented (very rarely used by applications);
- `msync()` implements only `MS_SYNC` and `MS_ASYNC` (`MS_INVALIDATE` is not implemented);
- `mbind()` is a no-op;
- `mincore()` always tells that pages are *not* in RAM;
- `set_mempolicy()` and `get_mempolicy` are not implemented;
- `mlock()`, `munlock()`, `mlockall()`, `munlockall()`, `mlock2()` are dummy (always return
  success).

As can be seen from above, many performance-improving system calls, flags and features are currently
*not* implemented by Gramine. Keep it in mind when you observe application performance degradation.

<details><summary>Related system calls</summary>

- ☑ `brk()`
- ▣ `mmap()`: see above for notes
- ▣ `mprotect()`: see above for notes
- ☑ `munmap()`

- ▣ `msync()`: does not implement `MS_INVALIDATE`
- ▣ `madvise()`: see above for notes
- ▣ `mbind()`: dummy
- ▣ `mincore()`: dummy
- ▣ `mlock()`: dummy
- ▣ `munlock()`: dummy
- ▣ `mlockall()`: dummy
- ▣ `munlockall()`: dummy
- ▣ `mlock2()`: dummy

- ☒ `mremap()`: very rarely used by applications
- ☒ `remap_file_pages()`: very rarely used by applications
- ☒ `set_mempolicy()`: may be implemented in the future
- ☒ `get_mempolicy()`: may be implemented in the future
- ☒ `memfd_create()`: may be implemented in the future
- ☒ `memfd_secret()`: very rarely used by applications
- ☒ `membarrier()`: may be implemented in the future
- ☒ `move_pages()`: very rarely used by applications
- ☒ `migrate_pages()`: very rarely used by applications
- ☒ `process_madvise()`: very rarely used by applications
- ☒ `process_mrelease()`: very rarely used by applications
- ☒ `set_mempolicy_home_node()`: very rarely used by applications

</details><br />

### Overview of Inter-Process Communication (IPC)

Gramine implements most of the Linux IPC mechanisms. In particular:

- ☑ Signals and process state changes
- ☑ Pipes
- ☑ FIFOs (named pipes)
- ▣ UNIX domain sockets
- ▣ File locking
- ☒ Message queues
- ☒ Semaphores
- ☒ Shared memory

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

<details><summary>Additional materials</summary>

- For Linux IPC overview, we recommend reading [Beej's Guide to Unix
  IPC](https://beej.us/guide/bgipc/html/).

- In case of SGX backend, pipes, FIFOs, UDSes and all other IPC communication are encrypted using
  the TLS-PSK (TLS with Pre-Shared Keys) protocol. The pre-shared key is randomly generated for each
  new Gramine instance. Before establishing any pipe/IPC communication, two Gramine processes (e.g.,
  parent and child) verify each other's trustworthiness using SGX local attestation.

</details><br />

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
host](../manifest-syntax.html#external-sigterm-injection). No other signals from the host are
supported. By default, Gramine ignores all signals sent by the host (including signals sent from
other applications or from other Gramine instances). This limitation is for security reasons,
relevant on SGX backend.

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

<details><summary>Related system calls</summary>

- ☑ `pause()`
- ☑ `rt_sigaction()`
- ☑ `rt_sigpending()`
- ☑ `rt_sigprocmask()`
- ☑ `rt_sigreturn()`
- ☑ `rt_sigsuspend()`
- ☑ `rt_sigtimedwait()`
- ☑ `sigaltstack()`

- ☒ `rt_sigqueueinfo()`: very rarely used by applications
- ☒ `rt_tgsigqueueinfo()`: very rarely used by applications
- ☒ `signalfd()`: very rarely used by applications
- ☒ `signalfd4()`: very rarely used by applications
- ☒ `pidfd_open()`: very rarely used by applications
- ☒ `pidfd_getfd()`: very rarely used by applications
- ☒ `pidfd_send_signal()`: very rarely used by applications
- ☒ `process_madvise()`: very rarely used by applications
- ☒ `process_mrelease()`: very rarely used by applications
- ☒ `userfaultfd()`: very rarely used by applications

- ▣ `kill()`: process groups not supported
- ▣ `tkill()`: remote threads not supported
- ☑ `tgkill()`

- ▣ `wait4()`: `WSTOPPED` and `WCONTINUED` not supported
- ▣ `waitid()`: `WSTOPPED` and `WCONTINUED` not supported

</details><br />

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
[`loader.uid`](../manifest-syntax.html#user-id-and-group-id). Similarly, the application is started
with GID = EGID = SGID and equal to `loader.gid`. If these manifest options are not set, then all
IDs are equal to zero, which means root user.

During execution, the application may modify these IDs, and the changes will be visible inside the
Gramine environment.

Gramine does *not* support Filesystem user ID (FSUID) and filesystem group ID (FSGID). The
corresponding system calls are `setfsuid()` and `setfsgid()` (not implemented).

Gramine has dummy support for Supplementary group IDs. The corresponding system calls are
`getgroups()` and `setgroups()`. Gramine starts the applications with an empty set of supplementary
groups. The application may modify this set, and the changes will be visible inside the Gramine
environment.

Currently, there are only two usages of user/group IDs in Gramine:
- changing ownership of a file via `chown()` and similar system calls;
- passing user ID in the SIGCHLD signal information on child process termination (in
  `siginfo_t::si_uid`).

Gramine does *not* currently implement user/group ID fields in the `/proc/[pid]/status` pseudo-file.

<details><summary>Related system calls</summary>

- ▣ `getuid()`: dummy
- ▣ `getgid()`: dummy
- ▣ `setuid()`: dummy
- ▣ `setgid()`: dummy
- ▣ `geteuid()`: dummy
- ▣ `getegid()`: dummy
- ▣ `getgroups()`: dummy
- ▣ `setgroups()`: dummy

- ☒ `setreuid()`: very rarely used by applications, may be implemented in the future
- ☒ `setregid()`: very rarely used by applications, may be implemented in the future
- ☒ `getresuid()`: very rarely used by applications, may be implemented in the future
- ☒ `setresuid()`: very rarely used by applications, may be implemented in the future
- ☒ `getresgid()`: very rarely used by applications, may be implemented in the future
- ☒ `setresgid()`: very rarely used by applications, may be implemented in the future
- ☒ `setfsuid()`: very rarely used by applications
- ☒ `setfsgid()`: very rarely used by applications

</details>

<details><summary>Related pseudo-files</summary>

- ☒ `/proc/[this-pid]/status`: fields `Uid`, `Gid`, `Groups` are not implemented

</details><br />

### File systems

Gramine implements file system operations, but with several peculiarities and limitations.

The most important peculiarity is that Gramine does *not* simply mirror the host OS's directory
hierarchy. Instead, Gramine constructs its own view on the selected subset of host's directories and
files: this is controlled by the manifest's [FS mount points
(`fs.mounts`)](../manifest-syntax.html#fs-mount-points). This feature is similar to the *volumes*
concept in [Docker](https://docs.docker.com/storage/volumes/). This Gramine feature is introduced
for security.

Another peculiarity is that Gramine provides several types of filesystem mounts:
- passthrough mounts (contain unencrypted files, see below),
- encrypted mounts (contain files that are automatically encrypted and integrity-protected).

In case of SGX backend, passthrough mounts must be of one of two kinds:
- containing allowed files (not encrypted or cryptographically hashed),
- containing trusted files (cryptographically hashed -- effectively, their contents are mixed into
  MRENCLAVE on SGX).

Additionally, mounts may be hosted in one of two ways:
- on the host OS (in passthrough mounts),
- inside the Gramine process (in *tmpfs* mounts).

All files potentially used by the application must be specified in the manifest file. Instead of
single files, whole directories can be specified. Refer to the [manifest documentation for more
details](../manifest-syntax.html#manifest-syntax).

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
- no operations across mounts, e.g., no rename of file located in one mount to another one (note
  that Linux also doesn't support such operations);
- no synchronization of file offsets, file sizes, etc. between Gramine processes;
- tmpfs mounts (in-memory file systems) are not shared by Gramine processes;
- File timestamps (access, modified, change timestamps) are not set/updated.

<details><summary>Additional materials</summary>

A mechanism for FS synchronization, as well as a general redesign of certain FS components, is a
task Gramine will tackle in the future. Below are some discussions and RFCs:

- <https://github.com/gramineproject/graphene/issues/2158>
- <https://github.com/gramineproject/gramine/issues/12>
- <https://github.com/gramineproject/gramine/issues/584>
- <https://github.com/gramineproject/gramine/issues/578>

</details><br />

#### File system operations

Gramine implements all classic file system operations, but with limitations described below.

Gramine supports opening files and directories (via `open()` and `openat()` system calls).
`O_CLOEXEC`, `O_CREAT`, `O_DIRECTORY`, `O_EXCL`, `O_NOFOLLOW`, `O_PATH`, `O_TRUNC` flags are
supported. Other flags are ignored. Notable ignored flags are `O_APPEND` (not yet implemented in
Gramine) and `O_TMPFILE` (bug in Gramine: should not be silently ignored).

Trusted files can be opened only for reading. Already-existing encrypted files can be opened only if
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
Regular files always return events "there is data to read" and "writing is possible". Other files
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
Therefore, `chown()`, `fchownat()`, `fchown()` system calls update UID and GID inside the
Gramine environment, but not on host files.

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

<details><summary>Related system calls</summary>

- ▣ `open()`: implemented, with limitations
- ▣ `openat()`: implemented, with limitations
- ☑ `close()`
- ☑ `creat()`
- ☑ `mkdir()`
- ☑ `mkdirat()`
- ☑ `getdents()`
- ☑ `getdents64()`
- ☑ `unlink()`
- ☑ `unlinkat()`
- ☑ `rmdir()`
- ▣ `rename()`: cannot rename across mounts
- ▣ `renameat()`: cannot rename across mounts

- ☑ `read()`
- ☑ `pread64()`
- ☑ `readv()`
- ☑ `preadv()`
- ☑ `write()`
- ☑ `pwrite64()`
- ☑ `writev()`
- ☑ `pwritev()`

- ▣ `lseek()`: see note above
- ▣ `mmap()`: see notes above
- ▣ `msync()`: see notes above
- ▣ `select()`: dummy
- ▣ `pselect6()`: dummy
- ▣ `poll()`: dummy
- ▣ `ppoll()`: dummy
- ☑ `fsync()`
- ☑ `fdatasync()`
- ▣ `truncate()`: see note above
- ▣ `ftruncate()`: see note above
- ▣ `fallocate()`: dummy
- ▣ `fadvise64()`: dummy

- ☑ `chmod()`
- ☑ `fchmod()`
- ☑ `fchmodat()`
- ▣ `chown()`: dummy
- ▣ `fchown()`: dummy
- ▣ `fchownat()`: dummy
- ▣ `access()`: dummy
- ▣ `faccessat()`: dummy
- ☑ `umask()`

- ▣ `sendfile()`: unoptimized

- ☑ `chdir()`
- ☑ `fchdir()`
- ☑ `getcwd()`

- ▣ `stat()`: partially dummy
- ▣ `fstat()`: partially dummy
- ▣ `lstat()`: partially dummy, always resolves to actual
  file
- ▣ `newfstatat()`: partially dummy
- ▣ `statfs()`: partially dummy
- ▣ `fstatfs()`: partially dummy

- ☑ `chroot()`

- ☒ `name_to_handle_at()`: very rarely used by applications
- ☒ `open_by_handle_at()`: very rarely used by applications
- ☒ `openat2()`: very rarely used by applications
- ☒ `renameat2()`: very rarely used by applications
- ☒ `preadv2()`: very rarely used by applications
- ☒ `pwritev2()`: very rarely used by applications
- ☒ `epoll_create()`: very rarely used by applications
- ☒ `epoll_create1()`: very rarely used by applications
- ☒ `epoll_wait()`: very rarely used by applications
- ☒ `epoll_pwait()`: very rarely used by applications
- ☒ `epoll_pwait2()`: very rarely used by applications
- ☒ `epoll_ctl()`: very rarely used by applications
- ☒ `sync()`: very rarely used by applications
- ☒ `syncfs()`: very rarely used by applications
- ☒ `sync_file_range()`: very rarely used by applications
- ☒ `faccessat2()`: very rarely used by applications
- ☒ `statx()`: very rarely used by applications
- ☒ `sysfs()`: very rarely used by applications
- ☒ `ustat()`: very rarely used by applications
- ☒ `mount()`: very rarely used by applications
- ☒ `move_mount()`: very rarely used by applications
- ☒ `umount2()`: very rarely used by applications
- ☒ `mount_setattr()`: very rarely used by applications
- ☒ `pivot_root()`: very rarely used by applications
- ☒ `utime()`: may be implemented in the future
- ☒ `utimes()`: may be implemented in the future
- ☒ `futimesat()`: may be implemented in the future
- ☒ `utimensat()`: may be implemented in the future

</details><br />

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

<details><summary>Related system calls</summary>

- ▣ `fcntl()`
  - ▣ `F_SETLK`: see notes above
  - ▣ `F_SETLKW`: see notes above
  - ▣ `F_GETLK`: see notes above

- ☒ `flock()`: may be implemented in the future

</details><br />

#### Monitoring filesystem events (inotify, fanotify)

Gramine does *not* currently implement inotify and fanotify APIs. Gramine could implement them in
the future, if need arises.

<details><summary>Related system calls</summary>

- ☒ `inotify_init()`
- ☒ `inotify_init1()`
- ☒ `inotify_add_watch()`
- ☒ `inotify_rm_watch()`
- ☒ `fanotify_init()`
- ☒ `fanotify_mark()`

</details><br />

#### Hard links and soft links (symbolic links)

There are two notions that must be discussed separately:

1. Host OS's links: Gramine sees them as normal files. On Linux host, these links are currently
   always followed during directory/file lookup.
2. In-Gramine links: Gramine has no support for links (i.e., applications cannot create links).
   - There is one exception: some pseudo-files like `/proc/[pid]/cwd` and `/proc/self`.

The above means that Gramine does not implement `link()` and `symlink()` system calls. Support for
`readlink()` system call is limited to only pseudo-files' links mentioned above.

Gramine may implement hard and soft links in the future.

<details><summary>Related system calls</summary>

- ☒ `link()`
- ☒ `symlink()`
- ▣ `readlink()`: see note above
- ☒ `linkat()`
- ☒ `symlinkat()`
- ▣ `readlinkat()`: see note above
- ☒ `lchown()`

</details>

<details><summary>Related pseudo-files</summary>

The following pseudo-files are symlinks. See also "Related pseudo-files" in the ["Process and thread
identifiers" section](#process-and-thread-identifiers).

- ☑ `/dev/`
  - ☑ `/dev/stdin`
  - ☑ `/dev/stdout`
  - ☑ `/dev/stderr`

- ☑ `/proc/self/`

- ☑ `/proc/[pid]/`
  - ☑ `/proc/[pid]/cwd`
  - ☑ `/proc/[pid]/exe`
  - ☑ `/proc/[pid]/root`

</details><br />

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

<details><summary>Related system calls</summary>

- ☑ `pipe()`
- ▣ `pipe2()`: `O_DIRECT` flag is ignored
- ▣ `mknod()`: `S_ISFIFO` type is supported
- ▣ `mknodat()`: `S_ISFIFO` type is supported
- ☑ `close()`

- ☑ `fstat()`

- ☑ `read()`
- ☑ `readv()`
- ☑ `write()`
- ☑ `writev()`

- ☑ `select()`
- ☑ `pselect6()`
- ☑ `poll()`
- ☑ `ppoll()`
- ☑ `epoll_create()`
- ☑ `epoll_create1()`
- ☑ `epoll_wait()`
- ☑ `epoll_pwait()`
- ☑ `epoll_ctl()`
- ☒ `epoll_pwait2()`: very rarely used by applications

- ▣ `sendfile()`: unoptimized

- ▣ `fcntl()`
  - ▣ `F_GETFL`: only `O_NONBLOCK`
  - ▣ `F_SETFL`: only `O_NONBLOCK`
  - ☒ `F_GETPIPE_SZ`: very rarely used by applications
  - ☒ `F_SETPIPE_SZ`: very rarely used by applications

- ▣ `ioctl()`
  - ☑ `FIONREAD`
  - ☑ `FIONBIO`

</details><br />

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

<details><summary>Note on domain names configuration</summary>

- To use libc name-resolving Berkeley socket APIs like `gethostbyname()`, `gethostbyaddr()`,
  `getaddrinfo`, one must enable the [`sys.enable_extra_runtime_domain_names_conf` manifest
  option](../manifest-syntax.html#domain-names-configuration).

</details>

<details><summary>Related system calls</summary>

- ▣ `socket()`: see notes above
- ☑ `bind()`
- ☑ `listen()`
- ☑ `accept()`
- ☑ `accept4()`
- ☑ `connect()`
- ☑ `close()`
- ☑ `shutdown()`

- ☑ `getsockname()`
- ☑ `getpeername()`
- ☑ `getsockopt()`
- ☑ `setsockopt()`

- ☑ `fstat()`

- ☑ `read()`
- ☑ `readv()`
- ☑ `write()`
- ☑ `writev()`

- ▣ `recv()`: see supported flags above
- ▣ `recvfrom()`: see supported flags above
- ▣ `recvmsg()`: see supported flags above
- ▣ `recvmmsg()`: see supported flags above
- ▣ `send()`: see supported flags above
- ▣ `sendto()`: see supported flags above
- ▣ `sendmsg()`: see supported flags above
- ▣ `sendmmsg()`: see supported flags above

- ☑ `select()`
- ☑ `pselect6()`
- ☑ `poll()`
- ☑ `ppoll()`
- ☑ `epoll_create()`
- ☑ `epoll_create1()`
- ☑ `epoll_wait()`
- ☑ `epoll_pwait()`
- ☑ `epoll_ctl()`
- ☒ `epoll_pwait2()`: very rarely used by applications

- ▣ `sendfile()`: unoptimized

- ▣ `fcntl()`
  - ▣ `F_GETFL`: only `O_NONBLOCK`
  - ▣ `F_SETFL`: only `O_NONBLOCK`

- ▣ `ioctl()`
  - ☑ `FIONREAD`
  - ☑ `FIONBIO`

</details>

<details><summary>Related pseudo-files</summary>

- ☒ `/proc/sys/net/core/`
- ☒ `/proc/sys/net/ipv4/`
- ☒ `/proc/sys/net/ipv6/`

</details><br />

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

<details><summary>Note on named UDSes</summary>

- There is an effort to make named UDSes visible on the Gramine filesystem, see
  <https://github.com/gramineproject/gramine/pull/1021>.

</details>

<details><summary>Related system calls</summary>

- ☑ `socketpair()`
- For other system calls, see ["TCP/IP and UDP/IP sockets" subsection](#tcp-ip-and-udp-ip-sockets)
  above.

</details>

<details><summary>Related pseudo-files</summary>

- ☒ `/proc/sys/net/unix/`
- For other pseudo-files, see ["TCP/IP and UDP/IP sockets" subsection](#tcp-ip-and-udp-ip-sockets)
  above.

</details><br />

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

<details><summary>Note on EPOLLERR/EPOLLHUP/EPOLLRDHUP</summary>

There is a pending [GitHub pull request](https://github.com/gramineproject/gramine/pull/1073) to
distinguish between the three error conditions.

</details>

<details><summary>Related system calls</summary>

- ☑ `select()`
- ☑ `pselect6()`
- ☑ `poll()`
- ☑ `ppoll()`
- ▣ `epoll_create()`: see notes above
- ▣ `epoll_create1()`: see notes above
- ▣ `epoll_wait()`: see notes above
- ▣ `epoll_pwait()`: see notes above
- ▣ `epoll_ctl()`: see notes above
- ☒ `epoll_pwait2()`: very rarely used by applications

</details><br />

### Asynchronous I/O

There are two asynchronous I/O APIs in Linux kernel:
- Linux POSIX asynchronous I/O (Linux AIO, older API with `io_setup()` etc.),
- I/O uring (io_uring, newer API with `io_uring_setup()` etc.).

Gramine does *not* currently implement either of these APIs. Gramine could implement them in the
future, if need arises.

Note that AIO provided in userspace by glibc (`aio_read()`, `aio_write()`, etc.) does not depend on
Gramine and is supported.

<details><summary>Related system calls</summary>

- ☒ `io_setup()`
- ☒ `io_destroy()`
- ☒ `io_getevents()`
- ☒ `io_submit()`
- ☒ `io_cancel()`

- ☒ `io_uring_setup()`
- ☒ `io_uring_enter()`
- ☒ `io_uring_register()`

</details><br />

### Event notifications (eventfd)

Gramine currently implements an *insecure* version of the `eventfd()` system call. It is considered
insecure in the context of SGX backend because it relies on the host OS, which could for example
maliciously drop an event or inject a random one. To enable this `eventfd()` implementation, the
manifest file must contain [`sys.insecure__allow_eventfd =
true`](../manifest-syntax.html#allowing-eventfd).

Gramine supports polling on eventfd via `poll()`, `ppoll()`, `select()`, `epoll_*()` system calls.

Gramine may implement a secure version of `eventfd()` for communication between Gramine processes in
the future. Such secure version will *not* be able to receive events from the host OS.

<details><summary>Related system calls</summary>

- ▣ `eventfd()`: insecure implementation
- ▣ `eventfd2()`: insecure implementation
- ☑ `close()`

- ☑ `read()`
- ☑ `write()`

- ☑ `select()`
- ☑ `pselect6()`
- ☑ `poll()`
- ☑ `ppoll()`
- ☑ `epoll_create()`
- ☑ `epoll_create1()`
- ☑ `epoll_wait()`
- ☑ `epoll_pwait()`
- ☑ `epoll_ctl()`
- ☒ `epoll_pwait2()`: very rarely used by applications

</details><br />

### Semaphores

There are two semaphore APIs in Linux kernel:
- System V semaphores (older API),
- POSIX semaphores (newer API).

POSIX semaphores are technically not a Linux kernel API. Instead, they are implemented on top of the
POSIX shared memory functionality of Linux by libc (i.e., via `/dev/shm` pseudo-filesystem).

Gramine does *not* currently implement either of these APIs. Gramine could implement them in
the future, if need arises.

<details><summary>Related system calls</summary>

- ☒ `semget()`
- ☒ `semop()`
- ☒ `semtimedop()`
- ☒ `semctl()`

</details>

<details><summary>Related pseudo-files</summary>

- ☒ `/dev/shm`

</details><br />

### Message queues

There are two message-queue APIs in Linux kernel:
- System V message queue (older API),
- POSIX message queue (newer API).

Gramine does *not* currently implement either of these APIs. Gramine could implement them in
the future, if need arises.

<details><summary>Related system calls</summary>

- ☒ `msgget()`
- ☒ `msgctl()`
- ☒ `msgrcv()`
- ☒ `msgsnd()`

- ☒ `mq_open()`
- ☒ `mq_getsetattr()`
- ☒ `mq_notify()`
- ☒ `mq_timedreceive()`
- ☒ `mq_timedsend()`
- ☒ `mq_unlink()`

</details><br />

### Shared memory

There are two shared-memory APIs in Linux kernel:
- System V shared memory (older API),
- POSIX shared memory (newer API).

Gramine does *not* currently implement either of these APIs.

In case of SGX backend, implementation of shared memory would be *insecure*, as shared memory by
design would be allocated in untrusted non-enclave memory, and there is no way for Gramine to
intercept memory accesses to shared memory regions (to provide some security guarantees).

<details><summary>Adding limited POSIX shared memory support</summary>

There is an effort to add limited support for POSIX shared memory, targeted for special use cases
like communication with hardware accelerators (e.g. GPUs):
- [Whitepaper](https://arxiv.org/abs/2203.01813),
- [GitHub issue](https://github.com/gramineproject/gramine/issues/757),
- [GitHub pull request](https://github.com/gramineproject/gramine/pull/827).

</details>

<details><summary>Related system calls</summary>

- ☒ `shmget()`
- ☒ `shmat()`
- ☒ `shmctl()`
- ☒ `shmdt()`

</details>

<details><summary>Related pseudo-files</summary>

- ☒ `/dev/shm`: may be implemented in the future (in a limited insecure way, see note above)

</details><br />

### IOCTLs

Gramine currently implements only a minimal set of IOCTL request codes. See the list under
"Related system calls".

<details><summary>Adding support for arbitrary IOCTLs </summary>

There is an effort to add support for specifying arbitrary IOCTLs (with arbitrary request codes and
corresponding IOCTL data structures), targeted for special use cases like communication with
hardware accelerators (e.g. GPUs):
- [Whitepaper](https://arxiv.org/abs/2203.01813),
- [GitHub issue](https://github.com/gramineproject/gramine/issues/353),
- [GitHub pull request](https://github.com/gramineproject/gramine/pull/671).

</details>

<details><summary>Related system calls</summary>

- ▣ `ioctl()`
  - ▣ `TIOCGPGRP`: dummy
  - ☑ `FIONBIO`
  - ☑ `FIONCLEX`
  - ☑ `FIOCLEX`
  - ☑ `FIOASYNC`
  - ☑ `FIONREAD`

</details><br />

### Date and time

Gramine partially implements getting date/time: `gettimeofday()`, `time()`, `clock_gettime()`,
`clock_getres()` system calls.

Gramine does *not* distinguish between different clocks available for `clock_gettime()` and
`clock_getres()`. All clocks are emulated via the `CLOCK_REALTIME` clock.

Gramine does *not* support setting or adjusting date/time: `settimeofday()`, `clock_settime()`,
`adjtimex()`, `clock_adjtime()`.

Gramine does *not* currently support getting process times (like user time, system time): `times()`.

<details><summary>Note on trustworthiness of date/time on SGX</summary>

In case of SGX backend, date/time cannot be trusted because it is queried from the possibly
malicious host OS. There is currently no solution to this limitation.

</details>

<details><summary>Related system calls</summary>

- ☑ `gettimeofday()`
- ☑ `time()`
- ▣ `clock_gettime()`: all clocks emulated via
  `CLOCK_REALTIME`
- ▣ `clock_getres()`: all clocks emulated via
  `CLOCK_REALTIME`

- ☒ `settimeofday()`: very rarely used by applications
- ☒ `clock_settime()`: very rarely used by applications
- ☒ `adjtimex()`: very rarely used by applications
- ☒ `clock_adjtime()`: very rarely used by applications
- ☒ `times()`: may be implemented in the future

</details><br />

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

<details><summary>Related system calls</summary>

- ☑ `nanosleep()`
- ▣ `clock_nanosleep()`: all clocks emulated via
  `CLOCK_REALTIME`
- ▣ `getitimer()`: only `ITIMER_REAL`
- ▣ `setitimer()`: only `ITIMER_REAL`
- ☑ `alarm()`

- ☒ `timer_create()`: may be implemented in the future
- ☒ `timer_settime()`: may be implemented in the future
- ☒ `timer_gettime()`: may be implemented in the future
- ☒ `timer_getoverrun()`: may be implemented in the future
- ☒ `timer_delete()`: may be implemented in the future

- ☒ `timerfd_create()`: may be implemented in the future
- ☒ `timerfd_settime()`: may be implemented in the future
- ☒ `timerfd_gettime()`: may be implemented in the future

</details><br />

### Randomness

Gramine implements obtaining random bytes via two Linux APIs:
- `getrandom()` system call,
- `/dev/random` and `/dev/urandom` pseudo-files.

In case of SGX backend, Gramine always uses only one source of random bytes: the RDRAND x86
instruction. This is a secure source of randomness.

<details><summary>Related system calls</summary>

- ☑ `getrandom()`

</details>

<details><summary>Related pseudo-files</summary>

- ☑ `/dev/random`
- ☑ `/dev/urandom`

</details><br />

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
- `RLIMIT_STACK` -- dummy, equal to [`sys.stack.size`](../manifest-syntax.html#stack-size) by
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

<details><summary>Related system calls</summary>

- ☒ `getrusage()`
- ▣ `sysinfo()`: only `totalram`, `totalhigh`, `freeram`
  and `freehigh`
- ▣ `uname()`: only `sysname`, `nodename`, `release`,
  `version`, `machine` and `domainname`
- ▣ `sethostname()`: dummy
- ▣ `setdomainname()`: dummy
- ▣ `getrlimit()`: see notes above
- ▣ `setrlimit()`: see notes above
- ▣ `prlimit64()`: see notes above

</details>

<details><summary>Related pseudo-files</summary>

- ▣ `/proc/cpuinfo`: partially implemented
    - ☑ `processor`, `vendor_id`, `cpu family`, `model`, `model name`, `stepping`,
      `physical id`, `core id`, `cpu cores`, `bogomips`
    - ☑ `flags`: all known CPU flags

- ▣ `/proc/meminfo`: partially implemented
    - ☑ `MemTotal`, `MemFree`, `MemAvailable`, `Committed_AS`, `VmallocTotal`
    - ☒ rest fields: always zero

- ▣ `/proc/stat`: dummy
    - ▣ `cpu` line: all fields are zeros
    - ▣ `cpuX` lines: all fields are zeros
    - ▣ `ctxt` line: always zero
    - ▣ `btime` line: always zero
    - ▣ `processes` line: always one
    - ▣ `procs_running` line: always one
    - ▣ `procs_blocked` line: always zero
    - ☒ `intr` line
    - ☒ `softirq` line

- ▣ `/sys/devices/system/cpu/`: only most important files
  implemented
  - ▣ `/sys/devices/system/cpu/cpu[x]/`
    - ▣ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/`
      - ☑ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/coherency_line_size`
      - ☑ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/level`
      - ☑ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/number_of_sets`
      - ☑ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/physical_line_partition`
      - ☑ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/shared_cpu_map`
      - ☑ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/size`
      - ☑ `/sys/devices/system/cpu/cpu[x]/cache/index[x]/type`
    - ☑ `/sys/devices/system/cpu/cpu[x]/online`
    - ▣ `/sys/devices/system/cpu/cpu[x]/topology/`
      - ☑ `/sys/devices/system/cpu/cpu[x]/topology/core_id`
      - ☑ `/sys/devices/system/cpu/cpu[x]/topology/core_siblings`
      - ☑ `/sys/devices/system/cpu/cpu[x]/topology/physical_package_id`
      - ☑ `/sys/devices/system/cpu/cpu[x]/topology/thread_siblings`
  - ☑ `/sys/devices/system/cpu/online`
  - ☑ `/sys/devices/system/cpu/possible`

- ▣ `/sys/devices/system/node/`: only most important files
  implemented
  - ▣ `/sys/devices/system/node/node[x]/`
    - ☑ `/sys/devices/system/node/node[x]/cpumap`
    - ☑ `/sys/devices/system/node/node[x]/distance`
    - ☑ `/sys/devices/system/node/node[x]/hugepages/`
      - ▣
        `/sys/devices/system/node/node[x]/hugepages/hugepages-[y]/nr_hugepages`: always zero
    - ▣ `/sys/devices/system/node/node[x]/meminfo`:
      partially implemented
      - ☑ `MemTotal`, `MemFree`, `MemUsed`
      - ☒ rest fields: always zero

</details><br />

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

<details><summary>Related system calls</summary>

- ☑ `gettimeofday()`: implemented in vDSO
- ▣ `clock_gettime()`: implemented in vDSO
- ☑ `time()`: implemented in vDSO
- ▣ `getcpu()`: implemented in vDSO

- ☑ `dup()`
- ☑ `dup2()`
- ☑ `dup3()`

- ▣ `fcntl()`
  - ☑ `F_DUPFD`
  - ☑ `F_DUPFD_CLOEXEC`
  - ☑ `F_GETFD`
  - ☑ `F_SETFD`

- ▣ `arch_prctl()`
  - ☑ `ARCH_GET_XCOMP_SUPP`
  - ☑ `ARCH_GET_XCOMP_PERM`
  - ☑ `ARCH_REQ_XCOMP_PERM`

</details>

<details><summary>Related pseudo-files</summary>

- ☑ `/dev/`
  - ☑ `/dev/null`
  - ☑ `/dev/zero`

</details><br />

### Advanced/infeasible, unimplemented features

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

<details><summary>Related system calls</summary>

- ☒ `_sysctl()`
- ☒ `acct()`
- ☒ `add_key()`
- ☒ `afs_syscall()`
- ☒ `bpf()`
- ☒ `capget()`
- ☒ `capset()`
- ☒ `close_range()`
- ☒ `copy_file_range()`
- ☒ `create_module()`
- ☒ `delete_module()`
- ☒ `fgetxattr()`
- ☒ `finit_module()`
- ☒ `flistxattr()`
- ☒ `fremovexattr()`
- ☒ `fsconfig()`
- ☒ `fsetxattr()`
- ☒ `fsmount()`
- ☒ `fsopen()`
- ☒ `fspick()`
- ☒ `get_kernel_syms()`
- ☒ `getpmsg()`
- ☒ `getsid()`
- ☒ `getxattr()`
- ☒ `init_module()`
- ☒ `io_pgetevents()`
- ☒ `ioperm()`
- ☒ `iopl()`
- ☒ `kexec_file_load()`
- ☒ `kexec_load()`
- ☒ `keyctl()`
- ☒ `landlock_add_rule()`
- ☒ `landlock_create_ruleset()`
- ☒ `landlock_restrict_self()`
- ☒ `lgetxattr()`
- ☒ `listxattr()`
- ☒ `llistxattr()`
- ☒ `lookup_dcookie()`
- ☒ `lremovexattr()`
- ☒ `lsetxattr()`
- ☒ `modify_ldt()`
- ☒ `nfsservctl()`
- ☒ `nfsservctl()`
- ☒ `open_tree()`
- ☒ `perf_event_open()`
- ☒ `personality()`
- ☒ `pkey_alloc()`
- ☒ `pkey_free()`
- ☒ `pkey_mprotect()`
- ☒ `process_vm_readv()`
- ☒ `process_vm_writev()`
- ☒ `ptrace()`
- ☒ `putpmsg()`
- ☒ `query_module()`
- ☒ `quotactl()`
- ☒ `quotactl_fd()`
- ☒ `readahead()`
- ☒ `reboot()`
- ☒ `removexattr()`
- ☒ `request_key()`
- ☒ `restart_syscall()`
- ☒ `rseq()`
- ☒ `seccomp()`
- ☒ `security()`
- ☒ `setns()`
- ☒ `setsid()`
- ☒ `setxattr()`
- ☒ `splice()`
- ☒ `swapoff()`
- ☒ `swapon()`
- ☒ `syslog()`
- ☒ `tee()`
- ☒ `tuxcall()`
- ☒ `unshare()`
- ☒ `uselib()`
- ☒ `vhangup()`
- ☒ `vmsplice()`
- ☒ `vserver()`

</details><br />

## Gramine-specific features

### Attestation

Gramine exposes low-level abstractions of attestation report and attestation quote objects (*SGX
Report* and *SGX Quote* accordingly, in case of SGX backend) through the `/dev/attestation/`
pseudo-filesystem. Manipulating with the `/dev/attestation/` pseudo-files allows to program local
attestation and remote attestation flows. Additionally, the `/dev/attestation/keys/` pseudo-dir
exposes pseudo-files to set encryption keys (in particular, for encrypted files).

For detailed information, refer to the ["Attestation and Secret Provisioning" documentation of
Gramine](../attestation.html#low-level-dev-attestation-interface).

<details><summary>Related pseudo-files</summary>

- ☑ `/dev/attestation/`
  - ☑ `/dev/attestation/attestation_type`
  - ☑ `/dev/attestation/user_report_data`
  - ☑ `/dev/attestation/target_info`
  - ☑ `/dev/attestation/my_target_info`
  - ☑ `/dev/attestation/report`
  - ☑ `/dev/attestation/quote`

  - ☑ `/dev/attestation/keys`
    - ☑ `/dev/attestation/keys/<key_name>`
  - ▣ `/dev/attestation/protected_files_key`: deprecated

</details><br />

## Notes on System V ABI

> ⚠ Below description assumes x86-64 architecture.

Gramine implements the system-call entry point (analogous to the `SYSCALL` x86 instruction ABI).
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

Gramine can execute only ELF binaries (executables and libraries) and executable scripts. Other
formats are not supported.
