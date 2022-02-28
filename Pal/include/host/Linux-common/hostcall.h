#ifndef HOSTCALL_H_
#define HOSTCALL_H_

#if defined(DB_LINUX)
#include "syscall.h"

#define HOSTCALL(name, args...) DO_SYSCALL(name, args)
#elif defined(DB_LINUX_SGX)
#include "enclave_ocalls.h"

#define HOSTCALL(name, args...) ocall_##name(args)
#endif

#endif // HOSTCALL_H_
