/*
 * This is for enclave to make ocalls to untrusted runtime.
 */

#pragma once

#include <asm/stat.h>
#include <linux/poll.h>
#include <linux/socket.h>

#include "pal_linux.h"
#include "pal_linux_types.h"
#include "sgx_attest.h"

noreturn void ocall_exit(int exitcode, int is_exitgroup);

int ocall_mmap_untrusted(void** addrptr, size_t size, int prot, int flags, int fd, off_t offset);

int ocall_munmap_untrusted(const void* addr, size_t size);

int ocall_cpuid(unsigned int leaf, unsigned int subleaf, unsigned int values[4]);

int ocall_open(const char* pathname, int flags, unsigned short mode);

int ocall_close(int fd);

ssize_t ocall_read(int fd, void* buf, size_t count);

ssize_t ocall_write(int fd, const void* buf, size_t count);

ssize_t ocall_pread(int fd, void* buf, size_t count, off_t offset);

ssize_t ocall_pwrite(int fd, const void* buf, size_t count, off_t offset);

int ocall_fstat(int fd, struct stat* buf);

int ocall_fionread(int fd);

int ocall_fsetnonblock(int fd, int nonblocking);

int ocall_fchmod(int fd, unsigned short mode);

int ocall_fsync(int fd);

int ocall_ftruncate(int fd, uint64_t length);

int ocall_mkdir(const char* pathname, unsigned short mode);

int ocall_getdents(int fd, struct linux_dirent64* dirp, size_t size);

int ocall_socket(int family, int type, int protocol);

int ocall_bind(int fd, struct sockaddr_storage* addr, size_t addrlen, uint16_t* out_new_port);

int ocall_listen_simple(int fd, unsigned int backlog);

int ocall_listen(int domain, int type, int protocol, int ipv6_v6only, struct sockaddr* addr,
                 size_t* addrlen);

int ocall_accept(int sockfd, struct sockaddr* addr, size_t* addrlen, struct sockaddr* local_addr,
                 size_t* local_addrlen, int options);

int ocall_connect(int domain, int type, int protocol, int ipv6_v6only, const struct sockaddr* addr,
                  size_t addrlen, struct sockaddr* bind_addr, size_t* bind_addrlen);

int ocall_connect_simple(int fd, struct sockaddr_storage* addr, size_t* addrlen);

ssize_t ocall_recv(int sockfd, struct iovec* buf, size_t iov_len, void* addr, size_t* addrlenptr,
                   void* control, size_t* controllenptr, unsigned int flags);

ssize_t ocall_send(int sockfd, const struct iovec* iov, size_t iov_len, const void* addr,
                   size_t addrlen, void* control, size_t controllen, unsigned int flags);

int ocall_setsockopt(int sockfd, int level, int optname, const void* optval, size_t optlen);

int ocall_shutdown(int sockfd, int how);

int ocall_resume_thread(void* tcs);

int ocall_sched_setaffinity(void* tcs, unsigned long* cpu_mask, size_t cpu_mask_len);

int ocall_sched_getaffinity(void* tcs, unsigned long* cpu_mask, size_t cpu_mask_len);

int ocall_clone_thread(void);

int ocall_create_process(size_t nargs, const char** args, uintptr_t (*reserved_mem_ranges)[2],
                         size_t reserved_mem_ranges_len, int* out_stream_fd);

int ocall_futex(uint32_t* uaddr, int op, int val, uint64_t* timeout_us);

int ocall_gettime(uint64_t* microsec);

void ocall_sched_yield(void);

int ocall_poll(struct pollfd* fds, size_t nfds, uint64_t* timeout_us);

int ocall_rename(const char* oldpath, const char* newpath);

int ocall_delete(const char* pathname);

int ocall_debug_map_add(const char* name, void* addr);

int ocall_debug_map_remove(void* addr);

int ocall_debug_describe_location(uintptr_t addr, char* buf, size_t buf_size);

int ocall_eventfd(int flags);

/*!
 * \brief Execute untrusted code in PAL to obtain a quote from the Quoting Enclave.
 *
 * \param      spid       Software provider ID (SPID); if NULL then DCAP/ECDSA is used.
 * \param      linkable   Quote type (linkable vs unlinkable); ignored if DCAP/ECDSA is used.
 * \param      report     Enclave report to be sent to the Quoting Enclave.
 * \param      nonce      16B nonce to be included in the quote for freshness; ignored if
 *                        DCAP/ECDSA is used.
 * \param[out] quote      Quote returned by the Quoting Enclave (allocated via malloc() in this
 *                        function; the caller gets the ownership of the quote).
 * \param[out] quote_len  Length of the quote returned by the Quoting Enclave.
 *
 * \returns 0 on success, negative Linux error code otherwise.
 *
 * The obtained quote is not validated in any way (i.e., this function does not check whether the
 * returned quote corresponds to this enclave or whether its contents make sense).
 */
int ocall_get_quote(const sgx_spid_t* spid, bool linkable, const sgx_report_t* report,
                    const sgx_quote_nonce_t* nonce, char** quote, size_t* quote_len);
