#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <malloc.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "common.h"

/*
 * Sanitization example: intercept `ioctl()` glibc/musl func and add sanitization of SIOCGIFCONF and
 * SIOCGIFHWADDR ioctls used by the main program. (Well, SIOCGIFHWADDR doesn't require sanitization
 * because its data structure has nothing that needs checks.)
 *
 * A more generic solution would probably be in the form of a shared LD_PRELOAD-ed library, or
 * directly inlined in the application codebase.
 *
 * Partial protection is also endorsed by `sgx.ioctl_structs` descriptions in the corresponding
 * manifest (e.g. SIOCGIFHWADDR's `ifreq::ifr_name` is copy-out-only and thus cannot be modified by
 * the attacker on the way back from IOCTL).
 */
#ifdef USE_MUSL
int ioctl(int fd, int request, ...) {
#else
int ioctl(int fd, unsigned long int request, ...) {
#endif
    va_list ap;
    va_start(ap, request);
    void* arg = va_arg(ap, void*);

    /* memoize some fields for SIOCGIFCONF sanitization after the syscall */
    bool initial_ifc = false;
    int initial_ifc_len = 0;
    void* initial_ifc_req = NULL;
    if (request == SIOCGIFCONF) {
        struct ifconf* ifc = (struct ifconf*)arg;
        if (ifc) {
            initial_ifc = true;
            initial_ifc_len = ifc->ifc_len;
            initial_ifc_req = ifc->ifc_req;
        }
    }

    int ret = syscall(SYS_ioctl, fd, request, arg);

    /* sanitize SIOCGIFCONF only; note that SIOCGIFHWADDR doesn't need any sanitization */
    if (request == SIOCGIFCONF && ret == 0 && initial_ifc) {
        struct ifconf* ifc = (struct ifconf*)arg;
        /* verify ifc_len (same checks for both ifc_req==NULL and ifc_req!=NULL cases) */
        if (ifc->ifc_len < 0) {
            fprintf(stderr, "SIOCGIFCONF() returns negative ifc_len");
            errno = EPERM;
            return -1;
        }
        if (ifc->ifc_len % sizeof(struct ifreq)) {
            fprintf(stderr, "SIOCGIFCONF() returns non-aligned ifc_len");
            errno = EPERM;
            return -1;
        }
        if ((ifc->ifc_len / sizeof(struct ifreq)) > 1024) {
            fprintf(stderr, "SIOCGIFCONF() returns too large ifc_len (limit is 1024 ifreq objs)");
            errno = EPERM;
            return -1;
        }

        if (!initial_ifc_req) {
            /* SIOCGIFCONF must return the necessary buffer size for receiving all available
             * addresses in ifc_len; ifc_req must be NULL */
            if (ifc->ifc_req) {
                fprintf(stderr, "SIOCGIFCONF(ifconf::ifc_req=NULL) returns ifc_req != NULL");
                errno = EPERM;
                return -1;
            }
        } else {
            /* ifc_req contains a pointer to an array of ifreq structures to be filled with all
             * currently active L3 interface addresses */
            if (ifc->ifc_req != initial_ifc_req) {
                fprintf(stderr, "SIOCGIFCONF(ifconf::ifc_req) returns modified ifc_req");
                errno = EPERM;
                return -1;
            }
            if (ifc->ifc_len > initial_ifc_len) {
                fprintf(stderr, "SIOCGIFCONF(ifconf::ifc_req) returns ifc_len > initial");
                errno = EPERM;
                return -1;
            }

            /* verify each ifreq structure in the array */
            struct ifreq* ifend = ifc->ifc_req + (ifc->ifc_len / sizeof(struct ifreq));
            for (struct ifreq* ifr = ifc->ifc_req; ifr < ifend; ifr++) {
                if (memchr(ifr->ifr_name, '\0', sizeof(ifr->ifr_name)) == NULL) {
                    fprintf(stderr, "SIOCGIFCONF(ifconf::ifc_req) has ifc_req with bad ifr_name");
                    errno = EPERM;
                    return -1;
                }
            }
        }
    }

    va_end(ap);
    return ret;
}

int main(void) {
    struct ifconf ifc;
    int s = CHECK(socket(AF_INET, SOCK_DGRAM, 0));

    ifc.ifc_req = NULL;
    CHECK(ioctl(s, SIOCGIFCONF, &ifc));

    ifc.ifc_req = (struct ifreq*)malloc(ifc.ifc_len);
    if (ifc.ifc_req == NULL)
        CHECK(-1);

    CHECK(ioctl(s, SIOCGIFCONF, &ifc));

    struct ifreq* ifend = ifc.ifc_req + (ifc.ifc_len / sizeof(struct ifreq));
    for (struct ifreq* ifr = ifc.ifc_req; ifr < ifend; ifr++) {
        if (ifr->ifr_addr.sa_family == AF_INET) {
            struct ifreq ifreq;
            strncpy(ifreq.ifr_name, ifr->ifr_name, sizeof(ifreq.ifr_name) - 1);
            ifreq.ifr_name[sizeof(ifreq.ifr_name) - 1] = '\0';

            CHECK(ioctl(s, SIOCGIFHWADDR, &ifreq));
            printf("interface %s: inet %s ether %02x:%02x:%02x:%02x:%02x:%02x\n", ifreq.ifr_name,
                    inet_ntoa(((struct sockaddr_in*)&ifr->ifr_addr)->sin_addr),
                    (int)((unsigned char*)&ifreq.ifr_hwaddr.sa_data)[0],
                    (int)((unsigned char*)&ifreq.ifr_hwaddr.sa_data)[1],
                    (int)((unsigned char*)&ifreq.ifr_hwaddr.sa_data)[2],
                    (int)((unsigned char*)&ifreq.ifr_hwaddr.sa_data)[3],
                    (int)((unsigned char*)&ifreq.ifr_hwaddr.sa_data)[4],
                    (int)((unsigned char*)&ifreq.ifr_hwaddr.sa_data)[5]);
        }
    }
    free(ifc.ifc_req);
    puts("TEST OK");
    return 0;
}
