#define _GNU_SOURCE
#include <arpa/inet.h>
#include <err.h>
#include <errno.h>
#include <malloc.h>
#include <netinet/in.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "common.h"

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
            strncpy(ifreq.ifr_name, ifr->ifr_name, sizeof(ifreq.ifr_name));
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
    printf("TEST OK\n");
    return 0;
}
