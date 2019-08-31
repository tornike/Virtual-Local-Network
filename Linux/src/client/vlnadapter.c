#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "vlnadapter.h"

struct tunnel_interface *tunnel_interface_create(int flags)
{
    int err, sfd;
    struct ifreq ifr;
    struct tunnel_interface *interface;
    if ((interface = malloc(sizeof(struct tunnel_interface))) == NULL) {
        dprintf(STDERR_FILENO, "Router: Malloc Failed %s\n", strerror(errno));
        return interface;
    };
    /* open the clone device */
    if ((interface->fd = open("/dev/net/tun", O_RDWR)) < 0) {
        dprintf(STDERR_FILENO,
                "Creating newtork interface failed: \n Opening clone device "
                "failed: %s\n",
                strerror(errno));
        free(interface);
        return NULL;
    }

    memset(&ifr, 0, sizeof(struct ifreq));

    ifr.ifr_flags = flags;

    strcpy(ifr.ifr_name, INTERFACE_NAME);

    /* try to create the device */
    if ((err = ioctl(interface->fd, TUNSETIFF, (void *)&ifr)) < 0) {
        dprintf(STDERR_FILENO,
                "Creating newtork interface failed: \n Creating device "
                "failed: %s\n",
                strerror(errno));
        free(interface);
        return NULL;
    }

    if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(STDERR_FILENO,
                "Creating newtork interface failed: \n Creating socket "
                "failed: %s\n",
                strerror(errno));
        free(interface);
        return NULL;
    }

    //------------------------
    if (ioctl(sfd, SIOCGIFFLAGS, &ifr) < 0) {
        printf("Getting interface flags failed: %s\n", strerror(errno));
    }
    printf("Flags %d\n", ifr.ifr_flags);
    //------------------------

    ifr.ifr_flags = IFF_UP | IFF_RUNNING | IFF_NOARP | IFF_POINTOPOINT;
    if (ioctl(sfd, SIOCSIFFLAGS, &ifr) < 0) {
        dprintf(STDERR_FILENO,
                "Creating newtork interface failed: \n Setting network "
                "interface flags "
                "failed: %s\n",
                strerror(errno));
        close(sfd);
        free(interface);
        return NULL;
    }

    close(sfd);

    return interface;
}

int tunnel_interface_set_network(uint32_t vaddr, uint32_t maskaddr,
                                 uint32_t broadaddr)
{

    struct sockaddr_in *addr;
    struct ifreq ifr;

    strcpy(ifr.ifr_name, INTERFACE_NAME);

    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_addr.s_addr = vaddr;
    addr->sin_family = AF_INET;

    int sfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (ioctl(sfd, SIOCSIFADDR, &ifr) < 0) {
        printf("Setting IP address failed: %s\n", strerror(errno));
        return -1;
    } else {
        printf("Set Inet\n");
    }

    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    addr->sin_addr.s_addr = maskaddr;

    if (ioctl(sfd, SIOCSIFNETMASK, &ifr) < 0) {
        printf("Setting mask address failed: %s\n", strerror(errno));
        return -1;
    } else {
        printf("Set Mask Address\n");
    }

    addr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
    addr->sin_addr.s_addr = broadaddr;

    if (ioctl(sfd, SIOCSIFBRDADDR, &ifr) < 0) {
        printf("Setting brodcast address failed: %s\n", strerror(errno));
        return -1;
    } else {
        printf("Set Brodcast Address\n");
    }
    close(sfd);
    return 1;
}
void tunnel_interface_destroy(struct tunnel_interface *interface)
{
    tunnel_interface_set_network(0, 0, 0);
    close(interface->fd);
}
