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

struct vln_adapter *vln_adapter_create(int flags)
{
    int err, sfd;
    struct ifreq ifr;
    struct vln_adapter *adapter;
    if ((adapter = malloc(sizeof(struct vln_adapter))) == NULL) {
        dprintf(STDERR_FILENO, "Router: Malloc Failed %s\n", strerror(errno));
        return adapter;
    };
    /* open the clone device */
    if ((adapter->fd = open("/dev/net/tun", O_RDWR)) < 0) {
        dprintf(STDERR_FILENO,
                "Creating newtork adapter failed: \n Opening clone device "
                "failed: %s\n",
                strerror(errno));
        free(adapter);
        return NULL;
    }

    memset(adapter->name, 0, ADAPTER_NAME_SIZE);
    strcpy(adapter->name, ADAPTER_NAME);

    memset(&ifr, 0, sizeof(struct ifreq));

    ifr.ifr_flags = flags;

    strcpy(ifr.ifr_name, adapter->name);

    /* try to create the device */
    if ((err = ioctl(adapter->fd, TUNSETIFF, (void *)&ifr)) < 0) {
        dprintf(STDERR_FILENO,
                "Creating newtork adapter failed: \n Creating device "
                "failed: %s\n",
                strerror(errno));
        free(adapter);
        return NULL;
    }

    if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(STDERR_FILENO,
                "Creating newtork adapter failed: \n Creating socket "
                "failed: %s\n",
                strerror(errno));
        free(adapter);
        return NULL;
    }

    //------------------------
    if (ioctl(sfd, SIOCGIFFLAGS, &ifr) < 0) {
        printf("Getting adapter flags failed: %s\n", strerror(errno));
    }
    //------------------------

    ifr.ifr_flags = IFF_UP | IFF_RUNNING | IFF_NOARP | IFF_POINTOPOINT;
    if (ioctl(sfd, SIOCSIFFLAGS, &ifr) < 0) {
        dprintf(STDERR_FILENO,
                "Creating newtork adapter failed: \n Setting network "
                "adapter flags "
                "failed: %s\n",
                strerror(errno));
        close(sfd);
        free(adapter);
        return NULL;
    }

    close(sfd);

    return adapter;
}

int vln_adapter_set_network(struct vln_adapter *adapter, uint32_t vaddr,
                            uint32_t maskaddr, uint32_t broadaddr)
{

    struct sockaddr_in *addr;
    struct ifreq ifr;

    strcpy(ifr.ifr_name, adapter->name);

    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_addr.s_addr = vaddr;
    addr->sin_family = AF_INET;

    int sfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (ioctl(sfd, SIOCSIFADDR, &ifr) < 0) {
        return -1;
    }
    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    addr->sin_addr.s_addr = maskaddr;

    if (ioctl(sfd, SIOCSIFNETMASK, &ifr) < 0) {
        return -1;
    }

    addr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
    addr->sin_addr.s_addr = broadaddr;

    if (ioctl(sfd, SIOCSIFBRDADDR, &ifr) < 0) {
        return -1;
    }
    close(sfd);
    return 1;
}
void vln_adapter_destroy(struct vln_adapter *adapter)
{
    vln_adapter_set_network(adapter, 0, 0, 0);
    close(adapter->fd);
}
