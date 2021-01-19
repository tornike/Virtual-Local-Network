/*
 * Virtual Local Network
 *
 * Copyright (C) 2020 VLN authors:
 *
 * Tornike Khachidze <tornike@github>
 * Luka Macharadze <lmach14@github>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

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

#include <vln_adapter.h>

struct vln_adapter *vln_adapter_create(/* const int flags, */ const char *name)
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

    memset(adapter->name, 0, VLN_ADAPTER_NAME_SIZE);
    strcpy(adapter->name, name);

    memset(&ifr, 0, sizeof(struct ifreq));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // flags;

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

int vln_adapter_set_network(struct vln_adapter *adapter, uint32_t addr,
                            uint32_t maskaddr, uint32_t broadaddr)
{

    struct sockaddr_in *addr_in;
    struct ifreq ifr;

    strcpy(ifr.ifr_name, adapter->name);

    addr_in = (struct sockaddr_in *)&ifr.ifr_addr;
    addr_in->sin_addr.s_addr = addr;
    addr_in->sin_family = AF_INET;

    int sfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (ioctl(sfd, SIOCSIFADDR, &ifr) < 0) {
        return -1;
    }
    addr_in = (struct sockaddr_in *)&ifr.ifr_netmask;
    addr_in->sin_addr.s_addr = maskaddr;

    if (ioctl(sfd, SIOCSIFNETMASK, &ifr) < 0) {
        return -1;
    }

    addr_in = (struct sockaddr_in *)&ifr.ifr_broadaddr;
    addr_in->sin_addr.s_addr = broadaddr;

    if (ioctl(sfd, SIOCSIFBRDADDR, &ifr) < 0) {
        return -1;
    }
    close(sfd);
    return 1;
}

void vln_adapter_set_network2(struct vln_adapter *adapter,
                              struct vln_network *network, uint32_t vaddr)
{
    vln_adapter_set_network(adapter, htonl(vaddr), htonl(network->mask_address),
                            htonl(network->mask_address));
}

void vln_adapter_destroy(struct vln_adapter *adapter)
{
    vln_adapter_set_network(adapter, 0, 0, 0);
    close(adapter->fd);
}
