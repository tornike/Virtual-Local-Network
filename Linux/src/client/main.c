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

#include "../connection.h"
#include "../lib/protocol.h"
#include "../lib/taskexecutor.h"
#include "../lib/tcpwrapper.h"
#include "../lib/uthash.h"
#include "../router.h"

// TODO!!!!!!!
#define UPDATETABLE 700
#define BUFFERSIZE 4096

//===========GLOBALS===========
char *_server_addr = "34.65.27.69"; // Must be changed.
int _server_port_temp = 33507; // Must be changed.
int _tunfd;
//===========GLOBALS===========

void router_listener(void *args, struct task_info *tinfo)
{
    struct tcpwrapper *server_con = (struct tcpwrapper *)args;
    // TODO;

    printf("Peers Changed\n");
}

/* Arguments taken by the function:
 *
 * char *name is the name of an interface (or '\0'). MUST have enough
 * space to hold the interface name if '\0'.
 *
 * int flags: interface (TUNSETIFF) flags (eg, IFF_TUN etc.)
 */
int create_adapter(char *name, int flags)
{
    int fd, err, sfd;
    struct ifreq ifr;

    /* open the clone device */
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        dprintf(STDERR_FILENO,
                "Creating newtork interface failed: \n Opening clone device "
                "failed: %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof(struct ifreq));

    ifr.ifr_flags = flags;

    if (*name) {
        strcpy(ifr.ifr_name, name);
    }

    /* try to create the device */
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        dprintf(STDERR_FILENO,
                "Creating newtork interface failed: \n Creating device "
                "failed: %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* get actual name of an interface */
    strcpy(name, ifr.ifr_name);

    if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(STDERR_FILENO,
                "Creating newtork interface failed: \n Creating socket "
                "failed: %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
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
        exit(EXIT_FAILURE);
    }

    close(sfd);

    return fd;
}

int add_vaddr_tunnel_interface(struct vln_initr_payload *paylod)
{

    struct sockaddr_in *addr;
    struct ifreq ifr;

    strcpy(ifr.ifr_name, "testint1");

    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_addr.s_addr = paylod->vaddr;
    addr->sin_family = AF_INET;

    int sfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (ioctl(sfd, SIOCSIFADDR, &ifr) < 0) {
        printf("Setting IP address failed: %s\n", strerror(errno));
        return -1;
    } else {
        printf("Set Inet\n");
    }

    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    addr->sin_addr.s_addr = paylod->maskaddr;

    if (ioctl(sfd, SIOCSIFNETMASK, &ifr) < 0) {
        printf("Setting mask address failed: %s\n", strerror(errno));
        return -1;
    } else {
        printf("Set Mask Address\n");
    }

    addr = (struct sockaddr_in *)&ifr.ifr_broadaddr;
    addr->sin_addr.s_addr = paylod->broadaddr;

    if (ioctl(sfd, SIOCSIFBRDADDR, &ifr) < 0) {
        printf("Setting brodcast address failed: %s\n", strerror(errno));
        return -1;
    } else {
        printf("Set Brodcast Address\n");
    }

    // TODO
    // sfd = socket(AF_INET6, SOCK_DGRAM, 0);

    // addr = (struct sockaddr_in *)&ifr.ifr_addr;
    // addr->sin_addr.s_addr = 0;
    // addr->sin_family = AF_INET6;

    // if (ioctl(sfd, SIOCSIFADDR, &ifr) < 0) {
    //     printf("Setting IPV6 address failed: %s\n", strerror(errno));
    //     return -1;
    // } else {
    //     printf("Set IPV6 Address\n");
    // }

    close(sfd);
    return 1;
}

void *recv_thread(void *arg)
{
    struct router *router = (struct router *)arg;
    // TODO
    struct sockaddr_in raddr;
    memset(&raddr, 0, sizeof(struct sockaddr_in));

    char buff[BUFFERSIZE];
    while (1) {
        int size = router_receive(router, buff, BUFFERSIZE);

        // char saddr[INET_ADDRSTRLEN];
        // char daddr[INET_ADDRSTRLEN];
        // inet_ntop(AF_INET, &((struct iphdr *)buff)->saddr, saddr,
        //           INET_ADDRSTRLEN);
        // inet_ntop(AF_INET, &((struct iphdr *)buff)->daddr, daddr,
        //           INET_ADDRSTRLEN);

        // printf("Received from V %s %s %d bytes\n", saddr, daddr, size);

        write(_tunfd, buff, size);
    }
    return NULL;
}

void *send_thread(void *arg)
{
    struct router *router = (struct router *)arg;
    // TODO
    char buff[BUFFERSIZE];
    while (1) {
        int size = read(_tunfd, buff, BUFFERSIZE);
        router_send(router, buff, size);
    }

    return NULL;
}

void manager_sender_handler(void *args, struct task_info *task_info)
{
    struct tcpwrapper *tcpwrapper = (struct tcpwrapper *)args;

    struct vln_packet_header *spacket;
    switch (task_info->operation) {
    case INIT: {
        printf("Send INIT\n");
        spacket = (struct vln_packet_header *)task_info->args;
        if (send_wrap(tcpwrapper, (void *)spacket,
                      sizeof(struct vln_packet_header) +
                          ntohl(spacket->payload_length)) != 0) {
            printf("error send_wrap INIT\n");
        } else {
            printf("send_wrap INIT\n");
        }
        free(spacket);
        break;
    }
    case UPDATE: {
        spacket = (struct vln_packet_header *)task_info->args;
        if (send_wrap(tcpwrapper, (void *)task_info->args,
                      sizeof(struct vln_packet_header) +
                          ntohl(spacket->payload_length)) != 0) {
            printf("error send_wrap INIT\n");
        } else {
            printf("send_wrap INIT\n");
        }
        free(spacket);
        break;
    }
    default:
        printf("ERROR: Unknown Packet Type\n");
        break;
    }
}

void manager_worker()
{
    int sockfd;
    int server_port = _server_port_temp;
    char *tcp_server_addr = _server_addr;
    struct sockaddr_in server_addr;
    struct router *router;

    memset(&server_addr, 0, sizeof(server_addr));

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }
    inet_pton(AF_INET, tcp_server_addr, &server_addr.sin_addr.s_addr);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);

    if (connect(sockfd, (struct sockaddr *)&server_addr,
                sizeof(struct sockaddr)) == -1) {
        perror("connect");
        exit(1);
    }

    struct tcpwrapper *tcpwrapper =
        tcpwrapper_create(sockfd, 1024); // TODO error cheking

    struct taskexecutor *rlistener =
        taskexecutor_create((Handler)&router_listener, tcpwrapper);

    taskexecutor_start(rlistener);

    struct vln_packet_header *spacket =
        malloc(sizeof(struct vln_packet_header));

    spacket->type = INIT;
    spacket->payload_length = 0;

    struct vln_packet_header rpacket;
    while (1) {
        printf("recv\n");
        if (recv_wrap(tcpwrapper, (void *)&rpacket,
                      sizeof(struct vln_packet_header)) != 0) {
            break;
        }
        printf("Type: %d\n", rpacket.type);
        switch (rpacket.type) {
        case CONNECT: {
            printf("Receive CONNECT\n");

            // struct vln_connect_payload rpaylod;
            // if (recv_wrap(tcpwrapper, (void *)&rpaylod,
            //               sizeof(struct vln_connect_payload)))
            //     printf("error recv_wrap CONNECT_TO_SERVER \n");

            // // router_add_connection(rpaylod.con_type, rpaylod.vaddr,
            // //                       rpaylod.raddr, rpaylod.rport);
            break;
        }
        case INITR: {
            printf("Received INITR\n");
            struct vln_initr_payload rpayload;
            if (recv_wrap(tcpwrapper, (void *)&rpayload,
                          sizeof(struct vln_initr_payload)) != 0)
                printf("error recv_wrap INITR \n");
            if (add_vaddr_tunnel_interface(&rpayload) == -1) {
                dprintf(STDERR_FILENO,
                        "Adding payload in interface failed: %s\n ",
                        strerror(errno));
                exit(EXIT_FAILURE);
            }

            int router_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
            router = router_create(
                ntohl(rpayload.vaddr),
                ntohl(rpayload.vaddr) & ntohl(rpayload.maskaddr),
                ntohl(rpayload.broadaddr), router_sockfd, rlistener);

            pthread_t rt, st;
            pthread_create(&rt, NULL, recv_thread, (void *)router);
            pthread_create(&st, NULL, send_thread, (void *)router);

            break;
        }
        case ROOTNODE: {
            printf("Recived: ROOTNODE\n");
            struct vln_rootnode_payload rpayload;
            if (recv_wrap(tcpwrapper, (void *)&rpayload,
                          sizeof(struct vln_rootnode_payload)) != 0)
                printf("error recv_wrap ROOTNODE \n");

            printf("Root raddr: %u\n", ntohl(rpayload.raddr));
            printf("Root port: %u\n", ntohs(rpayload.rport));
            printf("Root vaddr: %u\n", ntohl(rpayload.vaddr));

            router_send_init(router, ntohl(rpayload.raddr),
                             ntohs(rpayload.rport));

            // router_add_connection(router, 0, ntohl(rpayload.vaddr),
            //                       ntohl(rpayload.raddr),
            //                       ntohs(rpayload.rport), 0, 1);

            break;
        }
        case UPDATE: {
            printf("Update Received\n");
            struct vln_update_payload rpayload;
            if (recv_wrap(tcpwrapper, (void *)&rpayload,
                          sizeof(struct vln_update_payload)) != 0) {
                // TODO
            }
            printf("Update %u %u %u %u %u\n", ntohl(rpayload.svaddr),
                   ntohl(rpayload.dvaddr), ntohl(rpayload.vaddr),
                   ntohl(rpayload.raddr), ntohs(rpayload.rport));

            router_update_routing_table(
                router, ntohl(rpayload.svaddr), ntohl(rpayload.vaddr),
                ntohl(rpayload.raddr), ntohs(rpayload.rport));

            break;
        }
        case UPDATEDIS: {
            printf("UPDATEDIS Received\n");
            struct vln_updatedis_payload rpayload;
            if (recv_wrap(tcpwrapper, (void *)&rpayload,
                          sizeof(struct vln_updatedis_payload)) != 0) {
                // TODO
            }
            router_remove_connection(router, ntohl(rpayload.vaddr));
            break;
        }
        default:
            printf("ERROR: Unknown Packet Type\n");
            break;
        }
    }
    tcpwrapper_destroy(tcpwrapper);
}

int main(int argc, char **argv)
{
    char adapter_name[IFNAMSIZ];
    strcpy(adapter_name, "testint1");

    _tunfd = create_adapter(adapter_name, IFF_TUN | IFF_NO_PI);

    manager_worker();

    pthread_exit(NULL);
    return 0;
}