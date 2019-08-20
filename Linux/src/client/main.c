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

char *_server_addr = "34.65.70.129"; // Must be changed.
int _server_port_temp = 33507; // Must be changed.
int _tunfd;

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

void *recv_thread(void *arg)
{
    // TODO
    // struct sockaddr_in raddr;
    // memset(&raddr, 0, sizeof(struct sockaddr_in));

    // while (1) {
    //     char buff[BUFFERSIZE];
    //     int size = router_receive(buff, BUFFERSIZE);

    //     char saddr[INET_ADDRSTRLEN];
    //     char daddr[INET_ADDRSTRLEN];
    //     inet_ntop(AF_INET, &((struct iphdr *)buff)->saddr, saddr,
    //               INET_ADDRSTRLEN);
    //     inet_ntop(AF_INET, &((struct iphdr *)buff)->daddr, daddr,
    //               INET_ADDRSTRLEN);

    //     printf("Received from V %s %s %d bytes\n", saddr, daddr, size);

    //     write(tunfd, buff, size);
    // }
}

void *send_thread(void *arg)
{
    // TODO
    // while (1) {
    //     char buff[BUFFERSIZE];
    //     int size = read(tunfd, buff + sizeof(struct vln_data_packet_header),
    //                     BUFFERSIZE - sizeof(struct vln_data_packet_header));
    //     router_transmit(buff, size);
    // }

    return NULL;
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

void manager_sender_handler(void *args, struct task_info *task_info)
{
    struct tcpwrapper *tcpwrapper = (struct tcpwrapper *)args;

    struct vln_packet_header *spacket;
    switch (task_info->operation) {
    case INIT: {
        printf("Send INIT\n");
        spacket = (struct vln_packet_header *)task_info->args;
        if (send_wrap(tcpwrapper, (void *)spacket,
                      sizeof(struct vln_packet_header)) != 0) {
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

void *manager_sender_worker(void *arg)
{
    taskexecutor_start((struct taskexecutor *)arg);
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

    struct taskexecutor *taskexecutor =
        taskexecutor_create((Handler)&manager_sender_handler, tcpwrapper);

    pthread_t sm;
    pthread_create(&sm, NULL, manager_sender_worker, taskexecutor);

    struct vln_packet_header *spacket =
        malloc(sizeof(struct vln_packet_header));
    struct vln_packet_header rpacket;

    spacket->type = INIT;
    spacket->payload_length = 0;

    struct task_info *task_info = malloc(sizeof(struct task_info));
    task_info->operation = INIT;
    task_info->args = spacket;

    taskexecutor_add_task(taskexecutor, task_info);

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

            struct vln_connect_payload rpaylod;
            if (recv_wrap(tcpwrapper, (void *)&rpaylod,
                          sizeof(struct vln_connect_payload)))
                printf("error recv_wrap CONNECT_TO_SERVER \n");

            // router_add_connection(rpaylod.con_type, rpaylod.vaddr,
            //                       rpaylod.raddr, rpaylod.rport);
            break;
        }
        case INITR: {
            printf("Receive INITR\n");
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

            router =
                router_create(ntohl(rpayload.vaddr),
                              ntohl(rpayload.vaddr) & ntohl(rpayload.broadaddr),
                              ntohl(rpayload.broadaddr), taskexecutor);
            break;
        }
        case ROOTNODES: {

            printf("Enter: ROOTNODES\n");
            struct vln_connection_payload rpayload;
            if (recv_wrap(tcpwrapper, (void *)&rpayload,
                          sizeof(struct vln_connection_payload)) != 0)
                printf("error recv_wrap INITR \n");
            printf("recive: ROOTNODES\n");

            printf("Root raddr: %u\n", ntohl(rpayload.raddr));
            printf("Root port: %u\n", ntohs(rpayload.port));
            printf("Root vaddr: %u\n", ntohs(rpayload.vaddr));

            router_add_connection(router, 0, ntohl(rpayload.vaddr),
                                  ntohl(rpayload.raddr), ntohs(rpayload.port),
                                  0, 1);

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

    // pthread_t rt, st;
    // pthread_create(&rt, NULL, recv_thread, NULL);
    // pthread_create(&st, NULL, send_thread, NULL);

    manager_worker();

    pthread_exit(NULL);
    return 0;
}