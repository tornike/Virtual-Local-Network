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
#include "vlnadapter.h"

// TODO!!!!!!!
#define UPDATETABLE 700
#define BUFFERSIZE 4096

//===========GLOBALS===========
char *_server_addr = "34.65.27.69"; // Must be changed.
int _server_port_temp = 33507; // Must be changed.
struct tunnel_interface *_interfeace;
//===========GLOBALS===========

void router_listener(void *args, struct task_info *tinfo)
{
    struct tcpwrapper *server_con = (struct tcpwrapper *)args;
    // TODO;
    // check if its server die and if its p2p setup pyramid.
    printf("Peers Changed\n");
}

void *recv_thread(void *arg)
{
    struct router *router = (struct router *)arg;
    // TODO
    struct sockaddr_in raddr;
    memset(&raddr, 0, sizeof(struct sockaddr_in));

    struct router_buffer_slot *slot;
    while (1) {
        slot = router_receive(router);

        // void *buff = DATA_PACKET_PAYLOAD(slot->buffer);
        // char saddr[INET_ADDRSTRLEN];
        // char daddr[INET_ADDRSTRLEN];
        // inet_ntop(AF_INET, &((struct iphdr *)buff)->saddr, saddr,
        //           INET_ADDRSTRLEN);
        // inet_ntop(AF_INET, &((struct iphdr *)buff)->daddr, daddr,
        //           INET_ADDRSTRLEN);

        // printf("Received from V %s %s %d bytes\n", saddr, daddr,
        //        slot->used_size - sizeof(struct vln_data_packet_header));

        write(_interfeace->fd,
              slot->buffer + sizeof(struct vln_data_packet_header),
              slot->used_size - sizeof(struct vln_data_packet_header));

        router_add_free_slot(router, slot);
    }
    return NULL;
}

void *send_thread(void *arg)
{
    struct router *router = (struct router *)arg;
    // TODO
    struct router_buffer_slot *slot;
    while (1) {
        slot = router_get_free_slot(router);
        slot->used_size =
            read(_interfeace->fd,
                 slot->buffer + sizeof(struct vln_data_packet_header),
                 SLOT_SIZE - sizeof(struct vln_data_packet_header));
        slot->used_size += sizeof(struct vln_data_packet_header);
        ((struct vln_data_packet_header *)slot->buffer)->type = DATA;
        router_send(router, slot);
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
    case UPDATES: {
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

            if (tunnel_interface_set_network(rpayload.vaddr, rpayload.maskaddr,
                                             rpayload.broadaddr) == -1) {
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
        case UPDATES: {
            printf("Updates Received\n");
            struct vln_updates_payload rpayload;
            if (recv_wrap(tcpwrapper, (void *)&rpayload,
                          sizeof(struct vln_updates_payload)) != 0) {
                // TODO
            }
            printf("Update %u %u %u %u %u\n", ntohl(rpayload.svaddr),
                   ntohl(rpayload.dvaddr), ntohl(rpayload.vaddr),
                   ntohl(rpayload.raddr), ntohs(rpayload.rport));

            router_try_connection(router, ntohl(rpayload.vaddr),
                                  ntohl(rpayload.raddr), ntohs(rpayload.rport));

            router_setup_pyramid(router, ntohl(rpayload.vaddr));

            break;
        }
        case UPDATEDIS: {
            printf("UPDATEDIS Received\n");
            struct vln_updatedis_payload rpayload;
            if (recv_wrap(tcpwrapper, (void *)&rpayload,
                          sizeof(struct vln_updatedis_payload)) != 0) {
                // TODO
            }
            // router_remove_connection(router, ntohl(rpayload.vaddr));
            break;
        }
        default:
            printf("ERROR: Unknown Packet Type\n");
            break;
        }
    }
    tcpwrapper_destroy(tcpwrapper);
    // destroy router
    printf("client died\n");
}

int main(int argc, char **argv)
{
    _interfeace = tunnel_interface_create(IFF_TUN | IFF_NO_PI);

    if (_interfeace != NULL) {
        manager_worker();
    }

    pthread_exit(NULL);
    return 0;
}