#include <arpa/inet.h>
#include <assert.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "../lib/protocol.h"
#include "../lib/taskexecutor.h"
#include "../lib/tcpwrapper.h"
#include "../lib/uthash.h"
#include "../lib/utlist.h"
#include "../router.h"

#define BACKLOG 10

struct ipaddr {
    char addr[INET_ADDRSTRLEN];
    struct ipaddr *next;
    struct ipaddr *prev;
};

struct server_connection {
    uint32_t vaddr;
    uint32_t udp_addr;
    uint32_t udp_port;
    struct tcpwrapper *tcpwrapper;
    /*
        Maybe timers...
    */
    UT_hash_handle hh;
};

struct vln_network {
    uint32_t mask_address;
    uint32_t broadcast_address;
    uint32_t address;
    uint8_t network_bits;

    struct server_connection *connections;
    pthread_mutex_t connections_lock;

    struct router *router;
    uint32_t router_addr;
    uint16_t router_port;

    // id, name maybe and some data
};

//===========GLOBALS===========
uint32_t _serverip;
uint32_t _rserverip;
struct vln_network *_networks; // must be hash
//===========GLOBALS===========

void router_listener(void *args, struct task_info *tinfo)
{
    struct vln_network *net = (struct vln_network *)args;
    if (tinfo->operation == PEERCONNECTED) {
        struct router_action *act = (struct router_action *)tinfo->args;
        pthread_mutex_lock(&net->connections_lock);

        struct server_connection *curr_con;
        HASH_FIND_INT(net->connections, &act->vaddr, curr_con);
        curr_con->udp_addr = act->raddr; // Lock needed?
        curr_con->udp_port = act->rport;

        uint8_t spacket_to_curr[sizeof(struct vln_packet_header) +
                                sizeof(struct vln_update_payload)];
        struct vln_packet_header *stcheader =
            (struct vln_packet_header *)spacket_to_curr;
        struct vln_update_payload *stcpayload =
            (struct vln_update_payload *)PACKET_PAYLOAD(spacket_to_curr);
        stcheader->type = UPDATE;
        stcheader->payload_length = htonl(sizeof(struct vln_update_payload));
        stcpayload->svaddr = htonl(net->address);
        stcpayload->dvaddr = htonl(curr_con->vaddr);

        uint8_t spacket_to_others[sizeof(struct vln_packet_header) +
                                  sizeof(struct vln_update_payload)];
        struct vln_packet_header *stoheader =
            (struct vln_packet_header *)spacket_to_others;
        struct vln_update_payload *stopayload =
            (struct vln_update_payload *)PACKET_PAYLOAD(spacket_to_others);
        stoheader->type = UPDATE;
        stoheader->payload_length = htonl(sizeof(struct vln_update_payload));
        stopayload->svaddr = htonl(net->address);
        stopayload->vaddr = htonl(act->vaddr);
        stopayload->raddr = htonl(act->raddr);
        stopayload->rport = htons(act->rport);

        struct server_connection *elem;
        for (elem = net->connections; elem != NULL;
             elem = (struct server_connection *)(elem->hh.next)) {
            if (elem->udp_addr != 0 && elem->udp_port != 0 &&
                elem != curr_con) {

                stopayload->dvaddr = htonl(elem->vaddr);
                if (send_wrap(elem->tcpwrapper, (void *)spacket_to_others,
                              sizeof(struct vln_packet_header) +
                                  sizeof(struct vln_update_payload)) != 0) {
                    printf("Update Send Failed\n");
                } else {
                    printf("Update Sent\n");
                }

                stcpayload->vaddr = htonl(elem->vaddr);
                stcpayload->raddr = htonl(elem->udp_addr);
                stcpayload->rport = htons(elem->udp_port);
                if (send_wrap(curr_con->tcpwrapper, (void *)spacket_to_curr,
                              sizeof(struct vln_packet_header) +
                                  sizeof(struct vln_update_payload)) != 0) {
                    printf("Update Send Failed\n");
                } else {
                    printf("Update Sent\n");
                }
            }
        }

        pthread_mutex_unlock(&net->connections_lock);

        // send update to all server_connections where raddr and rport != 0
        // send all server_connections to new connection
        free(act);
        free(tinfo);
    } else {
        printf("Unknown router_listener operation\n");
    }
}

uint32_t get_available_address(struct vln_network *net)
{
    struct server_connection *con;
    for (int i = net->address + 1; i < net->broadcast_address; i++) {
        HASH_FIND_INT(net->connections, &i, con);
        if (con == NULL) {
            return i;
        }
    }
    return 0;
}

// void manager_sender_handler(void *args, struct task_info *task_info)
// {
//     struct tcpwrapper *tcpwrapper = (struct tcpwrapper *)args;

//     struct vln_packet_header *spacket;
//     switch (task_info->operation) {
//     case INIT: {
//         printf("Send INIT\n");
//         spacket = (struct vln_packet_header *)task_info->args;
//         if (send_wrap(tcpwrapper, (void *)spacket,
//                       sizeof(struct vln_packet_header) +
//                           ntohl(spacket->payload_length)) != 0) {
//             printf("BOLOMDE VER GAIGZAVNA\n");
//         } else {
//             printf("INITR Sent\n");
//         }
//         free(spacket);
//         break;
//     }
//     case ROOTNODES: {
//         printf("Send Root INIT\n");
//         spacket = (struct vln_packet_header *)task_info->args;
//         if (send_wrap(tcpwrapper, (void *)spacket,
//                       sizeof(struct vln_packet_header) +
//                           ntohl(spacket->payload_length)) != 0) {
//             printf("BOLOMDE VER GAIGZAVNA\n");
//         } else {
//             printf("INITR Sent\n");
//         }
//         free(spacket);
//         break;
//     }
//     case UPDATE: {
//         printf("Send UPDATE\n");
//         spacket = (struct vln_packet_header *)task_info->args;

//         struct vln_update_payload *update =
//             (struct vln_update_payload *)(PACKET_PAYLOAD(spacket) +
//                                           2 * sizeof(uint32_t));
//         uint32_t svaddr = ntohl(*(uint32_t *)(PACKET_PAYLOAD(spacket)));
//         uint32_t dvaddr =
//             ntohl(*(uint32_t *)(PACKET_PAYLOAD(spacket) + sizeof(uint32_t)));

//         struct server_connection *pcon;

//         if (dvaddr == 0) {
//             printf("Send UPDATE  0\n");
//             pthread_mutex_lock(&_connectionsm);
//             for (pcon = _server_connections; pcon != NULL;
//                  pcon = (struct server_connection *)(pcon->hh.next)) {
//                 if (!(pcon->vaddr == svaddr ||
//                       pcon->vaddr == ntohl(update->vaddr))) {
//                     if (send_wrap(pcon->tcpwrapper, (void *)spacket,
//                                   sizeof(struct vln_packet_header) +
//                                       ntohl(spacket->payload_length)) != 0) {
//                         printf("BOLOMDE VER GAIGZAVNA\n");
//                     } else {
//                         printf("INITR Sent\n");
//                     }
//                 }
//             }
//             pthread_mutex_unlock(&_connectionsm);

//         } else {
//             printf("Send UPDATE  1\n");
//             pthread_mutex_lock(&_connectionsm);
//             HASH_FIND_INT(_server_connections, &dvaddr, pcon);

//             // TODO if pcon is null
//             if (pcon != NULL) {

//                 if (send_wrap(pcon->tcpwrapper, (void *)task_info->args,
//                               sizeof(struct vln_packet_header) +
//                                   ntohl(spacket->payload_length)) != 0) {
//                     printf("BOLOMDE VER GAIGZAVNA\n");
//                 } else {
//                     printf("INITR Sent\n");
//                 }
//             }
//             pthread_mutex_unlock(&_connectionsm);
//         }
//         free(spacket);

//         break;
//     }

//     default:
//         printf("ERROR: Unknown Packet Type\n");
//         break;
//     }
// }

void *manager_sender_worker(void *arg)
{
    taskexecutor_start((struct taskexecutor *)arg);

    return NULL;
}

// TODO: error handling.
void *manager_worker(void *arg)
{
    int sockfd = *(int *)arg;

    struct tcpwrapper *tcpwrapper = tcpwrapper_create(sockfd, 1024);

    socklen_t c_addr_size = sizeof(struct sockaddr_in);

    //===========ZEDMET=============
    struct sockaddr_in c_addr;
    getpeername(sockfd, (struct sockaddr *)&c_addr, &c_addr_size);

    char adddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &c_addr.sin_addr, adddr, c_addr_size);
    printf("Client %s Connected\n", adddr);
    //==============================

    //===============AUTHENTIFICATION============
    // IF good assign address and go.
    //===============AUTHENTIFICATION============

    struct vln_network *curr_net = _networks; // find authorized network;
    struct server_connection *scon = malloc(sizeof(struct server_connection));
    scon->tcpwrapper = tcpwrapper;

    pthread_mutex_lock(&curr_net->connections_lock);
    scon->vaddr = get_available_address(curr_net); // TODO: no more address.
    HASH_ADD_INT(curr_net->connections, vaddr, scon);
    pthread_mutex_unlock(&curr_net->connections_lock);

    //==============SEND INTITR===============
    do {
        uint8_t spacket[sizeof(struct vln_packet_header) +
                        sizeof(struct vln_initr_payload)];
        struct vln_packet_header *sheader = (struct vln_packet_header *)spacket;
        struct vln_initr_payload *spayload =
            (struct vln_initr_payload *)PACKET_PAYLOAD(spacket);
        sheader->type = INITR;
        sheader->payload_length = htonl(sizeof(struct vln_initr_payload));
        spayload->vaddr = htonl(scon->vaddr);
        spayload->maskaddr = htonl(curr_net->mask_address);
        spayload->broadaddr = htonl(curr_net->broadcast_address);

        if (send_wrap(tcpwrapper, (void *)spacket, sizeof(spacket)) != 0) {
            printf("Send Failed\n");
        } else {
            printf("INITR Sent\n");
        }
    } while (0);
    //========================================

    //==============SEND ROOTNODE===============
    do {
        uint8_t spacket[sizeof(struct vln_packet_header) +
                        sizeof(struct vln_rootnode_payload)];
        struct vln_packet_header *sheader = (struct vln_packet_header *)spacket;
        struct vln_rootnode_payload *spayload =
            (struct vln_rootnode_payload *)PACKET_PAYLOAD(spacket);
        sheader->type = ROOTNODE;
        sheader->payload_length = htonl(sizeof(struct vln_rootnode_payload));
        spayload->vaddr = 0; // ????
        spayload->raddr = htonl(curr_net->router_addr);
        spayload->rport = htons(curr_net->router_port);

        if (send_wrap(tcpwrapper, (void *)spacket, sizeof(spacket)) != 0) {
            printf("Send Failed\n");
        } else {
            printf("ROOTNODE Sent\n");
        }
    } while (0);
    //========================================

    struct vln_packet_header rpacket;
    while (1) {
        if (recv_wrap(scon->tcpwrapper, (void *)&rpacket,
                      sizeof(struct vln_packet_header)) != 0) {
            printf("Connection Lost\n");
            break;
        }
        switch (rpacket.type) {
        case INIT: {
            assert(rpacket.payload_length == 0);
            printf("INIT RECVED: ar unda miego\n");

            break;
        }
        case UPDATE: {
            printf("UPDATE: ar unda miego\n");
            uint8_t rpayload[ntohl(rpacket.payload_length)];
            if (recv_wrap(scon->tcpwrapper, (void *)rpayload,
                          ntohl(rpacket.payload_length)))
                printf("UPDATE error recv_wrap CONNECT_TO_SERVER \n");
            uint8_t *spacket = malloc(sizeof(struct vln_packet_header) +
                                      ntohl(rpacket.payload_length));
            memcpy(spacket, &rpacket, sizeof(struct vln_packet_header));
            memcpy(PACKET_PAYLOAD(spacket), rpayload,
                   ntohl(rpacket.payload_length));
            // task_info = malloc(sizeof(struct task_info));
            // task_info->args = spacket;
            // task_info->operation = UPDATE;

            // taskexecutor_add_task(taskexecutor, task_info);
            break;
        }
        default:
            printf("ERROR: Unknown Packet Type\n");
            return NULL;
        }
    }
    tcpwrapper_destroy(scon->tcpwrapper);

    return NULL;
}

void recv_connections(int port)
{
    int sfd, cfd;
    struct sockaddr_in s_addr, c_addr;
    socklen_t sockaddr_in_size = sizeof(struct sockaddr_in);

    sfd = socket(AF_INET, SOCK_STREAM, 0); // TODO: error handling.

    int optval = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(port);
    s_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    bind(sfd, (struct sockaddr *)&s_addr,
         sizeof(struct sockaddr_in)); // TODO: error handling.
    listen(sfd, BACKLOG); // TODO: error handling.

    while (1) {
        cfd = accept(sfd, (struct sockaddr *)&c_addr,
                     &sockaddr_in_size); // TODO: error handling.

        pthread_t t;
        pthread_create(&t, NULL, manager_worker, (void *)cfd);
    }
}

int init(char *network_addr, char *network_bits)
{
    char *rip = "34.65.70.129";
    // TODO
    inet_pton(AF_INET, rip, &_rserverip);
    _rserverip = ntohl(_rserverip);

    // char server_addr[INET_ADDRSTRLEN];
    // // uint32_t network_addrb = htobe32(network_addr_int);
    // inet_ntop(AF_INET, &_network_address, server_addr, INET_ADDRSTRLEN);
    // printf("SERVER ADDR: %s %d\n", server_addr, htonl(_network_address +
    // 1)); pthread_mutex_init(&_connectionsm, NULL); printf("Router
    // Initialized!\n");

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("Invalid Arguments!\n");
        return EXIT_FAILURE;
    }

    init(argv[1], argv[2]);

    //=================Create Network================
    struct vln_network *new_net = malloc(sizeof(struct vln_network));
    inet_pton(AF_INET, argv[1], &new_net->address);
    new_net->address = ntohl(new_net->address);
    new_net->network_bits = atoi(argv[2]);
    new_net->broadcast_address =
        new_net->address + (uint32_t)pow(2, 32 - new_net->network_bits) - 1;
    new_net->mask_address = ((uint32_t)pow(2, new_net->network_bits) - 1)
                            << (32 - new_net->network_bits);

    new_net->connections = NULL;
    pthread_mutex_init(&new_net->connections_lock, NULL);

    socklen_t socklen = sizeof(struct sockaddr_in);
    struct sockaddr_in udp_addr;
    memset(&udp_addr, 0, socklen);
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    udp_addr.sin_port = 0;

    int router_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(router_sockfd, (struct sockaddr *)&udp_addr,
         sizeof(struct sockaddr_in));
    getsockname(router_sockfd, (struct sockaddr *)&udp_addr, &socklen);

    struct taskexecutor *rlistener =
        taskexecutor_create((Handler)&router_listener, new_net);

    pthread_t sm;
    pthread_create(&sm, NULL, manager_sender_worker,
                   rlistener); // executorshic wava mgoni

    new_net->router_addr = _serverip;
    new_net->router_addr = ntohs(udp_addr.sin_port);
    new_net->router =
        router_create(new_net->address, new_net->address,
                      new_net->broadcast_address, router_sockfd, rlistener);
    //=================Create Network================

    _networks = new_net;

    recv_connections(33507);

    return 0;
}