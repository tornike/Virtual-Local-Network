#define _GNU_SOURCE

#include <arpa/inet.h>
#include <assert.h>
#include <json-c/json.h>
#include <math.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "../lib/protocol.h"
#include "../lib/taskexecutor.h"
#include "../lib/tcpwrapper.h"
#include "../lib/uthash.h"
#include "../lib/utlist.h"
#include "../router.h"
#include "db.h"

#define BACKLOG 10

/* Prototypes */
int create_network(void *NotUsed, int argc, char **argv, char **azColName);

struct server_connection {
    uint32_t vaddr;
    uint32_t udp_addr;
    uint32_t udp_port;
    int sockfd;
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
    pthread_mutex_t connections_lock; // rwlock should be better.

    struct router *router;
    uint32_t router_addr;
    uint16_t router_port;
    char network_name[REQUEST_MAX_LENGTH];

    UT_hash_handle hh;

    // id, name maybe and some data
};

//===========GLOBALS===========
uint32_t _rserverip;
struct vln_network *_networks; // must be hash
pthread_rwlock_t _vln_network_lock;
sqlite3 *_db;
//===========GLOBALS===========

void router_listener(void *args, struct task_info *tinfo)
{
    struct vln_network *net = (struct vln_network *)args;
    if (tinfo->operation == PEERCONNECTED) {
        struct router_action *act = (struct router_action *)tinfo->args;
        pthread_mutex_lock(&net->connections_lock);

        struct server_connection *curr_con;
        HASH_FIND_INT(net->connections, &act->vaddr, curr_con);
        if (curr_con != NULL) {
            curr_con->udp_addr = act->raddr; // Lock needed?
            curr_con->udp_port = act->rport;

            uint8_t spacket_to_curr[sizeof(struct vln_packet_header) +
                                    sizeof(struct vln_updates_payload)];
            struct vln_packet_header *stcheader =
                (struct vln_packet_header *)spacket_to_curr;
            struct vln_updates_payload *stcpayload =
                (struct vln_updates_payload *)PACKET_PAYLOAD(spacket_to_curr);
            stcheader->type = UPDATES;
            stcheader->payload_length =
                htonl(sizeof(struct vln_updates_payload));
            stcpayload->svaddr = htonl(net->address);
            stcpayload->dvaddr = htonl(curr_con->vaddr);

            uint8_t spacket_to_others[sizeof(struct vln_packet_header) +
                                      sizeof(struct vln_updates_payload)];
            struct vln_packet_header *stoheader =
                (struct vln_packet_header *)spacket_to_others;
            struct vln_updates_payload *stopayload =
                (struct vln_updates_payload *)PACKET_PAYLOAD(spacket_to_others);
            stoheader->type = UPDATES;
            stoheader->payload_length =
                htonl(sizeof(struct vln_updates_payload));
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
                                      sizeof(struct vln_updates_payload)) !=
                        0) {
                        printf("Update Send Failed\n");
                    } else {
                        printf("Update Sent\n");
                    }

                    stcpayload->vaddr = htonl(elem->vaddr);
                    stcpayload->raddr = htonl(elem->udp_addr);
                    stcpayload->rport = htons(elem->udp_port);
                    if (send_wrap(curr_con->tcpwrapper, (void *)spacket_to_curr,
                                  sizeof(struct vln_packet_header) +
                                      sizeof(struct vln_updates_payload)) !=
                        0) {
                        printf("Update Send Failed\n");
                    } else {
                        printf("Update Sent\n");
                    }
                }
            }
        } else {
            printf("Con NUll in router listener\n");
        }
        pthread_mutex_unlock(&net->connections_lock);
        free(act);
    } else if (tinfo->operation == PEERDISCONNECTED) {
        struct router_action *act = (struct router_action *)tinfo->args;

        printf("PEERDISCONNECTED \n");

        pthread_mutex_lock(&net->connections_lock);

        struct server_connection *curr_con;
        HASH_FIND_INT(net->connections, &act->vaddr, curr_con);
        if (curr_con != NULL) {
            tcpwrapper_set_die_flag(curr_con->tcpwrapper);
        }
        // curr_con->vaddr = 0;  Seg Fault da gasaazrebelia
        pthread_mutex_unlock(&net->connections_lock);

        free(act);
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

void send_error(vln_packet_type type, struct tcpwrapper *tcpwrapper)
{
    uint8_t serror[sizeof(struct vln_packet_header) +
                   sizeof(struct vln_error_payload)];
    memset(serror, 0, sizeof(serror));
    struct vln_packet_header *sheader = (struct vln_packet_header *)serror;
    sheader->payload_length = htonl(sizeof(struct vln_error_payload));
    sheader->type = ERROR;
    struct vln_error_payload *spayload =
        (struct vln_error_payload *)PACKET_PAYLOAD(serror);
    spayload->type = type;

    if (send_wrap(tcpwrapper, (void *)serror, sizeof(serror)) != 0) {
        printf("error send_wrap %d\n", type);
    } else {
        printf("send_wrap %d\n", type);
    }
}

void *manager_worker(void *arg)
{
    struct tcpwrapper *tcpwrapper = (struct tcpwrapper *)arg;
    struct vln_network *curr_net;

    //===============AUTHENTIFICATION============
    // If good assign address and go.
    struct vln_packet_header rpacket;

    do {

        if (recv_wrap(tcpwrapper, (void *)&rpacket,
                      sizeof(struct vln_packet_header)) != 0) {
            printf("Connection Lost\n");
        }
        if (rpacket.type == CONNECT) {
            struct vln_connect_payload rpayload;
            if (recv_wrap(tcpwrapper, (void *)&rpayload,
                          ntohl(rpacket.payload_length)))
                printf("CONNECT error recv_wrap\n");
            char *name = network_is_exists(_db, rpayload.network_name,
                                           rpayload.network_password);
            if (name == NULL) {
                send_error(NAME_OR_PASSWOR, tcpwrapper);
                printf("name is null\n");
                return NULL;
            }
            pthread_rwlock_rdlock(&_vln_network_lock);
            HASH_FIND_STR(_networks, name, curr_net);
            pthread_rwlock_unlock(&_vln_network_lock);
            if (curr_net == NULL) { // TODO if network deletes not correct.
                send_error(NETWORK_NOT_EXISTS, tcpwrapper);
                printf("curr_net is null\n");
                return NULL;
            }
        } else if (rpacket.type == CREATE) {
            // DOTO
            struct vln_create_payload rpayload;
            if (recv_wrap(tcpwrapper, (void *)&rpayload,
                          ntohl(rpacket.payload_length)))
                printf("CONNECT error recv_wrap\n");
            if (insert_new_network(_db, rpayload.addres, rpayload.bit,
                                   rpayload.network_name,
                                   rpayload.network_password) == -1) {

                send_error(INSERT_ERROR, tcpwrapper);
                printf("INSERT error\n");
                return NULL;
            }
            char argv1[REQUEST_MAX_LENGTH];
            char argv2[REQUEST_MAX_LENGTH];
            char argv3[REQUEST_MAX_LENGTH];

            strcpy(argv1, rpayload.addres);
            strcpy(argv2, rpayload.bit);
            strcpy(argv3, rpayload.network_name);

            int argc = 4;
            char *argv[argc];
            argv[1] = argv1;
            argv[2] = argv2;
            argv[3] = argv3;
            create_network(NULL, argc, argv, NULL);
            pthread_rwlock_rdlock(&_vln_network_lock);
            HASH_FIND_STR(_networks, rpayload.network_name, curr_net);
            pthread_rwlock_unlock(&_vln_network_lock);
            if (curr_net == NULL) {

                send_error(NETWORK_NOT_EXISTS, tcpwrapper);
                printf("new_curr_net is null\n");
                return NULL;
            }

        } else {

            send_error(UNKNOWN_PACKET_TYPE, tcpwrapper);
            printf("ERROR: Unknown Packet Type %d\n", rpacket.type);
            return NULL;
        }
    } while (0);

    //===============AUTHENTIFICATION============

    struct server_connection *scon = malloc(sizeof(struct server_connection));
    // scon->sockfd = sockfd;
    scon->tcpwrapper = tcpwrapper;

    pthread_mutex_lock(&curr_net->connections_lock);
    scon->vaddr = get_available_address(curr_net); // TODO: no more address.
    if (scon->vaddr == 0) {
        send_error(SUBNET_IS_FULL, tcpwrapper);

        printf("Subnet is full \n");

        tcpwrapper_destroy(tcpwrapper);
        // close(sockfd);
        free(scon);
        pthread_mutex_unlock(&curr_net->connections_lock);

        return NULL;
    }
    HASH_ADD_INT(curr_net->connections, vaddr, scon);
    pthread_mutex_unlock(&curr_net->connections_lock);

    //==============SEND INIT===============
    do {
        uint8_t spacket[sizeof(struct vln_packet_header) +
                        sizeof(struct vln_init_payload)];
        struct vln_packet_header *sheader = (struct vln_packet_header *)spacket;
        struct vln_init_payload *spayload =
            (struct vln_init_payload *)PACKET_PAYLOAD(spacket);
        sheader->type = INIT;
        sheader->payload_length = htonl(sizeof(struct vln_init_payload));
        spayload->vaddr = htonl(scon->vaddr);
        spayload->maskaddr = htonl(curr_net->mask_address);
        spayload->broadaddr = htonl(curr_net->broadcast_address);

        if (send_wrap(tcpwrapper, (void *)spacket, sizeof(spacket)) != 0) {
            printf("Send Failed\n");
        } else {
            printf("INIT Sent\n");
        }
    } while (0);
    //==========================================

    //==============SEND ROOTNODE===============
    do {
        uint8_t spacket[sizeof(struct vln_packet_header) +
                        sizeof(struct vln_rootnode_payload)];
        struct vln_packet_header *sheader = (struct vln_packet_header *)spacket;
        struct vln_rootnode_payload *spayload =
            (struct vln_rootnode_payload *)PACKET_PAYLOAD(spacket);
        sheader->type = ROOTNODE;
        sheader->payload_length = htonl(sizeof(struct vln_rootnode_payload));
        spayload->vaddr = htonl(curr_net->address);
        spayload->raddr = htonl(curr_net->router_addr);
        spayload->rport = htons(curr_net->router_port);

        if (send_wrap(tcpwrapper, (void *)spacket, sizeof(spacket)) != 0) {
            printf("Send Failed\n");
        } else {
            printf("ROOTNODE Sent\n");
        }
    } while (0);
    //=========================================

    while (1) {
        if (recv_wrap(scon->tcpwrapper, (void *)&rpacket,
                      sizeof(struct vln_packet_header)) != 0) {
            printf("Connection Lost1\n");
            break;
        }
        if (rpacket.type == UPDATES) {
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
        } else {
            printf("ERROR: Unknown Packet Type\n");
            break;
        }
    }

    printf("removing connection\n");
    router_remove_connection(curr_net->router, scon->vaddr);

    pthread_mutex_lock(&curr_net->connections_lock);
    HASH_DEL(curr_net->connections, scon);
    pthread_mutex_unlock(&curr_net->connections_lock);

    //==============SEND PeerDisconnected===============
    do {
        uint8_t spacket[sizeof(struct vln_packet_header) +
                        sizeof(struct vln_updatedis_payload)];
        struct vln_packet_header *sheader = (struct vln_packet_header *)spacket;
        struct vln_updatedis_payload *spayload =
            (struct vln_updatedis_payload *)PACKET_PAYLOAD(spacket);
        sheader->type = UPDATEDIS;
        sheader->payload_length = htonl(sizeof(struct vln_updatedis_payload));
        spayload->vaddr = htonl(scon->vaddr);

        pthread_mutex_lock(&curr_net->connections_lock);
        struct server_connection *elem;
        for (elem = curr_net->connections; elem != NULL;
             elem = (struct server_connection *)(elem->hh.next)) {
            if (send_wrap(elem->tcpwrapper, (void *)spacket,
                          sizeof(struct vln_packet_header) +
                              sizeof(struct vln_updatedis_payload)) != 0) {
                printf("UPDATEDIS Send Failed\n");
            } else {
                printf("UPDATEDIS Sent\n");
            }
        }
        pthread_mutex_unlock(&curr_net->connections_lock);
    } while (0);
    //==========================================

    tcpwrapper_destroy(scon->tcpwrapper);
    free(scon);

    return NULL;
}

void recv_connections(int port) // TODO
{
    int sfd, cfd;
    struct sockaddr_in s_addr, c_addr;
    socklen_t sockaddr_in_size = sizeof(struct sockaddr_in);

    sfd = socket(AF_INET, SOCK_STREAM, 0);

    int optval = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(int));
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(port);
    s_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    bind(sfd, (struct sockaddr *)&s_addr, sizeof(struct sockaddr_in));
    listen(sfd, BACKLOG);

    while (1) {
        cfd = accept(sfd, (struct sockaddr *)&c_addr, &sockaddr_in_size);
        //===========ZEDMET=============
        socklen_t c_addr_size = sizeof(struct sockaddr_in);
        struct sockaddr_in c_addr;
        getpeername(sfd, (struct sockaddr *)&c_addr, &c_addr_size);

        char adddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &c_addr.sin_addr, adddr, c_addr_size);
        printf("Client %s Connected\n", adddr);
        //==============================
        struct tcpwrapper *tcpwrapper = tcpwrapper_create(cfd, 1024);
        pthread_t t;
        pthread_create(&t, NULL, manager_worker, (void *)tcpwrapper);
    }
}

int create_network(void *NotUsed, int argc, char **argv, char **azColName)
{
    printf("create_network \n");
    struct vln_network *new_net = malloc(sizeof(struct vln_network));
    inet_pton(AF_INET, argv[1],
              &new_net->address); // address 1 bits 2 id 0 name 3
    new_net->address = ntohl(new_net->address);
    new_net->network_bits = atoi(argv[2]);
    new_net->broadcast_address =
        new_net->address + (uint32_t)pow(2, 32 - new_net->network_bits) - 1;
    new_net->mask_address = ((uint32_t)pow(2, new_net->network_bits) - 1)
                            << (32 - new_net->network_bits);
    strcpy(new_net->network_name, argv[3]);

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
    taskexecutor_start(rlistener);

    new_net->router_addr = _rserverip;
    new_net->router_port = ntohs(udp_addr.sin_port);
    new_net->router =
        router_create(new_net->address, new_net->address,
                      new_net->broadcast_address, router_sockfd, rlistener);
    pthread_rwlock_wrlock(&_vln_network_lock);
    HASH_ADD_STR(_networks, network_name, new_net);
    pthread_rwlock_unlock(&_vln_network_lock);
    return 0;
}

int main(int argc, char **argv)
{
    FILE *fp;
    char buffer[1024];
    struct json_object *parsed_json;
    struct json_object *server_ip;
    struct json_object *server_port;

    fp = fopen("vln.config", "r");

    if (fp == NULL) {
        return -1;
    }
    fread(buffer, 1024, 1, fp);
    fclose(fp);

    parsed_json = json_tokener_parse(buffer);

    json_object_object_get_ex(parsed_json, "server_ip", &server_ip);
    json_object_object_get_ex(parsed_json, "server_port", &server_port);
    if (server_ip == NULL || server_port == NULL) {
        return -1;
    }

    inet_pton(AF_INET, (char *)json_object_get_string(server_ip), &_rserverip);
    _rserverip = ntohl(_rserverip);

    pthread_rwlock_init(&_vln_network_lock, NULL);
    _db = get_db();
    create_table(_db);

    select_all_network(_db, create_network);
    recv_connections(json_object_get_int(server_port));

    return 0;
}