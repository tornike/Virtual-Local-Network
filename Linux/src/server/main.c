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
    int sockfd;
    /*
        Maybe timers...
    */
    UT_hash_handle hh;
};

uint32_t _network_mask_address;
uint32_t _broadcast_address;
uint32_t _network_address;
uint8_t _network_bits;

// TODO
struct router *_router;

struct server_connection *_server_connections;
int _server_connections_count;
pthread_mutex_t _connectionsm;

uint32_t _serverip;
uint32_t _rserverip;

uint32_t get_available_address()
{
    struct server_connection *con;
    for (int i = _network_address + 2; i < _broadcast_address; i++) {
        HASH_FIND_INT(_server_connections, &i, con);
        if (con == NULL) {
            return i;
        }
    }
    return 0;
}

void manager_sender_handler(void *args, struct task_info *task_info)
{
    struct tcpwrapper *tcpwrapper = (struct tcpwrapper *)args;

    struct vln_packet_header *spacket;
    switch (task_info->operation) {
    case INIT: {
        printf("Send INIT\n");
        spacket = (struct vln_packet_header *)task_info->args;
        if (send_wrap(tcpwrapper, (void *)task_info->args,
                      sizeof(struct vln_packet_header) +
                          ntohl(spacket->payload_length)) != 0) {
            printf("BOLOMDE VER GAIGZAVNA\n");
        } else {
            printf("INITR Sent\n");
        }
        free(spacket);
        break;
    }
    case ROOTNODES: {
        printf("Send Root INIT\n");
        spacket = (struct vln_packet_header *)task_info->args;
        if (send_wrap(tcpwrapper, (void *)task_info->args,
                      sizeof(struct vln_packet_header) +
                          ntohl(spacket->payload_length)) != 0) {
            printf("BOLOMDE VER GAIGZAVNA\n");
        } else {
            printf("INITR Sent\n");
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

// TODO: error handling.
void *manager_worker(void *arg)
{
    struct server_connection *scon = (struct server_connection *)arg;
    socklen_t c_addr_size = sizeof(struct sockaddr_in);

    struct sockaddr_in c_addr;
    getpeername(scon->sockfd, (struct sockaddr *)&c_addr, &c_addr_size);

    char adddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &c_addr.sin_addr, adddr, c_addr_size);
    printf("Client %s Connected\n", adddr);

    // get virtual address, send hosts.

    struct tcpwrapper *tcpwrapper = tcpwrapper_create(scon->sockfd, 1024);

    struct taskexecutor *taskexecutor =
        taskexecutor_create((Handler)&manager_sender_handler, tcpwrapper);

    pthread_t sm;
    pthread_create(&sm, NULL, manager_sender_worker, taskexecutor);

    // get available adres
    _router = router_create(_network_address + 1, _network_address,
                            _broadcast_address, taskexecutor);

    struct vln_packet_header rpacket;

    struct task_info *task_info;
    // struct task_info *task_info = malloc(sizeof(struct task_info));
    // task_info->operation = INIT;
    // task_info->args = spacket;

    // taskexecutor_add_task(taskexecutor, task_info);

    while (1) {

        if (recv_wrap(tcpwrapper, (void *)&rpacket,
                      sizeof(struct vln_packet_header)) != 0) {
            printf("Connection Lost\n");
            break;
        }

        switch (rpacket.type) {
        case INIT: {
            assert(rpacket.payload_length == 0);
            printf("INIT RECVED\n");

            if (scon->vaddr == 0) {
                pthread_mutex_lock(&_connectionsm);
                scon->vaddr = get_available_address(); // TODO: empty list or
                                                       // already assigned.
                if (scon->vaddr == 0) {
                    pthread_mutex_unlock(&_connectionsm);
                    printf("ERROR: goto EndWhile\n");
                    goto EndWhile;
                    // TODO
                    // die die die die die worker
                }
                HASH_ADD_INT(_server_connections, vaddr, scon);
                _server_connections_count++;
                pthread_mutex_unlock(&_connectionsm);
            } else {
                printf("ERROR: Address already assigned\n");
                // TODO: ERROR: Already assigned.
            }

            uint8_t *spacket = malloc(sizeof(struct vln_packet_header) +
                                      sizeof(struct vln_initr_payload));
            struct vln_packet_header *sheader =
                (struct vln_packet_header *)spacket;
            struct vln_initr_payload *spayload =
                (struct vln_initr_payload *)PACKET_PAYLOAD(spacket);
            sheader->type = INITR;
            sheader->payload_length = htonl(sizeof(struct vln_initr_payload));
            spayload->vaddr = htonl(scon->vaddr);
            spayload->maskaddr = htonl(_network_mask_address);
            spayload->broadaddr = htonl(_broadcast_address);

            task_info = malloc(sizeof(struct task_info));
            task_info->operation = INIT;
            task_info->args = spacket;

            taskexecutor_add_task(taskexecutor, task_info);
            // if (send_wrap(tcpwrapper, (void *)spacket, sizeof(spacket)) != 0)
            // {
            //     printf("BOLOMDE VER GAIGZAVNA\n");
            // } else {
            //     printf("INITR Sent\n");
            // }

            uint8_t *spacket_root =
                malloc(sizeof(struct vln_packet_header) +
                       sizeof(struct vln_connection_payload));

            sheader = (struct vln_packet_header *)spacket_root;
            struct vln_connection_payload *spayload_root =
                (struct vln_connection_payload *)PACKET_PAYLOAD(spacket_root);

            sheader->type = ROOTNODES;
            sheader->payload_length =
                htonl(sizeof(struct vln_connection_payload));

            uint32_t root_addr;
            uint16_t root_port;
            router_get_raddr(_router, &root_addr, &root_port);

            spayload_root->vaddr = htonl(_network_address + 1); // TODO
            spayload_root->raddr = htonl(_rserverip);
            spayload_root->port = htons(root_port);

            task_info = malloc(sizeof(struct task_info));
            task_info->operation = ROOTNODES;
            task_info->args = spacket_root;

            taskexecutor_add_task(taskexecutor, task_info);
            // if (send_wrap(tcpwrapper, (void *)spacket_root,
            //               sizeof(spacket_root)) != 0) {
            //     printf("BOLOMDE VER GAIGZAVNA\n");
            // } else {
            //     printf("ROOTNODES Sent\n");
            // }

            break;
        }
        default:
            printf("ERROR: Unknown Packet Type\n");
            return NULL;
        }
    }
EndWhile:;
    tcpwrapper_destroy(tcpwrapper);

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

        struct server_connection *scon =
            malloc(sizeof(struct server_connection));
        scon->sockfd = cfd;

        pthread_t t;
        pthread_create(&t, NULL, manager_worker, scon);
    }
}

int init(char *network_addr, char *network_bits)
{
    inet_pton(AF_INET, network_addr, &_network_address);
    _network_address = ntohl(_network_address);
    _network_bits = atoi(network_bits);
    _broadcast_address =
        _network_address + (uint32_t)pow(2, 32 - _network_bits) - 1;
    _network_mask_address = ((uint32_t)pow(2, _network_bits) - 1)
                            << (32 - _network_bits);

    char *rip = "34.65.70.129";
    // TODO
    inet_pton(AF_INET, rip, &_rserverip);
    _rserverip = ntohl(_rserverip);

    _server_connections = NULL;
    _server_connections_count = 0;

    printf("Address Count: %d\n", 32 % _network_bits);

    char server_addr[INET_ADDRSTRLEN];
    // uint32_t network_addrb = htobe32(network_addr_int);
    inet_ntop(AF_INET, &_network_address, server_addr, INET_ADDRSTRLEN);
    printf("SERVER ADDR: %s %d\n", server_addr, htonl(_network_address + 1));
    pthread_mutex_init(&_connectionsm, NULL);
    printf("Router Initialized!\n");

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        printf("Invalid Arguments!\n");
        return EXIT_FAILURE;
    }

    init(argv[1], argv[2]);

    recv_connections(33507);

    return 0;
}