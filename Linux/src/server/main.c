#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "../lib/list.h"
#include "../lib/protocol.h"
#include "../lib/uthash.h"

#define BACKLOG 10

struct ipaddr {
    char addr[15];
    struct list_elem elem;
};

struct server_connection {
    uint32_t vaddr;
    int sockfd;
    /*
        Maybe timers...
    */
    UT_hash_handle hh;
};

struct list_elem *available_addresses;
struct server_connection *server_connections;
int server_connections_count;

pthread_mutex_t connectionsm;
pthread_mutex_t ipm;

uint32_t serverip;
int serverudpfd;

uint32_t get_available_address()
{
    uint32_t ip = 0;
    pthread_mutex_lock(&ipm);
    inet_pton(AF_INET,
              list_entry(available_addresses, struct ipaddr, elem)->addr,
              &ip); // TODO
    DL_DELETE(available_addresses, available_addresses);
    pthread_mutex_unlock(&ipm);
    return ip;
}

void add_available_address(uint32_t ip)
{
    // TODO
    // uint32_t ip = 0;
    // inet_pton(AF_INET, available_addresses->addr, &ip); // TODO
    // DL_DELETE(available_addresses, available_addresses);
}

// TODO: error handling.
void *worker(void *arg)
{
    struct server_connection *scon = (struct server_connection *)arg;

    struct sockaddr_in c_addr;
    socklen_t c_addr_size = sizeof(struct sockaddr_in);
    getpeername(scon->sockfd, (struct sockaddr *)&c_addr, &c_addr_size);

    char adddr[15];
    inet_ntop(AF_INET, &c_addr.sin_addr, adddr, c_addr_size);
    printf("Client Addr recvd %s\n", adddr);

    while (1) {
        uint8_t recv_buff[1024];
        int recvd = recv(scon->sockfd, &recv_buff, 1024, 0);
        if (recvd == 0) {
            printf("Connection Lost\n");
            return NULL; // TODO
        }

        struct vln_packet_header *p = (struct vln_packet_header *)&recv_buff;
        if (p->type == INIT) {
            printf("INIT RECVED\n");

            if (scon->vaddr == 0) {
                scon->vaddr = get_available_address(); // TODO: empty list and
                                                       // already assigned.
                HASH_ADD_INT(server_connections, vaddr, scon);
                server_connections++;
            } else {
                printf("ERROR: Address already assigned\n");
                // ERROR: Already assigned.
            }

            uint8_t packet[sizeof(struct vln_packet_header) + sizeof(uint32_t)];
            struct vln_packet_header *header =
                (struct vln_packet_header *)packet;
            header->type = INITR;
            header->payload_length = sizeof(uint32_t);
            uint32_t *payload =
                (uint32_t *)(packet + sizeof(struct vln_packet_header));
            *payload = scon->vaddr;

            int sent = send(scon->sockfd, (void *)packet, sizeof(packet), 0);
            if (sent != sizeof(packet)) {
                printf("BOLOMDE VER GAIGZAVNA\n");
            } else {
                printf("INITR Sent %d\n", sent);
            }
        } else if (p->type == HOSTS) {

            pthread_mutex_lock(&connectionsm);

            int payload_size =
                server_connections_count * sizeof(struct vln_vaddr_payload);
            uint8_t buff[payload_size + sizeof(struct vln_packet_header)];
            struct vln_packet_header *header = (struct vln_packet_header *)buff;
            struct vln_vaddr_payload *vaddrs =
                (struct vln_vaddr_payload *)(buff +
                                             sizeof(struct vln_packet_header));

            header->type = HOSTSR;
            header->payload_length = payload_size;

            struct server_connection *server_con_elem;
            for (server_con_elem = server_connections; server_con_elem != NULL;
                 server_con_elem = server_con_elem->hh.next) {
                vaddrs->flags = vaddrs->ip_addr == serverip ?
                                    VLN_SERVER | VLN_VIRTUALADDR :
                                    0;
                vaddrs->ip_addr = server_con_elem->vaddr;
                printf("%u\n", vaddrs->ip_addr);
                vaddrs++;
            }
            pthread_mutex_unlock(&connectionsm);

            int sent = send(scon->sockfd, (void *)buff, sizeof(buff), 0);
            if (sent != sizeof(buff)) {
                printf("BOLOMDE VER GAIGZAVNA\n");
            } else {
                printf("Sent %d\n", sent);
            }
        } else if (p->type == CONNECT) {
            assert(p->payload_length == sizeof(struct vln_connect_payload));

            struct vln_connect_payload *payload =
                (struct vln_connect_payload *)(recv_buff +
                                               sizeof(
                                                   struct vln_packet_header));
            struct server_connection *pcon; // TODO error check.
            HASH_FIND_INT(server_connections, &payload->vaddr, pcon);

            if (payload->con_type == PYRAMID) {
                payload->vaddr = pcon->vaddr;
                int sent = send(
                    pcon->sockfd, recv_buff,
                    sizeof(struct vln_packet_header) + p->payload_length, 0);
                if (sent != sizeof(sizeof(struct vln_packet_header) +
                                   p->payload_length)) {
                    printf("BOLOMDE VER GAIGZAVNA\n");
                } else {
                    printf("Sent %d\n", sent);
                }
            } else if (p->type == CONNECT_ACK) {
                assert(p->payload_length == sizeof(struct vln_connect_payload));

                struct vln_connect_payload *payload =
                    (struct vln_connect_payload
                         *)(recv_buff + sizeof(struct vln_packet_header));
                if (serverudpfd == 0) {
                    serverudpfd = socket(AF_INET, SOCK_DGRAM, 0);

                    struct sockaddr_in addr;
                    addr.sin_family = AF_INET;
                    addr.sin_port = htons(33508);
                    addr.sin_addr.s_addr = htonl(INADDR_ANY);

                    bind(serverudpfd, (struct sockaddr *)&addr,
                         sizeof(struct sockaddr_in));
                }

                int payload_size = sizeof(struct vln_uaddr_payload);
                uint8_t buff[payload_size + sizeof(struct vln_packet_header)];
                struct vln_packet_header *header =
                    (struct vln_packet_header *)buff;
                struct vln_uaddr_payload *serverport =
                    (struct vln_uaddr_payload *)(buff +
                                                 sizeof(
                                                     struct vln_packet_header));

                header->payload_length = payload_size;
                header->type = CONNECT_TO_SERVER;

                serverport->port = htons(33508);

                struct server_connection *pcon; // TODO error check.
                HASH_FIND_INT(server_connections, &payload->vaddr, pcon);

                // TODO: add virtual addresses to connections and start
                // listening.

                send(pcon->sockfd, &buff, sizeof(buff), 0);
                send(scon->sockfd, &buff, sizeof(buff), 0);

            } else {
                printf("ERROR: Unknown Connection Type\n");
            }
        } else {
            printf("ERROR: Unknown Packet Type\n");
        }
    }

    // int ip = 0;
    // inet_pton(AF_INET, available_addresses->addr, &ip);
    // DL_DELETE(available_addresses, available_addresses);

    // struct sockaddr_in uaddr;
    // memset(&uaddr, 0, sizeof(struct sockaddr_in));
    // uaddr.sin_family = AF_INET;
    // uaddr.sin_port = 0;
    // uaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    // int ufd = socket(AF_INET, SOCK_DGRAM, 0);
    // bind(ufd, (struct sockaddr *)&uaddr, sizeof(struct sockaddr_in));
    // getsockname(ufd, (struct sockaddr *)&uaddr, &c_addr_size);

    // pthread_t udpt;
    // pthread_create(&udpt, NULL, keep_alive_worker, &ufd);

    // uint8_t buff[sizeof(struct vln_packet_header) +
    //              sizeof(struct vln_uaddr_paylod)];
    // ((struct vln_packet_header *)buff)->type = UADDR;
    // ((struct vln_packet_header *)buff)->payload_length =
    //     sizeof(struct vln_uaddr_paylod);
    // ((struct vln_uaddr_paylod *)(buff + sizeof(struct
    // vln_packet_header)))
    //     ->port = htons(uaddr.sin_port);
    // printf("PORT %d\n", htons(uaddr.sin_port));

    // int sent = send(sockfd, buff, sizeof(buff), 0);
    // printf("send: %d\n", sent);
    // assert(sent == sizeof(buff));

    // pthread_mutex_lock(&ipm);

    // uint32_t ip;
    // inet_pton(AF_INET, available_addresses->addr, &ip);
    // DL_DELETE(available_addresses, available_addresses);

    // uint8_t buff2[sizeof(struct vln_packet_header) +
    //               sizeof(struct vln_addr_paylod)];
    // ((struct vln_packet_header *)buff2)->type = ADDR;
    // ((struct vln_packet_header *)buff2)->payload_length =
    //     sizeof(struct vln_addr_paylod);
    // ((struct vln_addr_paylod *)(buff2 + sizeof(struct
    // vln_packet_header)))
    //     ->ip_addr = ip;

    // sent = send(sockfd, buff2, sizeof(buff2), 0);
    // printf("VADDR send: %d\n", sent);
    // assert(sent == sizeof(buff2));

    // while (1) {
    //     recv(sockfd, buf, sizeof(buf), 0);
    // }

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
        pthread_create(&t, NULL, worker, scon);
    }
}

int init()
{
    available_addresses = NULL;
    server_connections = NULL;
    server_connections_count = 0;

    struct ipaddr *addr1 = malloc(sizeof(struct ipaddr));
    struct ipaddr *addr2 = malloc(sizeof(struct ipaddr));
    struct ipaddr *addr3 = malloc(sizeof(struct ipaddr));
    memset(addr1, 0, sizeof(struct ipaddr));
    memset(addr2, 0, sizeof(struct ipaddr));
    memset(addr3, 0, sizeof(struct ipaddr));

    strcpy(addr1->addr, "10.1.1.1");
    strcpy(addr2->addr, "10.1.1.2");
    strcpy(addr3->addr, "10.1.1.3");

    DL_APPEND(available_addresses, &addr1->elem);
    DL_APPEND(available_addresses, &addr2->elem);
    DL_APPEND(available_addresses, &addr3->elem);

    int count = 0;
    struct list_elem *tmp;
    DL_COUNT(available_addresses, tmp, count);
    printf("Address Count: %d\n", count);

    struct ipaddr *server_addr =
        list_entry(available_addresses, struct ipaddr, elem);
    inet_pton(AF_INET, server_addr->addr, &serverip);
    printf("SERVER ADDR: %s %d\n", server_addr->addr, serverip);
    DL_DELETE(available_addresses, available_addresses);

    // DL_COUNT(available_addresses, tmp, count);
    // printf("Address Count: %d\n", count);

    serverudpfd = 0;
    pthread_mutex_init(&ipm, NULL);
    pthread_mutex_init(&connectionsm, NULL);

    return 0;
}

int main(int argc, char **argv)
{
    init();

    recv_connections(33507);

    return 0;
}