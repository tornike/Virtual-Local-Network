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

#include "../lib/protocol.h"
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

struct ipaddr *available_addresses;
pthread_mutex_t ipm;
struct server_connection *server_connections;
int server_connections_count;
pthread_mutex_t connectionsm;

uint32_t serverip;
uint32_t rserverip;

uint32_t get_available_address()
{
    uint32_t ip = 0;
    pthread_mutex_lock(&ipm);
    inet_pton(AF_INET, available_addresses->addr, &ip); // TODO
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
    socklen_t c_addr_size = sizeof(struct sockaddr_in);

    struct sockaddr_in c_addr;
    getpeername(scon->sockfd, (struct sockaddr *)&c_addr, &c_addr_size);

    char adddr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &c_addr.sin_addr, adddr, c_addr_size);
    printf("Client %s Connected\n", adddr);

    // get virtual address, send hosts.

    while (1) {
        uint8_t recv_buff[1024];
        int recvd = recv(scon->sockfd, &recv_buff, 1024, 0);
        if (recvd == 0) {
            printf("Connection Lost\n");
            return NULL; // TODO
        }

        struct vln_packet_header *rpacket =
            (struct vln_packet_header *)&recv_buff;
        switch (rpacket->type) {
        case INIT: {
            assert(rpacket->payload_length == 0);
            printf("INIT RECVED\n");

            if (scon->vaddr == 0) {
                scon->vaddr = get_available_address(); // TODO: empty list or
                                                       // already assigned.
                HASH_ADD_INT(server_connections, vaddr, scon);
                server_connections_count++;
            } else {
                printf("ERROR: Address already assigned\n");
                // TODO: ERROR: Already assigned.
            }

            uint8_t spacket[sizeof(struct vln_packet_header) +
                            sizeof(struct vln_initr_payload)];
            struct vln_packet_header *sheader =
                (struct vln_packet_header *)spacket;
            struct vln_initr_payload *spayload =
                (struct vln_initr_payload *)PACKET_PAYLOAD(spacket);
            sheader->type = INITR;
            sheader->payload_length = sizeof(struct vln_initr_payload);
            spayload->vaddr = scon->vaddr;
            spayload->vmaskaddr = 0;

            int sent = send(scon->sockfd, (void *)spacket, sizeof(spacket), 0);
            if (sent != sizeof(spacket)) {
                printf("BOLOMDE VER GAIGZAVNA\n");
            } else {
                printf("INITR Sent %d\n", sent);
            }
            break;
        }
        case HOSTS: {
            assert(rpacket->payload_length == 0);
            printf("HOSTS RECVED\n");

            pthread_mutex_lock(&connectionsm);

            int payload_size =
                server_connections_count * sizeof(struct vln_vaddr_payload);

            uint8_t spacket[sizeof(struct vln_packet_header) + payload_size];
            struct vln_packet_header *sheader =
                (struct vln_packet_header *)spacket;
            struct vln_vaddr_payload *vaddrs =
                (struct vln_vaddr_payload *)PACKET_PAYLOAD(spacket);
            sheader->type = HOSTSR;
            sheader->payload_length = payload_size;

            struct server_connection *server_con_elem;
            for (server_con_elem = server_connections; server_con_elem != NULL;
                 server_con_elem = server_con_elem->hh.next) {
                if (server_con_elem->vaddr == scon->vaddr) {
                    continue;
                }
                vaddrs->flags = 0;
                vaddrs->ip_addr = server_con_elem->vaddr;
                vaddrs++;
            }

            vaddrs->flags = VLN_SERVER | VLN_VIRTUALADDR;
            vaddrs->ip_addr = serverip;

            pthread_mutex_unlock(&connectionsm);

            int sent = send(scon->sockfd, (void *)spacket, sizeof(spacket), 0);
            if (sent != sizeof(spacket)) {
                printf("BOLOMDE VER GAIGZAVNA\n");
            } else {
                printf("HOSTSR SENT\n");
            }
            break;
        }
        case CONNECT: {
            assert(rpacket->payload_length ==
                   sizeof(struct vln_server_connect_payload));
            printf("CONNECT RECVED\n");

            struct vln_server_connect_payload *rpayload =
                (struct vln_server_connect_payload *)PACKET_PAYLOAD(rpacket);

            if (rpayload->vaddr == serverip) {
                printf("connect to server ip\n");
                router_add_connection(P2P, scon->vaddr, c_addr.sin_addr.s_addr,
                                      0);

                uint8_t spacket[sizeof(struct vln_packet_header) +
                                sizeof(struct vln_connect_payload)];
                struct vln_packet_header *sheader =
                    (struct vln_packet_header *)spacket;
                struct vln_connect_payload *spayload =
                    (struct vln_connect_payload *)PACKET_PAYLOAD(spacket);
                sheader->type = CONNECT;
                sheader->payload_length = sizeof(struct vln_connect_payload);

                spayload->con_type = P2P;
                spayload->vaddr = serverip;
                spayload->raddr = rserverip;
                spayload->rport = htons(33508);
                int sent = send(scon->sockfd, spacket,
                                sizeof(struct vln_packet_header) +
                                    sheader->payload_length,
                                0);
                break; // TODO
            }

            struct server_connection *pcon;

            // lock ???
            HASH_FIND_INT(server_connections, &rpayload->vaddr, pcon);
            // unlock ???
            // pcon sheidzleba waishalos gamoyenebisas, race
            // conditions gadawyveta unda.

            if (pcon == NULL) { // TODO error check.
                printf("NULLLLLLLLLLLLLLLLL\n");
                break;
            }

            // uint32_t raddr1;
            // uint16_t rport1;
            // uint32_t raddr2;
            // uint16_t rport2;
            // router_get_raddr(scon->vaddr, &raddr1, &rport1);
            // router_get_raddr(scon->vaddr, &raddr2, &rport2);
            // printf("INCONNECT %ud, %ud, %ud, %ud\n", raddr1, rport1, raddr2,
            //        rport2);

            uint8_t spacket[sizeof(struct vln_packet_header) +
                            sizeof(struct vln_connect_payload)];
            struct vln_packet_header *sheader =
                (struct vln_packet_header *)spacket;
            struct vln_connect_payload *spayload =
                (struct vln_connect_payload *)PACKET_PAYLOAD(spacket);
            sheader->type = CONNECT;
            sheader->payload_length = sizeof(struct vln_connect_payload);

            if (rpayload->con_type == PYRAMID) {
                spayload->con_type = PYRAMID;

                spayload->vaddr = scon->vaddr;
                spayload->raddr = rserverip;
                spayload->rport = htons(33508);

                int sent = send(pcon->sockfd, spacket,
                                sizeof(struct vln_packet_header) +
                                    sheader->payload_length,
                                0);

                spayload->vaddr = pcon->vaddr;
                // spayload->raddr = raddr2;
                // spayload->rport = rport2;

                sent = send(scon->sockfd, spacket,
                            sizeof(struct vln_packet_header) +
                                sheader->payload_length,
                            0);

                if (sent != sizeof(sizeof(struct vln_packet_header) +
                                   sheader->payload_length)) {
                    printf("BOLOMDE VER GAIGZAVNA\n");
                } else {
                    printf("Sent %d\n", sent);
                }
            } else {
                printf("ERROR: Unknown Connection Type\n");
            }
            break;
        }
        default:
            printf("ERROR: Unknown Packet Type\n");
            return NULL;
        }
    }

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
    char *rip = "34.65.70.129";
    inet_pton(AF_INET, rip, &rserverip);

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

    DL_APPEND(available_addresses, addr1);
    DL_APPEND(available_addresses, addr2);
    DL_APPEND(available_addresses, addr3);

    int count = 0;
    struct ipaddr *tmp;
    DL_COUNT(available_addresses, tmp, count);
    printf("Address Count: %d\n", count);

    struct ipaddr *server_addr = available_addresses;
    inet_pton(AF_INET, server_addr->addr, &serverip);
    printf("SERVER ADDR: %s %d\n", server_addr->addr, serverip);
    DL_DELETE(available_addresses, available_addresses);

    pthread_mutex_init(&ipm, NULL);
    pthread_mutex_init(&connectionsm, NULL);

    return 0;
}

int main(int argc, char **argv)
{
    init();

    router_init(10);

    printf("Router Initialized!\n");

    recv_connections(33507);

    return 0;
}