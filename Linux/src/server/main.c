#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "../lib/protocol.h"
#include "../lib/utlist.h"

#define BACKLOG 10

struct ipaddr_utelement {
    char addr[15];
    struct ipaddr_utelement *next;
    struct ipaddr_utelement *prev;
};

struct connection_utelement {
    pthread_t t;
    int ufd;
    int cfd;
    struct connection_utelement *next;
    struct connection_utelement *prev;
};

pthread_mutex_t ipm;

struct ipaddr_utelement *available_addresses;

struct temp_worker_args {
    int cfd;
    struct sockaddr_in *c_addr;
};

void *keep_alive_worker(void *arg)
{
    int sockfd = *(int *)arg;

    struct sockaddr_in recv_addr;

    socklen_t addr_size = sizeof(struct sockaddr_in);

    uint8_t buf[1024];
    int first = 1;
    while (1) {
        recvfrom(sockfd, &buf, 1024, 0, (struct sockaddr *)&recv_addr,
                 &addr_size);

        struct vln_packet_header *packet = (struct vln_packet_header *)buf;
        if (packet->type != KEEPALIVE) {
            printf("NOT UDPKEEPALIVE\n");
        } else {
            printf("KEEPALIVE\n");
            if (first) {
                pthread_mutex_unlock(&ipm);
                first = 0;
            }
        }
    }
}

// TODO: error handling.
void *worker(void *arg)
{
    struct sockaddr_in c_addr; // = ((struct temp_worker_args *)arg)->c_addr;
    int sockfd = ((struct connection_utelement *)arg)->cfd;

    socklen_t c_addr_size = sizeof(struct sockaddr_in);
    getpeername(sockfd, (struct sockaddr *)&c_addr, &c_addr_size);

    // int ip = 0;
    // inet_pton(AF_INET, available_addresses->addr, &ip);
    // DL_DELETE(available_addresses, available_addresses);

    struct sockaddr_in uaddr;
    memset(&uaddr, 0, sizeof(struct sockaddr_in));
    uaddr.sin_family = AF_INET;
    uaddr.sin_port = 0;
    uaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ufd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(ufd, (struct sockaddr *)&uaddr, sizeof(struct sockaddr_in));
    getsockname(ufd, (struct sockaddr *)&uaddr, &c_addr_size);

    printf("Bound\n");

    pthread_t udpt;
    pthread_create(&udpt, NULL, keep_alive_worker, &ufd);

    uint8_t buf[1024];
    recv(sockfd, &buf, 1024, 0); // waiting for INIT

    printf("RECVED\n");

    struct vln_packet_header *p = (struct vln_packet_header *)&buf;
    if (p->type != INIT) {
        printf("NOT INIT\n");
        exit(1);
    }

    uint8_t buff[sizeof(struct vln_packet_header) +
                 sizeof(struct vln_uaddr_paylod)];
    ((struct vln_packet_header *)buff)->type = UADDR;
    ((struct vln_packet_header *)buff)->payload_length =
        sizeof(struct vln_uaddr_paylod);
    ((struct vln_uaddr_paylod *)(buff + sizeof(struct vln_packet_header)))
        ->port = htons(uaddr.sin_port);
    printf("PORT %d\n", htons(uaddr.sin_port));

    int sent = send(sockfd, buff, sizeof(buff), 0);
    printf("send: %d\n", sent);
    assert(sent == sizeof(buff));

    pthread_mutex_lock(&ipm);

    uint32_t ip;
    inet_pton(AF_INET, available_addresses->addr, &ip);
    DL_DELETE(available_addresses, available_addresses);

    uint8_t buff2[sizeof(struct vln_packet_header) +
                  sizeof(struct vln_addr_paylod)];
    ((struct vln_packet_header *)buff2)->type = ADDR;
    ((struct vln_packet_header *)buff2)->payload_length =
        sizeof(struct vln_addr_paylod);
    ((struct vln_addr_paylod *)(buff2 + sizeof(struct vln_packet_header)))
        ->ip_addr = ip;

    sent = send(sockfd, buff2, sizeof(buff2), 0);
    printf("VADDR send: %d\n", sent);
    assert(sent == sizeof(buff2));

    while (1) {
        recv(sockfd, buf, sizeof(buf), 0);
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

        struct connection_utelement *con =
            malloc(sizeof(struct connection_utelement));

        con->cfd = cfd;

        pthread_create(&con->t, NULL, worker, con);
    }
}

int init()
{
    available_addresses = NULL;

    struct ipaddr_utelement *addr1 = malloc(sizeof(struct ipaddr_utelement));
    struct ipaddr_utelement *addr2 = malloc(sizeof(struct ipaddr_utelement));
    memset(addr1, 0, sizeof(struct ipaddr_utelement));
    memset(addr2, 0, sizeof(struct ipaddr_utelement));

    strcpy(addr1->addr, "10.1.1.1");
    strcpy(addr2->addr, "10.1.1.2");

    DL_APPEND(available_addresses, addr1);
    DL_APPEND(available_addresses, addr2);

    int count = 0;
    struct ipaddr_utelement *tmp;
    DL_COUNT(available_addresses, tmp, count);
    printf("Address Count: %d\n", count);

    // printf("ADDR: %s\n", available_addresses->addr);
    // DL_DELETE(available_addresses, available_addresses);

    // DL_COUNT(available_addresses, tmp, count);
    // printf("Address Count: %d\n", count);

    pthread_mutex_init(&ipm, NULL);

    return 0;
}

int main(int argc, char **argv)
{
    init();

    recv_connections(33507);

    return 0;
}