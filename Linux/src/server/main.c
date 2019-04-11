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
    char addr[15];
    struct connection_utelement *next;
    struct connection_utelement *prev;
};

struct ipaddr_utelement *available_addresses;

struct temp_worker_args {
    int cfd;
    struct sockaddr_in *c_addr;
};

int ips[2];
int ports[2];
int used;

void *worker(void *arg)
{
    struct sockaddr_in *c_addr = ((struct temp_worker_args *)arg)->c_addr;
    int cfd = ((struct temp_worker_args *)arg)->cfd;

    int ip = 0;
    inet_pton(AF_INET, available_addresses->addr, &ip);

    struct sockaddr_in uaddr;
    memset(&uaddr, 0, sizeof(struct sockaddr_in));
    uaddr.sin_family = AF_INET;
    uaddr.sin_port = used == 1 ? ports[1] : ports[0];
    uaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ufd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(ufd, (struct sockaddr *)&uaddr, sizeof(struct sockaddr_in));

    printf("Bound\n");

    uint8_t
        buff[sizeof(struct vln_packet_header) + sizeof(struct vln_addr_paylod)];
    ((struct vln_packet_header *)&buff)->type = ADDR;
    ((struct vln_addr_paylod *)(&buff + sizeof(struct vln_packet_header)))
        ->ip_addr = ip;
    ((struct vln_addr_paylod *)(&buff + sizeof(struct vln_packet_header)))
        ->port = used == 1 ? ports[1] : ports[0];

    if (used) {
        ips[1] = c_addr->sin_addr.s_addr;
    } else {
        ips[0] = c_addr->sin_addr.s_addr;
    }
    used = 1;

    int sent = send(cfd, &buff, sizeof(buff), 0);
    assert(sent == sizeof(buff));

    //-----------RETRANSMIT---------------
    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;

    struct sockaddr_in raddr;
    memset(&raddr, 0, sizeof(struct sockaddr_in));
    socklen_t rslen = sizeof(struct sockaddr_in);

    while (1) {
        char buff[1024];
        int size =
            recvfrom(ufd, buff, 1024, 0, (struct sockaddr *)&raddr, &rslen);
        //--------------------------------
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &raddr.sin_addr, ip, INET_ADDRSTRLEN);
        printf("Received from %s:%d %d bytes\n", ip, raddr.sin_port, size);
        //--------------------------------

        char v_saddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, (const void *)&((struct iphdr *)buff)->saddr,
                  v_saddr, INET_ADDRSTRLEN);

        char v_daddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, (const void *)&((struct iphdr *)buff)->daddr,
                  v_daddr, INET_ADDRSTRLEN);

        printf("Virtual Source addr %s\n", v_saddr);
        printf("Virtual Destionation addr %s\n", v_daddr);
        // if (strcmp(v_saddr, "10.1.1.1") == 0) {
        //     ips[0] = raddr.sin_addr.s_addr;
        //     ports[0] = raddr.sin_port;
        //     printf("10.1.1.1 Stored %d\n", raddr.sin_port);
        // } else if (strcmp(v_saddr, "10.1.1.2") == 0) {
        //     ips[1] = raddr.sin_addr.s_addr;
        //     ports[1] = raddr.sin_port;
        //     printf("10.1.1.2 Stored %d\n", raddr.sin_port);
        // }

        if (strcmp(v_daddr, "10.1.1.1") == 0) {
            saddr.sin_port = ports[0];
            saddr.sin_addr.s_addr = ips[0];
            int sent = sendto(ufd, buff, size, 0, (struct sockaddr *)&saddr,
                              sizeof(struct sockaddr_in));
            printf("Retransmitted1 %d bytes\n", sent);
        } else if (strcmp(v_daddr, "10.1.1.2") == 0) {
            saddr.sin_port = ports[1];
            saddr.sin_addr.s_addr = ips[1];
            int sent = sendto(ufd, buff, size, 0, (struct sockaddr *)&saddr,
                              sizeof(struct sockaddr_in));
            printf("Retransmitted2 %d bytes\n", sent);
        } else {
            printf("Some Packets Dropped\n");
        }
    }

    return NULL;
}

void recv_connections(int port)
{
    int sfd, cfd;
    struct sockaddr_in s_addr, c_addr;
    socklen_t sockaddr_in_size = sizeof(struct sockaddr_in);

    sfd = socket(AF_INET, SOCK_STREAM, 0);

    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(port);
    s_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    bind(sfd, (struct sockaddr *)&s_addr, sizeof(struct sockaddr_in));
    listen(sfd, BACKLOG);

    pthread_t t1;
    pthread_t t2;

    while (1) {
        cfd = accept(sfd, (struct sockaddr *)&c_addr, &sockaddr_in_size);

        struct temp_worker_args args;
        args.c_addr = &c_addr;
        args.cfd = cfd;

        if (used) {
            pthread_create(&t2, NULL, worker, &args);
        } else {
            pthread_create(&t1, NULL, worker, &args);
        }
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

    ports[0] = 51000;
    ports[1] = 51001;
    used = 0;
    return 0;
}

int main(int argc, char **argv)
{
    init();

    recv_connections(5000);

    return 0;
}