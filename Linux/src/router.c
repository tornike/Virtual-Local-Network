#define _GNU_SOURCE

#include "router.h"
#include "connection.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>

#include <stdio.h>

#include "lib/protocol.h"

#define MAX_PACKETS 15
#define SLOT_SIZE 4096
#define MAX_EVENTS 10

struct buffer_slot {
    uint8_t buffer[SLOT_SIZE];
    size_t used_size;
};

struct buffer_cond {
    int read_idx;
    sem_t used_slots;
    struct buffer_slot slots[MAX_PACKETS]; /* Different cache lines */
    sem_t free_slots;
    int write_idx;
};

struct router {
    uint32_t vaddr;
    uint32_t network_addr;
    uint32_t broadcast_addr;
    size_t subnet_size;
    struct connection **routing_table;
    pthread_rwlock_t routing_table_lock;
    int sockfd;
    struct buffer_cond *recv_buffer;
    int epoll_fd;
    struct epoll_event event, events[MAX_EVENTS];
};

// static void send_init(struct connection *con)
// {
//     uint8_t spacket[sizeof(struct vln_data_packet_header) +
//                     sizeof(struct vln_data_init_payload)];
//     struct vln_data_packet_header *sheader =
//         (struct vln_data_packet_header *)spacket;
//     struct vln_data_init_payload *spayload =
//         (struct vln_data_init_payload *)DATA_PACKET_PAYLOAD(spacket);

//     sheader->type = INIT;
//     spayload->vaddr = client_vaddr;

//     struct sockaddr_in saddr;
//     saddr.sin_family = AF_INET;
//     saddr.sin_port = con->rport;
//     saddr.sin_addr.s_addr = con->raddr;
//     int sent = sendto(sockfd, spacket, sizeof(spacket), 0,
//                       (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
//     printf("init sent %d\n", sent);
// }

static void *recv_worker(void *arg)
{
    struct router *router = (struct router *)arg;

    socklen_t slen = sizeof(struct sockaddr_in);
    struct sockaddr_in raddr;

    memset(&raddr, 0, sizeof(struct sockaddr_in)); // arafers shveba ideashi.

    struct buffer_slot *slot;
    struct vln_data_packet_header *header;
    struct vln_data_init_payload *payload;
    while (1) {
        sem_wait(&router->recv_buffer->free_slots);
        slot = &router->recv_buffer->slots[router->recv_buffer->write_idx];

        slot->used_size = recvfrom(router->sockfd, slot->buffer, SLOT_SIZE, 0,
                                   (struct sockaddr *)&raddr, &slen);

        header = (struct vln_data_packet_header *)slot->buffer;
        payload = (struct vln_data_init_payload *)DATA_PACKET_PAYLOAD(header);

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &raddr.sin_addr, (void *)&ip, INET_ADDRSTRLEN);
        printf("Received from %s:%d %ld bytes\n", ip, raddr.sin_port,
               slot->used_size);

        if (header->type == DATA) {
            printf("Data Recvd!!!\n");
            router->recv_buffer->write_idx =
                (router->recv_buffer->write_idx + 1) % MAX_PACKETS;
            sem_post(&router->recv_buffer->used_slots);
        } else if (header->type == RETRANSMIT) {
            printf("Retransmit Recvd\n");
            router_transmit(router, slot->buffer, slot->used_size);
            sem_post(&router->recv_buffer->free_slots);
            continue;
        } else if (header->type == KEEPALIVE) {
            printf("KEEPALIVE Recvd\n");
            sem_post(&router->recv_buffer->free_slots);
            continue;
        } else if (header->type == INIT) {
            printf("Init Recvd\n");
            printf("Vaddr %ul\n", payload->vaddr);
            uint32_t vaddr_be = ntohl(payload->vaddr);
            int key = vaddr_be % router->subnet_size;

            pthread_rwlock_wrlock(&router->routing_table_lock);
            struct connection *con = router->routing_table[key];
            if (con->rport == 0)
                con->rport = raddr.sin_port;
            printf("RPORT %d SET FOR HOST %ul\n", raddr.sin_port,
                   payload->vaddr);
            pthread_rwlock_unlock(&router->routing_table_lock);
            sem_post(&router->recv_buffer->free_slots);
            continue;
        } else {
            printf("bad type\n");
        }
    }
    return NULL;
}

static void *keep_alive_worker(void *arg)
{
    struct router *router = (struct router *)arg;

    struct itimerspec iti;
    memset(&iti, 0, sizeof(struct itimerspec));
    iti.it_interval.tv_sec = 0;
    iti.it_value.tv_sec = 10;

    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;

    while (1) {
        int event_count =
            epoll_wait(router->epoll_fd, router->events, MAX_EVENTS, 30000);
        struct connection *con;
        for (int i = 0; i < event_count; i++) {
            con = (struct connection *)router->events[i].data.ptr;
            uint64_t timerexps;
            read(con->timerfds, &timerexps, sizeof(uint64_t));
            printf("Timer '%lu'\n", timerexps);

            struct vln_data_packet_header packet;
            packet.type = KEEPALIVE;

            saddr.sin_port = con->rport;
            saddr.sin_addr.s_addr = con->raddr;

            int sent = sendto(
                router->sockfd, &packet, sizeof(struct vln_data_packet_header),
                0, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

            printf("KEEPALIVE SENT %ul %d\n", con->raddr, con->rport);

            timerfd_settime(con->timerfds, 0, &iti, NULL);
        }
    }
    return NULL;
}

static void init_buffer_cond(struct buffer_cond **bc)
{
    *bc = malloc(sizeof(struct buffer_cond));
    sem_init(&(*bc)->free_slots, 0, MAX_PACKETS);
    sem_init(&(*bc)->used_slots, 0, 0);
    (*bc)->write_idx = 0;
    (*bc)->read_idx = 0;
}

struct router *router_create(uint32_t vaddr, uint32_t net_addr,
                             uint32_t broad_addr)
{
    struct router *router;
    if ((router = malloc(sizeof(struct router))) == NULL) {
        dprintf(STDERR_FILENO, "Router: Malloc Failed %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    };

    init_buffer_cond(&router->recv_buffer); // TODO

    router->subnet_size = broad_addr - net_addr - 1;

    if ((router->routing_table = malloc(sizeof(struct connection *) *
                                        router->subnet_size)) == NULL) {
        dprintf(STDERR_FILENO, "Router: Malloc Failed %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    memset(router->routing_table, (uint64_t)NULL,
           sizeof(struct connection *) * router->subnet_size);

    pthread_rwlock_init(&router->routing_table_lock, NULL);

    if ((router->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        dprintf(STDERR_FILENO, "Router: Socket Creation Failed %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if ((bind(router->sockfd, (struct sockaddr *)&addr,
              sizeof(struct sockaddr_in)) < 0)) {
        dprintf(STDERR_FILENO, "Router: Failed to Bind %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if ((router->epoll_fd = epoll_create1(0)) < 0) {
        dprintf(STDERR_FILENO,
                "Router: Failed to create epoll file descriptor %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    router->vaddr = vaddr;
    router->network_addr = net_addr;
    router->broadcast_addr = broad_addr;

    pthread_t kat, rt;
    pthread_create(&kat, NULL, keep_alive_worker, router);
    pthread_create(&rt, NULL, recv_worker, router);

    return router;
}

void router_destroy(struct router *router)
{
    // TODO
}

// int router_add_connection(vln_connection_type ctype, uint32_t vaddr,
//                           uint32_t raddr, uint16_t rport)
// {
//     struct connection *ncon = malloc(sizeof(struct connection *));
//     ncon->con_type = ctype;
//     ncon->raddr = raddr;
//     ncon->vaddr = vaddr;
//     ncon->rport = rport;
//     ncon->timerfdr = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
//     ncon->timerfds = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);

//     uint32_t bigen_vaddr = htobe32(ncon->vaddr);
//     printf("CON ADDD %u\n", bigen_vaddr);
//     int key = bigen_vaddr % 10;
//     pthread_rwlock_wrlock(&connections_lock);
//     connections[key] = ncon;
//     event.events = EPOLLIN;
//     event.data.ptr = ncon;
//     epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ncon->timerfds, &event);

//     if (connections[key]->con_type == P2P) {
//         struct itimerspec iti;
//         memset(&iti, 0, sizeof(struct itimerspec));
//         iti.it_interval.tv_sec = 0;
//         iti.it_value.tv_sec = 10;

//         timerfd_settime(ncon->timerfds, 0, &iti, NULL);
//     }

//     pthread_rwlock_unlock(&connections_lock);

//     char ip[INET_ADDRSTRLEN]; ////
//     inet_ntop(AF_INET, &vaddr, &ip, INET_ADDRSTRLEN); ///
//     printf("Added connection to IP: %s %u %d\n", ip, ncon->raddr,
//     ncon->rport);

//     if (ncon->rport != 0 && ncon->con_type == P2P)
//         send_init(ncon);

//     return 0;
// }

int router_remove_connection(uint32_t vaddr)
{
    // TODO

    // uint32_t bigen_vaddr = htobe32(vaddr);
    // pthread_rwlock_wrlock(&connections_lock);
    // // maybe timer destroy
    // // and removing from poll
    // free(connections[bigen_vaddr % 10]);
    // connections[bigen_vaddr % 10] = NULL;
    // pthread_rwlock_unlock(&connections_lock);
    // return 0;
}

int router_transmit(struct router *router, void *packet, size_t size)
{
    size_t ssize;
    int key;
    struct sockaddr_in saddr;
    uint32_t vaddr_be;
    struct itimerspec iti;

    void *packetd = ((struct vln_data_packet_header *)packet) + 1;
    void *packeth = ((struct vln_data_packet_header *)packet);

    vaddr_be = ntohl(((struct iphdr *)packetd)->daddr);

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;

    pthread_rwlock_rdlock(&router->routing_table);
    if (vaddr_be > router->network_addr && vaddr_be < router->broadcast_addr) {
        printf("TRANSMIT %u\n", vaddr_be);
        key = vaddr_be % router->subnet_size;
        if (router->routing_table[key] == NULL) {
            printf("CONNECTION IS NULL!!!\n");
            ssize = -1;
        } else {
            // need this??
            ((struct vln_data_packet_header *)packeth)->type =
                router->routing_table[key]->con_type == P2P ? DATA : RETRANSMIT;
            // need this??

            saddr.sin_port =
                htons(router->routing_table[key]->rport); // hton ??
            saddr.sin_addr.s_addr =
                htonl(router->routing_table[key]->raddr); // hton ??

            ssize =
                sendto(router->sockfd, packet,
                       size + sizeof(struct vln_data_packet_header), 0,
                       (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

            // Decomposition ???
            memset(&iti, 0, sizeof(struct itimerspec));
            iti.it_interval.tv_sec = 0;
            iti.it_value.tv_sec = 10;

            timerfd_settime(router->routing_table[key]->timerfds, 0, &iti,
                            NULL);
            // Decomposition ???
        }
    } else if (vaddr_be == router->broadcast_addr) {
        printf("BROADCAST %u\n", vaddr_be);
        // TODO
    } else {
        printf("OUT OF RANGE %u\n", vaddr_be);
        // WHAT TO DO???
    }

    pthread_rwlock_unlock(&router->routing_table);
    return ssize;
}

int router_receive(struct router *router, void *buffer, size_t size)
{
    sem_wait(&router->recv_buffer->used_slots);
    struct buffer_slot *slot =
        &router->recv_buffer->slots[router->recv_buffer->read_idx];

    size_t real_size =
        size > slot->used_size - sizeof(struct vln_data_packet_header) ?
            slot->used_size - sizeof(struct vln_data_packet_header) :
            size;

    memcpy(buffer, slot->buffer + sizeof(struct vln_data_packet_header),
           real_size);

    sem_post(&router->recv_buffer->free_slots);
    router->recv_buffer->read_idx =
        (router->recv_buffer->read_idx + 1) % MAX_PACKETS;

    return real_size;
}

int router_retransmit(void *packet)
{
    return 0;
}

void router_get_raddr(struct router *router, uint32_t *raddr, uint16_t *rport)
{
    *raddr = 0;
    *rport = 0;

    socklen_t addr_size = sizeof(struct sockaddr_in);
    struct sockaddr_in addr;
    getsockname(router->sockfd, (struct sockaddr *)&addr,
                &addr_size); // TODO error checking.

    *raddr = ntohl(addr.sin_addr.s_addr);
    *rport = ntohs(addr.sin_port);
}
