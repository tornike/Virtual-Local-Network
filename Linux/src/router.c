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
#include "lib/taskexecutor.h"
#include "lib/uthash.h"

#define MAX_PACKETS 15
#define SLOT_SIZE 4096
#define MAX_EVENTS 10

#define CONNECTIONSADDR(addr_port, addr) *(uint32_t *)&addr_port = addr
#define CONNECTIONGADDR(addr_port) *(uint32_t *)&addr_port
#define CONNECTIONSPORT(addr_port, port)                                       \
    *(uint16_t *)((uint32_t *)&addr_port + 1) = port
#define CONNECTIONGPORT(addr_port) *(uint16_t *)((uint32_t *)&addr_port + 1)

// TODO!!!!!!!
#define UPDATETABLE 700

struct vln_task_info_update_arg {
    uint32_t vaddr;
    uint8_t payload;
};

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
    struct taskexecutor *send_manager;
    struct connection *peers;
    pthread_mutex_t peers_lock;
};

void *prepear_update_packet_2(struct router *router, struct connection *new_con)
{
    uint8_t *spacket =
        malloc(sizeof(struct vln_packet_header) + 2 + sizeof(uint32_t) +
               sizeof(struct vln_update_payload));
    struct vln_packet_header *sheader = (struct vln_packet_header *)spacket;
    // *((uint32_t *)PACKET_PAYLOAD(spacket)) = htonl(new_con->vaddr);

    *(uint32_t *)PACKET_PAYLOAD(spacket) = htonl(router->vaddr);
    *((uint32_t *)PACKET_PAYLOAD(spacket) + 1) = 0;

    sheader->type = UPDATE;
    sheader->payload_length =
        htonl(sizeof(uint32_t) + 2 * sizeof(struct vln_update_payload));
    struct vln_update_payload *update = PACKET_PAYLOAD(spacket);
    update->raddr = CONNECTIONGADDR(new_con->addr_port);
    update->rport = CONNECTIONGPORT(new_con->addr_port);
    update->vaddr = htonl(new_con->vaddr);

    return spacket;
}

void *prepear_update_packet(struct router *router, uint32_t dvaddr)
{
    pthread_mutex_lock(&router->peers_lock);
    uint32_t count = HASH_COUNT(router->peers);
    uint8_t *spacket =
        malloc(sizeof(struct vln_packet_header) + 2 * sizeof(uint32_t) +
               count * sizeof(struct vln_update_payload));
    struct vln_packet_header *sheader = (struct vln_packet_header *)spacket;
    sheader->type = UPDATE;
    *(uint32_t *)PACKET_PAYLOAD(spacket) = htonl(router->vaddr);
    *((uint32_t *)PACKET_PAYLOAD(spacket) + 1) = htonl(dvaddr);
    struct vln_update_payload *update =
        PACKET_PAYLOAD(spacket) + sizeof(uint32_t);

    struct connection *s;
    uint32_t real_count = 0;
    for (s = router->peers; s != NULL; s = (struct connection *)(s->hh.next)) {
        if (s->active == 1) {
            update->raddr = CONNECTIONGADDR(s->addr_port);
            update->rport = CONNECTIONGPORT(s->addr_port);
            update->vaddr = s->vaddr;
            update = update + 1;
            real_count++;
        }
    }
    sheader->payload_length = htonl(
        2 * sizeof(uint32_t) + real_count * sizeof(struct vln_update_payload));
    pthread_mutex_unlock(&router->peers_lock);
    return spacket;
}

static void send_init(struct router *router, struct connection *con)
{
    uint8_t spacket[sizeof(struct vln_data_packet_header) +
                    sizeof(struct vln_data_init_payload)];
    struct vln_data_packet_header *sheader =
        (struct vln_data_packet_header *)spacket;
    struct vln_data_init_payload *spayload =
        (struct vln_data_init_payload *)DATA_PACKET_PAYLOAD(spacket);

    sheader->type = INIT;
    spayload->vaddr = htonl(router->vaddr);

    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = ntohs(CONNECTIONGPORT(con->addr_port));
    saddr.sin_addr.s_addr = ntohl(CONNECTIONGADDR(con->addr_port));
    int sent = sendto(router->sockfd, spacket, sizeof(spacket), 0,
                      (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));
    printf("Init sent %d\n", sent);
}

static void update_routing_table(struct router *router, uint32_t vaddr,
                                 struct connection *con)
{
    struct connection *cur_con;
    int key = vaddr % router->subnet_size;
    pthread_rwlock_wrlock(&router->routing_table_lock);
    cur_con = router->routing_table[key];
    if (cur_con == NULL || cur_con->value > con->value) {
        router->routing_table[key] = con;
    }
    pthread_rwlock_unlock(&router->routing_table_lock);
}

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
            payload =
                (struct vln_data_init_payload *)DATA_PACKET_PAYLOAD(header);
            printf("Router Vaddr %u \n", ntohl(payload->vaddr));
            printf("Router Rport %d SET FOR HOST %u\n", ntohs(raddr.sin_port),
                   ntohl(payload->vaddr));

            router_add_connection(router, 0, ntohl(payload->vaddr),
                                  ntohl(raddr.sin_addr.s_addr),
                                  ntohs(raddr.sin_port), 1, 0);

            uint64_t key = 0;
            CONNECTIONSADDR(key, ntohl(raddr.sin_addr.s_addr));
            CONNECTIONSPORT(key, ntohs(raddr.sin_port));
            struct connection *temp_con;
            pthread_mutex_lock(&router->peers_lock);
            HASH_FIND_UINT64_T(router->peers, &key, temp_con);
            pthread_mutex_unlock(&router->peers_lock);
            update_routing_table(router, temp_con->vaddr, temp_con);

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

            saddr.sin_port = htons(CONNECTIONGPORT(con->addr_port));
            saddr.sin_addr.s_addr = htonl(CONNECTIONGADDR(con->addr_port));

            int sent = sendto(
                router->sockfd, &packet, sizeof(struct vln_data_packet_header),
                0, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

            printf("KEEPALIVE SENT %u %d\n",
                   htonl(CONNECTIONGADDR(con->addr_port)),
                   htons(CONNECTIONGPORT(con->addr_port)));

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
                             uint32_t broad_addr,
                             struct taskexecutor *taskexecutor)
{
    struct router *router;
    if ((router = malloc(sizeof(struct router))) == NULL) {
        dprintf(STDERR_FILENO, "Router: Malloc Failed %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    };

    router->send_manager = taskexecutor;

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

    router->peers = NULL;
    pthread_mutex_init(&router->peers_lock, NULL);

    pthread_t kat, rt;
    pthread_create(&kat, NULL, keep_alive_worker, router);
    pthread_create(&rt, NULL, recv_worker, router);

    return router;
}

void router_destroy(struct router *router)
{
    // TODO
}

int router_add_connection(struct router *router, vln_connection_type ctype,
                          uint32_t vaddr, uint32_t raddr, uint16_t rport,
                          int isActive, int sendInit)
{
    struct connection *new_con = malloc(sizeof(struct connection));
    new_con->con_type = ctype;
    new_con->vaddr = vaddr;
    CONNECTIONSADDR(new_con->addr_port, raddr);
    CONNECTIONSPORT(new_con->addr_port, rport);
    new_con->active = isActive;
    new_con->timerfdr = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
    new_con->timerfds = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);

    router->event.events = EPOLLIN;
    router->event.data.ptr = new_con;
    epoll_ctl(router->epoll_fd, EPOLL_CTL_ADD, new_con->timerfds,
              &router->event);
    if (isActive == 1) {
        struct task_info *task_info = malloc(sizeof(struct task_info));
        task_info->args = prepear_update_packet(router, new_con->vaddr);
        task_info->operation = UPDATE;
        taskexecutor_add_task(router->send_manager, task_info);

        task_info = malloc(sizeof(struct task_info));
        task_info->args = prepear_update_packet_2(router, new_con);
        task_info->operation = UPDATE;
        taskexecutor_add_task(router->send_manager, task_info);
    }

    pthread_mutex_lock(&router->peers_lock);
    HASH_ADD_UINT64_T(router->peers, addr_port, new_con);
    pthread_mutex_unlock(&router->peers_lock);

    struct itimerspec iti;
    memset(&iti, 0, sizeof(struct itimerspec));
    iti.it_interval.tv_sec = 0;
    iti.it_value.tv_sec = 1;
    timerfd_settime(new_con->timerfds, 0, &iti, NULL);

    char ip[INET_ADDRSTRLEN]; //
    inet_ntop(AF_INET, &vaddr, &ip, INET_ADDRSTRLEN); //
    printf("Added connection to IP: %s %u %d\n", ip,
           CONNECTIONGADDR(new_con->addr_port),
           CONNECTIONGPORT(new_con->addr_port));

    if (sendInit == 1)
        send_init(router, new_con);

    return 0;
}

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
    return 0;
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

    pthread_rwlock_rdlock(&router->routing_table_lock);
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
                htons(CONNECTIONGPORT(router->routing_table[key])); // hton ??
            saddr.sin_addr.s_addr =
                htonl(CONNECTIONGADDR(router->routing_table[key])); // hton ??

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

    pthread_rwlock_unlock(&router->routing_table_lock);
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
