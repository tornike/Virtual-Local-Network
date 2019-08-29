#define _GNU_SOURCE

#include "router.h"
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

struct router_buffer_slot {
    uint8_t buffer[SLOT_SIZE];
    size_t used_size;
};

struct router_buffer {
    int read_idx;
    sem_t used_slots;
    struct router_buffer_slot slots[MAX_PACKETS]; /* Different cache lines */
    sem_t free_slots;
    int write_idx;
};

struct router_connection {
    uint32_t vaddr;
    uint64_t addr_port;
    int timerfds;
    int timerfdr;

    uint8_t active;
    uint8_t value;

    UT_hash_handle hh;
};

struct router {
    uint32_t vaddr;
    uint32_t network_addr;
    uint32_t broadcast_addr;
    size_t subnet_size;
    struct router_connection **routing_table;
    pthread_rwlock_t routing_table_lock;
    int sockfd;
    struct router_buffer *recv_buffer;
    struct router_buffer *send_buffer;
    int epoll_fd;
    struct epoll_event event, events[MAX_EVENTS];
    struct taskexecutor *peer_listener;
    struct router_connection *peers;
    pthread_mutex_t peers_lock;
};

static void init_router_buffer(struct router_buffer **);
static struct router_connection *
create_connection(uint32_t vaddr, uint32_t raddr, uint32_t rport);
static void set_timers(struct router *router, struct router_connection *con,
                       int send_tv, int recv_tv);
static void *keep_alive_worker(void *arg);
static void *recv_worker(void *arg);
static void *send_worker(void *arg);
static void update_routing_table(struct router *router, uint32_t vaddr,
                                 struct router_connection *con);

struct router *router_create(uint32_t vaddr, uint32_t net_addr,
                             uint32_t broad_addr, int sockfd,
                             struct taskexecutor *taskexecutor)
{
    struct router *router;
    if ((router = malloc(sizeof(struct router))) == NULL) {
        dprintf(STDERR_FILENO, "Router: Malloc Failed %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    };
    router->peer_listener = taskexecutor;

    init_router_buffer(&router->recv_buffer); // TODO
    init_router_buffer(&router->send_buffer); // TODO

    router->subnet_size = broad_addr - net_addr - 1;

    if ((router->routing_table = malloc(sizeof(struct router_connection *) *
                                        (router->subnet_size + 1))) == NULL) {
        dprintf(STDERR_FILENO, "Router: Malloc Failed %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    memset(router->routing_table, (uint64_t)NULL,
           sizeof(struct router_connection *) * (router->subnet_size + 1));

    pthread_rwlock_init(&router->routing_table_lock, NULL);

    router->sockfd = sockfd;

    if ((router->epoll_fd = epoll_create1(0)) < 0) {
        dprintf(STDERR_FILENO,
                "Router: Failed to create epoll file descriptor %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    router->vaddr = vaddr; // TODO:
    router->network_addr = net_addr;
    router->broadcast_addr = broad_addr;

    router->peers = NULL;
    pthread_mutex_init(&router->peers_lock, NULL);

    pthread_t kat, rt, st;
    pthread_create(&kat, NULL, keep_alive_worker, router);
    pthread_create(&rt, NULL, recv_worker, router);
    pthread_create(&st, NULL, send_worker, router);

    return router;
}

void router_destroy(struct router *router)
{
    // TODO
}

// int router_add_connection(struct router *router, vln_connection_type ctype,
//                           uint32_t vaddr, uint32_t raddr, uint16_t rport,
//                           int isActive, int sendInit)
// {
//     struct router_connection *new_con =
//         malloc(sizeof(struct router_connection));
//     new_con->vaddr = vaddr;
//     CONNECTIONSADDR(new_con->addr_port, raddr);
//     CONNECTIONSPORT(new_con->addr_port, rport);
//     new_con->active = isActive;
//     new_con->timerfdr = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
//     new_con->timerfds = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);

//     router->event.events = EPOLLIN;
//     router->event.data.ptr = new_con;
//     epoll_ctl(router->epoll_fd, EPOLL_CTL_ADD, new_con->timerfds,
//               &router->event);
//     if (isActive == 1) {
//         // struct task_info *task_info = malloc(sizeof(struct task_info));
//         // task_info->args = prepear_update_packet(router, new_con->vaddr);
//         // task_info->operation = UPDATE;
//         // taskexecutor_add_task(router->send_manager, task_info);

//         // task_info = malloc(sizeof(struct task_info));
//         // task_info->args = prepear_update_packet_2(router, new_con);
//         // task_info->operation = UPDATE;
//         // taskexecutor_add_task(router->send_manager, task_info);
//     }

//     pthread_mutex_lock(&router->peers_lock);
//     HASH_ADD_UINT64_T(router->peers, addr_port, new_con);
//     pthread_mutex_unlock(&router->peers_lock);

//     struct itimerspec iti;
//     memset(&iti, 0, sizeof(struct itimerspec));
//     iti.it_interval.tv_sec = 0;
//     iti.it_value.tv_sec = 1;
//     timerfd_settime(new_con->timerfds, 0, &iti, NULL);

//     char ip[INET_ADDRSTRLEN]; //
//     inet_ntop(AF_INET, &vaddr, &ip, INET_ADDRSTRLEN); //
//     printf("Added connection to IP: %s %u %d\n", ip,
//            CONNECTIONGADDR(new_con->addr_port),
//            CONNECTIONGPORT(new_con->addr_port));

//     // if (sendInit == 1)
//     //     send_init(router, new_con);

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
    return 0;
}

int router_transmit(struct router *router, void *packet, size_t size)
{
    size_t ssize;
    int key;
    struct sockaddr_in saddr;
    uint32_t vaddr_be;
    struct itimerspec iti;

    void *packeth = ((struct vln_data_packet_header *)packet);
    void *packetd = ((struct vln_data_packet_header *)packet) + 1;

    vaddr_be = ntohl(((struct iphdr *)packetd)->daddr);

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;

    pthread_rwlock_rdlock(&router->routing_table_lock);
    printf("In Router_transmit %u %u %u\n", router->network_addr, router->vaddr,
           router->broadcast_addr);
    if (vaddr_be > router->network_addr && vaddr_be < router->broadcast_addr) {
        printf("TRANSMIT %u\n", vaddr_be);
        key = vaddr_be - router->network_addr;
        if (router->routing_table[key] == NULL) {
            printf("CONNECTION IS NULL!!!\n");
            ssize = -1;
        } else {
            // need this??
            ((struct vln_data_packet_header *)packeth)->type = DATA;
            // need this??

            saddr.sin_port = htons(CONNECTIONGPORT(
                router->routing_table[key]->addr_port)); // hton ??
            saddr.sin_addr.s_addr = htonl(CONNECTIONGADDR(
                router->routing_table[key]->addr_port)); // hton ??

            printf("Sending Data To %u %u\n",
                   CONNECTIONGADDR(router->routing_table[key]->addr_port),
                   CONNECTIONGPORT(router->routing_table[key]->addr_port));

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

size_t router_receive(struct router *router, void *buffer, size_t size)
{
    sem_wait(&router->recv_buffer->used_slots);
    struct router_buffer_slot *slot =
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

size_t router_send(struct router *router, void *buffer, size_t size)
{
    // This method must be cold by 1 thread. if Added retransmision in Client
    // this will be a problem.
    struct router_buffer_slot *slot;
    size_t real_size;

    sem_wait(&router->send_buffer->free_slots);
    slot = &router->send_buffer->slots[router->send_buffer->write_idx];
    ((struct vln_data_packet_header *)slot->buffer)->type = DATA;

    real_size = size > SLOT_SIZE - sizeof(struct vln_data_packet_header) ?
                    SLOT_SIZE - sizeof(struct vln_data_packet_header) :
                    size;

    slot->used_size = real_size + sizeof(struct vln_data_packet_header);

    memcpy(slot->buffer + sizeof(struct vln_data_packet_header), buffer,
           real_size);

    uint32_t vaddr = ntohl(
        ((struct iphdr *)(slot->buffer + sizeof(struct vln_data_packet_header)))
            ->daddr);
    // printf("router_send Sending to %u\n", vaddr);

    sem_post(&router->send_buffer->used_slots);
    router->send_buffer->write_idx =
        (router->send_buffer->write_idx + 1) % MAX_PACKETS;

    return real_size;
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

void router_send_init(struct router *router, uint32_t raddr, uint32_t rport)
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
    saddr.sin_port = ntohs(rport);
    saddr.sin_addr.s_addr = ntohl(raddr);

    struct router_connection *new_con =
        create_connection(router->network_addr, raddr, rport);
    new_con->active = 1;
    set_timers(router, new_con, 10, 0);
    update_routing_table(router, router->network_addr, new_con);

    int sent = sendto(router->sockfd, spacket, sizeof(spacket), 0,
                      (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

    struct task_info *tinfo = malloc(sizeof(struct task_info));
    tinfo->operation = PEERCONNECTED;
    tinfo->args = NULL; // TODO

    taskexecutor_add_task(router->peer_listener, tinfo);

    printf("Init sent %d\n", sent);
}

void router_update_routing_table(struct router *router, uint32_t svaddr,
                                 uint32_t vaddr, uint32_t raddr, uint32_t rport)
{
    int key = vaddr - router->network_addr;
    int skey = svaddr - router->network_addr;
    pthread_rwlock_wrlock(&router->routing_table_lock);
    router->routing_table[key] = router->routing_table[skey];
    // if (cur_con == NULL || cur_con->value > con->value) {
    //     router->routing_table[key] = con;
    pthread_rwlock_unlock(&router->routing_table_lock);
}

// void *prepear_update_packet_2(struct router *router,
//                               struct router_connection *new_con)
// {
//     uint8_t *spacket =
//         malloc(sizeof(struct vln_packet_header) + 2 + sizeof(uint32_t) +
//                sizeof(struct vln_update_payload));
//     struct vln_packet_header *sheader = (struct vln_packet_header *)spacket;
//     // *((uint32_t *)PACKET_PAYLOAD(spacket)) = htonl(new_con->vaddr);

//     *(uint32_t *)PACKET_PAYLOAD(spacket) = htonl(router->vaddr);
//     *((uint32_t *)PACKET_PAYLOAD(spacket) + 1) = 0;

//     sheader->type = UPDATE;
//     sheader->payload_length =
//         htonl(2 * sizeof(uint32_t) + sizeof(struct vln_update_payload));
//     struct vln_update_payload *update =
//         PACKET_PAYLOAD(spacket) + 2 * sizeof(uint32_t);
//     update->raddr = htonl(CONNECTIONGADDR(new_con->addr_port));
//     update->rport = htonl(CONNECTIONGPORT(new_con->addr_port));
//     update->vaddr = htonl(new_con->vaddr);

//     return spacket;
// }

// void *prepear_update_packet(struct router *router, uint32_t dvaddr)
// {
//     pthread_mutex_lock(&router->peers_lock);
//     uint32_t count = HASH_COUNT(router->peers);
//     uint8_t *spacket =
//         malloc(sizeof(struct vln_packet_header) + 2 * sizeof(uint32_t) +
//                count * sizeof(struct vln_update_payload));
//     struct vln_packet_header *sheader = (struct vln_packet_header *)spacket;
//     sheader->type = UPDATE;
//     *(uint32_t *)PACKET_PAYLOAD(spacket) = htonl(router->vaddr);
//     *((uint32_t *)PACKET_PAYLOAD(spacket) + 1) = htonl(dvaddr);
//     struct vln_update_payload *update =
//         PACKET_PAYLOAD(spacket) + 2 * sizeof(uint32_t);

//     struct router_connection *s;
//     uint32_t real_count = 0;
//     for (s = router->peers; s != NULL;
//          s = (struct router_connection *)(s->hh.next)) {
//         if (s->active == 1) {
//             update->raddr = htonl(CONNECTIONGADDR(s->addr_port));
//             update->rport = htonl(CONNECTIONGPORT(s->addr_port));
//             update->vaddr = s->vaddr;
//             update = update + 1;
//             real_count++;
//         }
//     }
//     sheader->payload_length = htonl(
//         2 * sizeof(uint32_t) + real_count * sizeof(struct
//         vln_update_payload));
//     pthread_mutex_unlock(&router->peers_lock);
//     return spacket;
// }

static void *recv_worker(void *arg)
{
    struct router *router = (struct router *)arg;
    socklen_t slen = sizeof(struct sockaddr_in);
    struct sockaddr_in raddr;
    memset(&raddr, 0, sizeof(struct sockaddr_in));

    struct router_buffer_slot *slot;
    struct vln_data_packet_header *header;
    struct vln_data_init_payload *payload;
    void *packeth;
    void *packetd;
    while (1) {
        sem_wait(&router->recv_buffer->free_slots);
        slot = &router->recv_buffer->slots[router->recv_buffer->write_idx];

        slot->used_size = recvfrom(router->sockfd, slot->buffer, SLOT_SIZE, 0,
                                   (struct sockaddr *)&raddr, &slen);

        header = (struct vln_data_packet_header *)slot->buffer;

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &raddr.sin_addr, (void *)&ip, INET_ADDRSTRLEN);
        // printf("Received from %s:%d %ld bytes\n", ip, raddr.sin_port,
        //        slot->used_size);

        if (header->type == DATA) {
            // printf("Data Recvd!!!\n");
            packeth = ((struct vln_data_packet_header *)slot->buffer);
            packetd = ((struct vln_data_packet_header *)slot->buffer) + 1;

            uint32_t vaddr = ntohl(((struct iphdr *)packetd)->daddr);
            if (vaddr == router->vaddr) {
                router->recv_buffer->write_idx =
                    (router->recv_buffer->write_idx + 1) % MAX_PACKETS;
                sem_post(&router->recv_buffer->used_slots);
            } else {
                // printf("Retransmiting\n");
                router_send(
                    router,
                    slot->buffer + sizeof(struct vln_data_packet_header),
                    slot->used_size - sizeof(struct vln_data_packet_header));
                sem_post(&router->recv_buffer->free_slots);
                continue;
            }
        } else if (header->type == RETRANSMIT) {

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

            struct router_connection *new_con = create_connection(
                ntohl(payload->vaddr), ntohl(raddr.sin_addr.s_addr),
                ntohs(raddr.sin_port));
            new_con->active = 1;
            set_timers(router, new_con, 10, 0);
            update_routing_table(router, new_con->vaddr, new_con);

            struct router_action *act = malloc(sizeof(struct router_action));
            act->vaddr = ntohl(payload->vaddr);
            act->raddr = ntohl(raddr.sin_addr.s_addr);
            act->rport = ntohs(raddr.sin_port);

            struct task_info *task = malloc(sizeof(struct task_info));
            task->operation = PEERCONNECTED;
            task->args = act;
            taskexecutor_add_task(router->peer_listener, task);

            sem_post(&router->recv_buffer->free_slots);
            continue;
        } else {
            printf("bad type\n");
        }
    }
    return NULL;
}

static void *send_worker(void *arg)
{
    struct router *router = (struct router *)arg;
    socklen_t slen = sizeof(struct sockaddr_in);
    struct sockaddr_in saddr;
    memset(&saddr, 0, slen);

    saddr.sin_family = AF_INET;

    uint32_t vaddr;
    struct router_buffer_slot *slot;
    struct vln_data_packet_header *header;
    void *packeth;
    void *packetd;

    int key;
    struct itimerspec iti;
    memset(&iti, 0, sizeof(struct itimerspec));
    iti.it_interval.tv_sec = 0;
    iti.it_value.tv_sec = 10;

    while (1) {
        sem_wait(&router->send_buffer->used_slots);
        slot = &router->send_buffer->slots[router->send_buffer->read_idx];

        packeth = ((struct vln_data_packet_header *)slot->buffer);
        packetd = ((struct vln_data_packet_header *)slot->buffer) + 1;

        vaddr = ntohl(((struct iphdr *)packetd)->daddr);

        // printf("send_worker Sending to %u\n", vaddr);

        if (vaddr > router->network_addr && vaddr < router->broadcast_addr) {
            // printf("TRANSMIT %u\n", vaddr);
            key = vaddr - router->network_addr;
            pthread_rwlock_rdlock(&router->routing_table_lock);
            if (router->routing_table[key] == NULL) {
                printf("CONNECTION IS NULL!!!\n");
            } else {
                // need this??
                ((struct vln_data_packet_header *)packeth)->type = DATA;
                // need this??

                saddr.sin_port = htons(CONNECTIONGPORT(
                    router->routing_table[key]->addr_port)); // hton ??
                saddr.sin_addr.s_addr = htonl(CONNECTIONGADDR(
                    router->routing_table[key]->addr_port)); // hton ??

                // printf("Sending Data To %u %u\n",
                //        CONNECTIONGADDR(router->routing_table[key]->addr_port),
                //        CONNECTIONGPORT(router->routing_table[key]->addr_port));

                sendto(router->sockfd, packeth, slot->used_size, 0,
                       (struct sockaddr *)&saddr, slen);

                timerfd_settime(router->routing_table[key]->timerfds, 0, &iti,
                                NULL);
                pthread_rwlock_unlock(&router->routing_table_lock);
            }
        } else if (vaddr == router->broadcast_addr) {
            printf("BROADCAST %u\n", vaddr);
            // TODO
        } else {
            printf("OUT OF RANGE %u\n", vaddr);
            // WHAT TO DO???
        }

        router->send_buffer->read_idx =
            (router->send_buffer->read_idx + 1) % MAX_PACKETS;
        sem_post(&router->send_buffer->free_slots);
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
        struct router_connection *con;
        for (int i = 0; i < event_count; i++) {
            con = (struct router_connection *)router->events[i].data.ptr;
            uint64_t timerexps;
            read(con->timerfds, &timerexps, sizeof(uint64_t));
            printf("Timer '%lu'\n", timerexps);

            struct vln_data_packet_header packet;
            packet.type = KEEPALIVE;

            saddr.sin_port = htons(CONNECTIONGPORT(con->addr_port));
            saddr.sin_addr.s_addr = htonl(CONNECTIONGADDR(con->addr_port));

            sendto(router->sockfd, &packet,
                   sizeof(struct vln_data_packet_header), 0,
                   (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

            printf("KEEPALIVE SENT %u %d\n", CONNECTIONGADDR(con->addr_port),
                   CONNECTIONGPORT(con->addr_port));

            timerfd_settime(con->timerfds, 0, &iti, NULL);
        }
    }
    return NULL;
}

static void init_router_buffer(struct router_buffer **buff)
{
    *buff = malloc(sizeof(struct router_buffer));
    sem_init(&(*buff)->free_slots, 0, MAX_PACKETS);
    sem_init(&(*buff)->used_slots, 0, 0);
    (*buff)->write_idx = 0;
    (*buff)->read_idx = 0;
}

static struct router_connection *
create_connection(uint32_t vaddr, uint32_t raddr, uint32_t rport)
{
    struct router_connection *new_con =
        malloc(sizeof(struct router_connection));
    // new_con->con_type = ctype;
    new_con->vaddr = vaddr;
    CONNECTIONSADDR(new_con->addr_port, raddr);
    CONNECTIONSPORT(new_con->addr_port, rport);
    new_con->active = 0;
    new_con->timerfdr = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
    new_con->timerfds = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);

    return new_con;
}

static void set_timers(struct router *router, struct router_connection *con,
                       int send_tv, int recv_tv)
{
    router->event.events = EPOLLIN;
    router->event.data.ptr = con;
    epoll_ctl(router->epoll_fd, EPOLL_CTL_ADD, con->timerfds, &router->event);

    struct itimerspec iti;
    memset(&iti, 0, sizeof(struct itimerspec));
    iti.it_interval.tv_sec = 0;
    iti.it_value.tv_sec = send_tv;

    timerfd_settime(con->timerfds, 0, &iti, NULL);
}

static void update_routing_table(struct router *router, uint32_t vaddr,
                                 struct router_connection *con)
{
    struct router_connection *cur_con;
    int key = vaddr - router->network_addr;
    pthread_rwlock_wrlock(&router->routing_table_lock);
    cur_con = router->routing_table[key];
    router->routing_table[key] = con;
    // if (cur_con == NULL || cur_con->value > con->value) {
    //     router->routing_table[key] = con;
    // }
    pthread_rwlock_unlock(&router->routing_table_lock);
}
