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
#include "lib/utlist.h"

#define MAX_PACKETS 100
#define MAX_EVENTS 10

#define CONNECTIONSADDR(addr_port, addr) *(uint32_t *)&addr_port = addr
#define CONNECTIONGADDR(addr_port) *(uint32_t *)&addr_port
#define CONNECTIONSPORT(addr_port, port)                                       \
    *(uint16_t *)((uint32_t *)&addr_port + 1) = port
#define CONNECTIONGPORT(addr_port) *(uint16_t *)((uint32_t *)&addr_port + 1)

struct router_connection {
    uint32_t vaddr;
    uint64_t addr_port;
    int timerfds;
    int timerfdr;

    uint8_t active;

    UT_hash_handle hh;
};

struct router {
    int sockfd;

    uint32_t vaddr;
    uint32_t network_addr;
    uint32_t broadcast_addr;
    size_t subnet_size;

    struct router_connection **routing_table;
    pthread_rwlock_t routing_table_lock;

    struct router_buffer_slot *free_slots;
    pthread_mutex_t free_slots_lock;
    pthread_cond_t free_slots_cond;

    struct router_buffer_slot *recv_buffer;
    pthread_mutex_t recv_buffer_lock;
    pthread_cond_t recv_buffer_cond;

    struct router_buffer_slot *send_buffer;
    pthread_mutex_t send_buffer_lock;
    pthread_cond_t send_buffer_cond;

    int sepoll_fd;
    struct epoll_event sevent, sevents[MAX_EVENTS];

    int repoll_fd;
    struct epoll_event revent, revents[MAX_EVENTS];

    struct taskexecutor *peer_listener;

    struct router_connection *held_connections;
    pthread_rwlock_t held_connections_lock;

    uint64_t root_addr_port;
};

static void allocate_free_slots(struct router *, size_t slot_count);
static struct router_connection *
create_connection(uint32_t vaddr, uint32_t raddr, uint32_t rport);
void destroy_connection(struct router_connection *con);
static void set_timers(struct router *router, struct router_connection *con,
                       int send_tv, int recv_tv);
static void *keep_alive_send_worker(void *arg);
static void *keep_alive_check_worker(void *arg);
static void *recv_worker(void *arg);
static void *send_worker(void *arg);
static void update_routing_table(struct router *router, uint32_t vaddr,
                                 struct router_connection *);

struct router *router_create(uint32_t vaddr, uint32_t net_addr,
                             uint32_t broad_addr, int sockfd,
                             struct taskexecutor *taskexecutor)
{
    struct router *router;
    if ((router = malloc(sizeof(struct router))) == NULL) {
        dprintf(STDERR_FILENO, "Router: Malloc Failed %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    };
    router->sockfd = sockfd;
    router->vaddr = vaddr; // TODO:
    router->network_addr = net_addr;
    router->broadcast_addr = broad_addr;
    router->subnet_size = broad_addr - net_addr - 1;

    router->free_slots = NULL;
    pthread_mutex_init(&router->free_slots_lock, NULL);
    pthread_cond_init(&router->free_slots_cond, NULL);
    allocate_free_slots(router, 20); /* Must be At least 4 !!! */

    router->recv_buffer = NULL;
    pthread_mutex_init(&router->recv_buffer_lock, NULL);
    pthread_cond_init(&router->recv_buffer_cond, NULL);

    router->send_buffer = NULL;
    pthread_mutex_init(&router->send_buffer_lock, NULL);
    pthread_cond_init(&router->send_buffer_cond, NULL);

    if ((router->routing_table = malloc(sizeof(struct router_connection *) *
                                        (router->subnet_size + 1))) == NULL) {
        dprintf(STDERR_FILENO, "Router: Malloc Failed %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    memset(router->routing_table, (uint64_t)NULL,
           sizeof(struct router_connection *) * (router->subnet_size + 1));

    pthread_rwlock_init(&router->routing_table_lock, NULL);

    if ((router->sepoll_fd = epoll_create1(0)) < 0) {
        dprintf(STDERR_FILENO,
                "Router: Failed to create epoll file descriptor %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    if ((router->repoll_fd = epoll_create1(0)) < 0) {
        dprintf(STDERR_FILENO,
                "Router: Failed to create epoll file descriptor %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    router->held_connections = NULL;
    pthread_rwlock_init(&router->held_connections_lock, NULL);

    router->peer_listener = taskexecutor;

    router->root_addr_port = 0;

    pthread_t kasw, kacw, rt1, rt2, st1, st2;
    pthread_create(&kasw, NULL, keep_alive_send_worker, router);
    pthread_create(&kacw, NULL, keep_alive_check_worker, router);
    pthread_create(&rt1, NULL, recv_worker, router);
    pthread_create(&rt2, NULL, recv_worker, router);
    pthread_create(&st1, NULL, send_worker, router);
    pthread_create(&st2, NULL, send_worker, router);

    return router;
}

void router_destroy(struct router *router)
{
    // TODO
}

void router_try_connection(struct router *router, uint32_t vaddr,
                           uint32_t raddr, uint16_t rport)
{
    struct router_connection *new_con = create_connection(vaddr, raddr, rport);
    new_con->active = 0;

    pthread_rwlock_wrlock(&router->held_connections_lock);
    HASH_ADD_UINT64_T(router->held_connections, addr_port, new_con);
    set_timers(router, new_con, 1, 30);
    pthread_rwlock_unlock(&router->held_connections_lock);
}

void router_remove_connection(struct router *router, uint32_t vaddr,
                              uint32_t raddr, uint16_t rport)
{
    uint64_t addr_port;
    CONNECTIONSADDR(addr_port, raddr);
    CONNECTIONSPORT(addr_port, rport);

    struct router_connection *con;
    pthread_rwlock_wrlock(&router->held_connections_lock);
    HASH_FIND_UINT64_T(router->held_connections, &addr_port, con);
    if (con != NULL) {
        HASH_DEL(router->held_connections, con);
        printf("Waishalaaa\n");
    }
    pthread_rwlock_unlock(&router->held_connections_lock);

    if (con != NULL) {
        destroy_connection(con);
    }
}

struct router_buffer_slot *router_get_free_slot(struct router *router)
{
    struct router_buffer_slot *res;
    pthread_mutex_lock(&router->free_slots_lock);
    while (router->free_slots == NULL) {
        pthread_cond_wait(&router->free_slots_cond, &router->free_slots_lock);
    }
    res = router->free_slots;
    DL_DELETE(router->free_slots, res);
    pthread_mutex_unlock(&router->free_slots_lock);

    return res;
}

void router_add_free_slot(struct router *router,
                          struct router_buffer_slot *slot)
{
    pthread_mutex_lock(&router->free_slots_lock);
    DL_APPEND(router->free_slots, slot);
    pthread_cond_broadcast(&router->free_slots_cond);
    pthread_mutex_unlock(&router->free_slots_lock);
}

struct router_buffer_slot *router_receive(struct router *router)
{
    struct router_buffer_slot *res;
    pthread_mutex_lock(&router->recv_buffer_lock);
    while (router->recv_buffer == NULL) {
        pthread_cond_wait(&router->recv_buffer_cond, &router->recv_buffer_lock);
    }
    res = router->recv_buffer;
    DL_DELETE(router->recv_buffer, res);
    pthread_mutex_unlock(&router->recv_buffer_lock);

    return res;
}

void router_send(struct router *router, struct router_buffer_slot *slot)
{
    pthread_mutex_lock(&router->send_buffer_lock);
    DL_APPEND(router->send_buffer, slot);
    pthread_cond_broadcast(&router->send_buffer_cond);
    pthread_mutex_unlock(&router->send_buffer_lock);
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

    // TODO wait for approval from tcp same as in clients or just activate
    // imediatelly.

    struct router_connection *new_con =
        create_connection(router->network_addr, raddr, rport);
    new_con->active = 1;
    router->root_addr_port = new_con->addr_port;
    set_timers(router, new_con, 10, 30);

    update_routing_table(router, new_con->vaddr, new_con);

    pthread_rwlock_wrlock(&router->held_connections_lock);
    HASH_ADD_UINT64_T(router->held_connections, addr_port, new_con);
    pthread_rwlock_unlock(&router->held_connections_lock);

    int sent = sendto(router->sockfd, spacket, sizeof(spacket), 0,
                      (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

    struct task_info *tinfo = malloc(sizeof(struct task_info));
    tinfo->operation = PEERCONNECTED;
    tinfo->args = NULL; // TODO

    taskexecutor_add_task(router->peer_listener, tinfo);

    printf("Init sent %d\n", sent);
}

void router_setup_pyramid(struct router *router, uint32_t vaddr)
{
    int key = vaddr - router->network_addr;

    struct router_connection *root_con;
    pthread_rwlock_rdlock(&router->held_connections_lock);
    HASH_FIND_UINT64_T(router->held_connections, &router->root_addr_port,
                       root_con);
    if (root_con != NULL) {
        pthread_rwlock_wrlock(&router->routing_table_lock);
        router->routing_table[key] = root_con;
        pthread_rwlock_unlock(&router->routing_table_lock);
        printf("Pyramid set\n");
    }
    pthread_rwlock_unlock(&router->held_connections_lock);
}

static void *recv_worker(void *arg)
{
    struct router *router = (struct router *)arg;
    socklen_t slen = sizeof(struct sockaddr_in);

    struct sockaddr_in raddr;
    memset(&raddr, 0, sizeof(struct sockaddr_in));

    int key;
    uint32_t vaddr;
    uint32_t svaddr;

    struct itimerspec iti;
    memset(&iti, 0, sizeof(struct itimerspec));
    iti.it_interval.tv_sec = 0;
    iti.it_value.tv_sec = 30;

    struct vln_data_packet_header *packeth;
    void *packetd;
    struct router_buffer_slot *slot;
    while (1) {
        slot = router_get_free_slot(router);

        slot->used_size = recvfrom(router->sockfd, slot->buffer, SLOT_SIZE, 0,
                                   (struct sockaddr *)&raddr, &slen);

        packeth = (struct vln_data_packet_header *)slot->buffer;

        // char ip[INET_ADDRSTRLEN];
        // inet_ntop(AF_INET, &raddr.sin_addr, (void *)&ip, INET_ADDRSTRLEN);
        // printf("Received from %s:%d %ld bytes\n", ip, raddr.sin_port,
        //        slot->used_size);

        if (packeth->type == DATA) {
            packetd = ((struct vln_data_packet_header *)slot->buffer) + 1;

            vaddr = ntohl(((struct iphdr *)packetd)->daddr);
            svaddr = ntohl(((struct iphdr *)packetd)->saddr);

            key = svaddr - router->network_addr;

            uint64_t hc_addr_port;
            CONNECTIONSADDR(hc_addr_port, ntohl(raddr.sin_addr.s_addr));
            CONNECTIONSPORT(hc_addr_port, ntohs(raddr.sin_port));

            struct router_connection *held_con;
            pthread_rwlock_rdlock(&router->held_connections_lock);
            HASH_FIND_UINT64_T(router->held_connections, &hc_addr_port,
                               held_con);
            if (held_con != NULL) {
                timerfd_settime(held_con->timerfdr, 0, &iti, NULL);
            }
            pthread_rwlock_unlock(&router->held_connections_lock);

            // printf("Data Recvd!!! %u %u\n", vaddr, slot->used_size);
            if (vaddr == router->vaddr) {
                pthread_mutex_lock(&router->recv_buffer_lock);
                DL_APPEND(router->recv_buffer, slot);
                pthread_cond_broadcast(&router->recv_buffer_cond);
                pthread_mutex_unlock(&router->recv_buffer_lock);
            } else {
                // printf("Retransmiting %u\n", vaddr);
                router_send(router, slot);
            }
        } else if (packeth->type == KEEPALIVE) {
            printf("KEEPALIVE Recvd\n");
            struct vln_data_keepalive_payload *rpayload =
                (struct vln_data_keepalive_payload *)DATA_PACKET_PAYLOAD(
                    slot->buffer);

            vaddr = ntohl(rpayload->vaddr); // agar

            key = vaddr - router->network_addr; // agar
            printf("Keepalive Vaddr %u key %d\n", ntohl(rpayload->vaddr),
                   key); // agar

            printf("KEEPALIVE RECV %u %u %d\n", vaddr,
                   ntohl(raddr.sin_addr.s_addr), ntohs(raddr.sin_port));

            uint64_t hc_addr_port;
            CONNECTIONSADDR(hc_addr_port, ntohl(raddr.sin_addr.s_addr));
            CONNECTIONSPORT(hc_addr_port, ntohs(raddr.sin_port));

            struct router_connection *held_con;
            pthread_rwlock_wrlock(&router->held_connections_lock);
            HASH_FIND_UINT64_T(router->held_connections, &hc_addr_port,
                               held_con);
            if (held_con != NULL) {
                printf("timer reset\n"); // agar
                if (held_con->active == 0) {
                    held_con->active = 1;
                    // rlistener, update for pyramids.
                    printf("P2P\n");
                    update_routing_table(router, held_con->vaddr, held_con);
                }
                timerfd_settime(held_con->timerfdr, 0, &iti, NULL);
            } else {
                printf("Connection NULL"); // agar
            }
            pthread_rwlock_unlock(&router->held_connections_lock);

        } else if (packeth->type == INIT) {
            printf("Init Recvd\n");
            struct vln_data_init_payload *payload =
                (struct vln_data_init_payload *)DATA_PACKET_PAYLOAD(packeth);
            printf("Router Vaddr %u \n", ntohl(payload->vaddr));
            printf("Router Rport %d SET FOR HOST %u\n", ntohs(raddr.sin_port),
                   ntohl(payload->vaddr));

            struct router_connection *new_con = create_connection(
                ntohl(payload->vaddr), ntohl(raddr.sin_addr.s_addr),
                ntohs(raddr.sin_port));
            new_con->active = 1;
            set_timers(router, new_con, 10, 30);
            update_routing_table(router, new_con->vaddr, new_con);

            pthread_rwlock_wrlock(&router->held_connections_lock);
            HASH_ADD_UINT64_T(router->held_connections, addr_port, new_con);
            pthread_rwlock_unlock(&router->held_connections_lock);

            struct router_action *act = malloc(sizeof(struct router_action));
            act->vaddr = ntohl(payload->vaddr);
            act->raddr = ntohl(raddr.sin_addr.s_addr);
            act->rport = ntohs(raddr.sin_port);

            struct task_info *task = malloc(sizeof(struct task_info));
            task->operation = PEERCONNECTED;
            task->args = act;
            taskexecutor_add_task(router->peer_listener, task);

        } else {
            printf("bad type\n");
        }
    }
    printf("recv_worker died\n");
    return NULL;
}

static void *send_worker(void *arg)
{
    struct router *router = (struct router *)arg;

    socklen_t slen = sizeof(struct sockaddr_in);
    struct sockaddr_in saddr;
    memset(&saddr, 0, slen);

    saddr.sin_family = AF_INET;

    void *packeth;
    void *packetd;
    uint32_t vaddr;

    int key;
    struct itimerspec iti;
    memset(&iti, 0, sizeof(struct itimerspec));
    iti.it_interval.tv_sec = 0;
    iti.it_value.tv_sec = 10;

    struct router_buffer_slot *slot_to_send;
    while (1) {
        pthread_mutex_lock(&router->send_buffer_lock);
        while (router->send_buffer == NULL) {
            pthread_cond_wait(&router->send_buffer_cond,
                              &router->send_buffer_lock);
        }
        slot_to_send = router->send_buffer;
        DL_DELETE(router->send_buffer, slot_to_send);
        pthread_mutex_unlock(&router->send_buffer_lock);

        packeth = ((struct vln_data_packet_header *)slot_to_send->buffer);
        packetd = ((struct vln_data_packet_header *)slot_to_send->buffer) + 1;

        vaddr = ntohl(((struct iphdr *)packetd)->daddr);

        if (vaddr > router->network_addr && vaddr < router->broadcast_addr) {
            // printf("TRANSMIT %u\n", vaddr);
            key = vaddr - router->network_addr;
            pthread_rwlock_rdlock(&router->routing_table_lock);
            if (router->routing_table[key] == NULL) {
                printf("CONNECTION IS NULL!!!\n");
            } else {

                saddr.sin_port = htons(CONNECTIONGPORT(
                    router->routing_table[key]->addr_port)); // hton ??
                saddr.sin_addr.s_addr = htonl(CONNECTIONGADDR(
                    router->routing_table[key]->addr_port)); // hton ??

                // printf("Sending Data To %u %u\n",
                //        CONNECTIONGADDR(router->routing_table[key]->addr_port),
                //        CONNECTIONGPORT(router->routing_table[key]->addr_port));

                sendto(router->sockfd, packeth, slot_to_send->used_size, 0,
                       (struct sockaddr *)&saddr, slen);

                timerfd_settime(router->routing_table[key]->timerfds, 0, &iti,
                                NULL); // es agaraa aq swori
            }
            pthread_rwlock_unlock(&router->routing_table_lock);
        } else if (vaddr == router->broadcast_addr) {
            printf("BROADCAST %u\n", vaddr);
            // TODO
        } else {
            printf("OUT OF RANGE %u\n", vaddr);
            // WHAT TO DO???
        }

        router_add_free_slot(router, slot_to_send);
    }

    return NULL;
}

static void *keep_alive_send_worker(void *arg)
{
    struct router *router = (struct router *)arg;

    struct itimerspec iti;
    memset(&iti, 0, sizeof(struct itimerspec));
    iti.it_interval.tv_sec = 0;
    iti.it_value.tv_sec = 10;

    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;

    struct router_connection *con;
    uint64_t addr_port;
    int event_count, i;
    while (1) {
        event_count =
            epoll_wait(router->sepoll_fd, router->sevents, MAX_EVENTS, -1);
        for (i = 0; i < event_count; i++) {
            addr_port = router->sevents[i].data.u64;

            pthread_rwlock_rdlock(&router->held_connections_lock);
            HASH_FIND_UINT64_T(router->held_connections, &addr_port, con);
            printf("TRY in keepalive %lu\n", con);
            if (con == NULL) {
                printf("Connection NULLIA\n");
                pthread_rwlock_unlock(&router->held_connections_lock);
                continue;
            }

            // Delete
            uint64_t timerexps;
            read(con->timerfds, &timerexps, sizeof(uint64_t));
            printf("Timer '%lu'\n", timerexps);
            // Delete

            uint8_t spacket[sizeof(struct vln_data_packet_header) +
                            sizeof(struct vln_data_keepalive_payload)];
            struct vln_data_packet_header *sheader =
                (struct vln_data_packet_header *)spacket;
            struct vln_data_keepalive_payload *spayload =
                (struct vln_data_keepalive_payload *)DATA_PACKET_PAYLOAD(
                    spacket);
            sheader->type = KEEPALIVE;
            spayload->vaddr = htonl(router->vaddr);

            saddr.sin_port = htons(CONNECTIONGPORT(con->addr_port));
            saddr.sin_addr.s_addr = htonl(CONNECTIONGADDR(con->addr_port));

            sendto(router->sockfd, &spacket, sizeof(spacket), 0,
                   (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

            printf("KEEPALIVE SENT %u %u %d\n", con->vaddr,
                   CONNECTIONGADDR(con->addr_port),
                   CONNECTIONGPORT(con->addr_port));

            timerfd_settime(con->timerfds, 0, &iti, NULL);

            pthread_rwlock_unlock(&router->held_connections_lock);
        }
    }
    return NULL;
}

static void *keep_alive_check_worker(void *arg)
{
    struct router *router = (struct router *)arg;

    struct router_connection *con;
    uint64_t addr_port;
    uint32_t vaddr;
    int event_count, i;
    while (1) {
        event_count =
            epoll_wait(router->repoll_fd, router->revents, MAX_EVENTS, -1);

        for (i = 0; i < event_count; i++) {
            addr_port = router->revents[i].data.u64;

            pthread_rwlock_rdlock(&router->held_connections_lock);
            HASH_FIND_UINT64_T(router->held_connections, &addr_port, con);
            if (con == NULL) {
                pthread_rwlock_unlock(&router->held_connections_lock);
                continue;
            }

            // Delete
            uint64_t timerexps;
            read(con->timerfdr, &timerexps, sizeof(uint64_t));
            printf("Recv Timer '%lu'\n", timerexps);
            printf("NO TRAFIC FOR %d Seconds, Dead Connection\n", 30);
            // Delete

            vaddr = con->vaddr;

            // if (con->active == 0) {
            //     HASH_DEL(router->held_connections, con);
            //     destroy_connection(con);
            // } else {
            struct router_action *act = malloc(sizeof(struct router_action));
            act->vaddr = vaddr;
            act->raddr = 0; // TODO
            act->rport = 0; // TODO

            struct task_info *task = malloc(sizeof(struct task_info));
            task->operation = PEERDISCONNECTED;
            task->args = act;

            taskexecutor_add_task(router->peer_listener, task);
            //}
            pthread_rwlock_unlock(&router->held_connections_lock);
        }
    }
    return NULL;
}

static void allocate_free_slots(struct router *router, size_t slot_count)
{
    struct router_buffer_slot *slot;
    for (int i = 0; i < slot_count; i++) {
        slot = malloc(sizeof(struct router_buffer_slot));
        slot->used_size = 0;
        if (slot != NULL) {
            DL_APPEND(router->free_slots, slot);
        }
    }
}

static struct router_connection *
create_connection(uint32_t vaddr, uint32_t raddr, uint32_t rport)
{
    struct router_connection *new_con =
        malloc(sizeof(struct router_connection));
    new_con->vaddr = vaddr;
    CONNECTIONSADDR(new_con->addr_port, raddr);
    CONNECTIONSPORT(new_con->addr_port, rport);
    new_con->active = 0;
    new_con->timerfds = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
    new_con->timerfdr = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);

    return new_con;
}

void destroy_connection(struct router_connection *con)
{
    close(con->timerfds);
    close(con->timerfdr);
    free(con);
}

static void set_timers(struct router *router, struct router_connection *con,
                       int send_tv, int recv_tv)
{
    router->sevent.events = EPOLLIN;
    router->sevent.data.u64 = con->addr_port;
    epoll_ctl(router->sepoll_fd, EPOLL_CTL_ADD, con->timerfds, &router->sevent);

    router->revent.events = EPOLLIN;
    router->revent.data.u64 = con->addr_port;
    epoll_ctl(router->repoll_fd, EPOLL_CTL_ADD, con->timerfdr, &router->revent);

    struct itimerspec itis;
    memset(&itis, 0, sizeof(struct itimerspec));
    itis.it_interval.tv_sec = 0;
    itis.it_value.tv_sec = send_tv;

    struct itimerspec itir;
    memset(&itir, 0, sizeof(struct itimerspec));
    itir.it_interval.tv_sec = 0;
    itir.it_value.tv_sec = recv_tv;

    timerfd_settime(con->timerfds, 0, &itis, NULL);

    timerfd_settime(con->timerfdr, 0, &itir, NULL);
}

static void update_routing_table(struct router *router, uint32_t vaddr,
                                 struct router_connection *new_con)
{
    int key = vaddr - router->network_addr;

    pthread_rwlock_wrlock(&router->routing_table_lock);
    router->routing_table[key] = new_con;
    pthread_rwlock_unlock(&router->routing_table_lock);
}
