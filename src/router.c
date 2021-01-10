#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <unistd.h>

#include "router.h"
#include <uthash.h>
#include <utlist.h>

#define MAX_PACKETS 100
#define MAX_EVENTS 10

#define CONNECTIONSADDR(addr_port, addr) *(uint32_t *)&addr_port = addr
#define CONNECTIONGADDR(addr_port) *(uint32_t *)&addr_port
#define CONNECTIONSPORT(addr_port, port)                                       \
    *(uint16_t *)((uint32_t *)&addr_port + 1) = port
#define CONNECTIONGPORT(addr_port) *(uint16_t *)((uint32_t *)&addr_port + 1)

#define KEEPALIVERECV 1
#define KEEPALIVESEND 2
#define KEEPALIVEDIE 3

typedef uint8_t keep_alive_event;

struct keep_alive_info {
    keep_alive_event event;
    int timerfd;
    struct router_connection *con;
    pthread_rwlock_t con_lock;
};

struct router_connection {
    uint32_t vaddr;
    uint32_t raddr;
    uint16_t rport;

    uint8_t active;

    struct keep_alive_info *skinfo;
    struct keep_alive_info *rkinfo;

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

    pthread_t kasw, rt1, rt2, st1, st2;

    int epoll_fd;
    struct epoll_event event, events[MAX_EVENTS];

    int mngr_pipe_fd;

    struct router_connection *pending_connections;
    pthread_mutex_t pending_connections_lock;

    int buffer_threads_flag;
    pthread_rwlock_t buffer_threads_flag_lock;
};

static void allocate_free_slots(struct router *, size_t slot_count);
static struct router_connection *
create_connection(uint32_t vaddr, uint32_t raddr, uint16_t rport);
void destroy_connection(struct router_connection *con);
static void set_timers(struct router *router, struct router_connection *con,
                       int send_tv, int recv_tv);
static void *keep_alive_worker(void *arg);
static void *recv_worker(void *arg);
static void *send_worker(void *arg);
static void update_routing_table(struct router *router, uint32_t vaddr,
                                 struct router_connection *);

struct router *router_create(uint32_t vaddr, uint32_t net_addr,
                             uint32_t broad_addr, int sockfd, int mngr_pipe_fd)
{
    struct router *router;
    if ((router = malloc(sizeof(struct router))) == NULL) {
        dprintf(STDERR_FILENO, "Router: Malloc Failed %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    };
    router->sockfd = sockfd;
    router->vaddr = vaddr;
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

    if ((router->epoll_fd = epoll_create1(0)) < 0) {
        dprintf(STDERR_FILENO,
                "Router: Failed to create epoll file descriptor %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    router->pending_connections = NULL;
    pthread_mutex_init(&router->pending_connections_lock, NULL);

    router->mngr_pipe_fd = mngr_pipe_fd;

    router->buffer_threads_flag = 0;
    pthread_rwlock_init(&router->buffer_threads_flag_lock, NULL);

    pthread_create(&router->kasw, NULL, keep_alive_worker, router);
    pthread_create(&router->rt1, NULL, recv_worker, router);
    pthread_create(&router->rt2, NULL, recv_worker, router);
    pthread_create(&router->st1, NULL, send_worker, router);
    pthread_create(&router->st2, NULL, send_worker, router);

    return router;
}

void router_stop(struct router *router)
{
    pthread_rwlock_wrlock(&router->buffer_threads_flag_lock);
    router->buffer_threads_flag = 1;
    pthread_rwlock_unlock(&router->buffer_threads_flag_lock);

    pthread_cond_broadcast(&router->recv_buffer_cond);
    pthread_cond_broadcast(&router->send_buffer_cond);
    pthread_cond_broadcast(&router->free_slots_cond);

    shutdown(router->sockfd, SHUT_RDWR);

    pthread_join(router->rt1, NULL);
    pthread_join(router->rt2, NULL);

    pthread_join(router->st1, NULL);
    pthread_join(router->st2, NULL);
}

void router_destroy(struct router *router)
{
    pthread_rwlock_wrlock(&router->routing_table_lock);
    /* [0] and [1] is the same object */
    for (int key = 1; key <= router->subnet_size; key++) {
        if (router->routing_table[key] != NULL &&
            key == (router->routing_table[key]->vaddr - router->network_addr)) {
            destroy_connection(router->routing_table[key]);
        }
    }
    pthread_rwlock_unlock(&router->routing_table_lock);

    struct keep_alive_info *dkinfo = malloc(sizeof(struct keep_alive_info));
    dkinfo->event = KEEPALIVEDIE;
    dkinfo->timerfd = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);
    pthread_rwlock_init(&dkinfo->con_lock, NULL);

    struct itimerspec iti;
    memset(&iti, 0, sizeof(struct itimerspec));
    iti.it_value.tv_sec = 2;

    router->event.events = EPOLLIN;
    router->event.data.ptr = dkinfo;
    epoll_ctl(router->epoll_fd, EPOLL_CTL_ADD, dkinfo->timerfd, &router->event);
    timerfd_settime(dkinfo->timerfd, 0, &iti, NULL);

    int del_freeslots = 0;
    int del_sendslots = 0;
    int del_recvslots = 0;

    struct router_buffer_slot *tmp;
    struct router_buffer_slot *slot;
    DL_FOREACH_SAFE(router->send_buffer, slot, tmp)
    {
        DL_DELETE(router->send_buffer, slot);
        free(slot);
        del_sendslots++;
    }

    DL_FOREACH_SAFE(router->recv_buffer, slot, tmp)
    {
        DL_DELETE(router->recv_buffer, slot);
        free(slot);
        del_recvslots++;
    }

    DL_FOREACH_SAFE(router->free_slots, slot, tmp)
    {
        DL_DELETE(router->free_slots, slot);
        free(slot);
        del_freeslots++;
    }

    free(router->routing_table);

    pthread_rwlock_destroy(&router->buffer_threads_flag_lock);
    pthread_rwlock_destroy(&router->routing_table_lock);
    pthread_mutex_destroy(&router->pending_connections_lock);
    pthread_mutex_destroy(&router->free_slots_lock);
    pthread_mutex_destroy(&router->recv_buffer_lock);
    pthread_mutex_destroy(&router->send_buffer_lock);
    pthread_cond_destroy(&router->free_slots_cond);
    pthread_cond_destroy(&router->send_buffer_cond);
    pthread_cond_destroy(&router->recv_buffer_cond);

    pthread_join(router->kasw, NULL);

    close(router->mngr_pipe_fd);

    close(router->sockfd);
    close(router->epoll_fd);
    free(router);
}

void router_try_connection(struct router *router, uint32_t vaddr,
                           uint32_t raddr, uint16_t rport)
{
    struct router_connection *new_con = create_connection(vaddr, raddr, rport);
    new_con->active = 0;

    pthread_mutex_lock(&router->pending_connections_lock);
    HASH_ADD_INT(router->pending_connections, vaddr, new_con);
    set_timers(router, new_con, 1, 30);
    pthread_mutex_unlock(&router->pending_connections_lock);
}

void router_remove_connection(struct router *router, uint32_t vaddr)
{
    int key = vaddr - router->network_addr;

    int isp2p = 0;

    struct router_connection *con;
    pthread_rwlock_wrlock(&router->routing_table_lock);
    con = router->routing_table[key];
    router->routing_table[key] = NULL;
    if (con != NULL && key == con->vaddr - router->network_addr) {
        isp2p = 1;
    }
    pthread_rwlock_unlock(&router->routing_table_lock);

    if (isp2p == 1) {
        destroy_connection(con);
    }
}

struct router_buffer_slot *router_get_free_slot(struct router *router)
{
    struct router_buffer_slot *res;

    pthread_rwlock_rdlock(&router->buffer_threads_flag_lock);
    if (router->buffer_threads_flag == 1) {
        return NULL;
    }
    pthread_rwlock_unlock(&router->buffer_threads_flag_lock);

    pthread_mutex_lock(&router->free_slots_lock);
    while (router->free_slots == NULL) {
        pthread_cond_wait(&router->free_slots_cond, &router->free_slots_lock);

        pthread_rwlock_rdlock(&router->buffer_threads_flag_lock);
        if (router->buffer_threads_flag == 1) {
            pthread_rwlock_unlock(&router->buffer_threads_flag_lock);
            pthread_mutex_unlock(&router->free_slots_lock);
            return NULL;
        }
        pthread_rwlock_unlock(&router->buffer_threads_flag_lock);
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

    pthread_rwlock_rdlock(&router->buffer_threads_flag_lock);
    if (router->buffer_threads_flag == 1) {
        return NULL;
    }
    pthread_rwlock_unlock(&router->buffer_threads_flag_lock);

    pthread_mutex_lock(&router->recv_buffer_lock);
    while (router->recv_buffer == NULL) {
        pthread_cond_wait(&router->recv_buffer_cond, &router->recv_buffer_lock);

        pthread_rwlock_rdlock(&router->buffer_threads_flag_lock);
        if (router->buffer_threads_flag == 1) {
            pthread_rwlock_unlock(&router->buffer_threads_flag_lock);
            pthread_mutex_unlock(&router->recv_buffer_lock);
            return NULL;
        }
        pthread_rwlock_unlock(&router->buffer_threads_flag_lock);
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

void router_send_init(struct router *router, uint32_t root_vaddr,
                      uint32_t root_raddr, uint16_t root_rport)
{
    uint8_t spacket[sizeof(struct router_packet_header) +
                    sizeof(struct router_init_payload)];
    struct router_packet_header *sheader =
        (struct router_packet_header *)spacket;
    struct router_init_payload *spayload =
        (struct router_init_payload *)ROUTER_PACKET_PAYLOAD(spacket);
    sheader->type = INIT;
    spayload->vaddr = htonl(router->vaddr);

    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(root_rport);
    saddr.sin_addr.s_addr = htonl(root_raddr);

    // Wait for approval from tcp same as in clients or just activate
    // imediatelly.

    struct router_connection *new_con =
        create_connection(root_vaddr, root_raddr, root_rport);
    new_con->active = 1;
    set_timers(router, new_con, 10, 30);

    update_routing_table(router, new_con->vaddr, new_con);
    update_routing_table(router, router->network_addr, new_con);

    sendto(router->sockfd, spacket, sizeof(spacket), 0,
           (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

    struct router_event rev;
    rev.type = PEERCONNECTED;
    rev.ptr = NULL;

    write(router->mngr_pipe_fd, &rev, sizeof(struct router_event));
}

void router_setup_pyramid(struct router *router, uint32_t vaddr)
{
    int key = vaddr - router->network_addr;
    int root_key = 0; /* index 0 in routing table holds root host */

    pthread_rwlock_wrlock(&router->routing_table_lock);
    router->routing_table[key] = router->routing_table[root_key];
    pthread_rwlock_unlock(&router->routing_table_lock);
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
    iti.it_value.tv_sec = 30;

    struct router_packet_header *packeth;
    void *packetd;
    struct router_buffer_slot *slot;
    while (1) {

        slot = router_get_free_slot(router); // waiting point

        if (slot == NULL)
            break;

        slot->used_size =
            recvfrom(router->sockfd, slot->buffer, SLOT_SIZE, 0,
                     (struct sockaddr *)&raddr, &slen); // waiting point

        if (slot->used_size < 1) {
            router_add_free_slot(router, slot);
            break;
        }

        packeth = (struct router_packet_header *)slot->buffer;

        if (packeth->type == DATA) {
            packetd = ((struct router_packet_header *)slot->buffer) + 1;

            vaddr = ntohl(((struct iphdr *)packetd)->daddr);
            svaddr = ntohl(((struct iphdr *)packetd)->saddr);

            key = svaddr - router->network_addr;

            pthread_rwlock_rdlock(&router->routing_table_lock);
            timerfd_settime(router->routing_table[key]->rkinfo->timerfd, 0,
                            &iti, NULL);
            pthread_rwlock_unlock(&router->routing_table_lock);

            if (vaddr == router->vaddr) {
                pthread_mutex_lock(&router->recv_buffer_lock);
                DL_APPEND(router->recv_buffer, slot);
                pthread_cond_broadcast(&router->recv_buffer_cond);
                pthread_mutex_unlock(&router->recv_buffer_lock);
            } else {
                router_send(router, slot);
            }
        } else if (packeth->type == KEEPALIVE) {
            struct router_keepalive_payload *rpayload =
                (struct router_keepalive_payload *)ROUTER_PACKET_PAYLOAD(
                    slot->buffer);

            vaddr = ntohl(rpayload->vaddr);
            key = vaddr - router->network_addr;

            pthread_rwlock_rdlock(&router->routing_table_lock);
            timerfd_settime(router->routing_table[key]->rkinfo->timerfd, 0,
                            &iti, NULL);

            pthread_rwlock_unlock(&router->routing_table_lock);

            struct router_connection *pen_con;
            pthread_mutex_lock(&router->pending_connections_lock);
            HASH_FIND_INT(router->pending_connections, &vaddr, pen_con);
            if (pen_con != NULL) {
                HASH_DEL(router->pending_connections, pen_con);
                timerfd_settime(pen_con->rkinfo->timerfd, 0, &iti, NULL);
                update_routing_table(router, pen_con->vaddr, pen_con);
                printf("P2P\n");
            }
            pthread_mutex_unlock(&router->pending_connections_lock);

            router_add_free_slot(router, slot);
        } else if (packeth->type == INIT) {
            struct router_init_payload *payload =
                (struct router_init_payload *)ROUTER_PACKET_PAYLOAD(packeth);

            struct router_connection *new_con = create_connection(
                ntohl(payload->vaddr), ntohl(raddr.sin_addr.s_addr),
                ntohs(raddr.sin_port));
            new_con->active = 1;
            set_timers(router, new_con, 10, 30);

            update_routing_table(router, new_con->vaddr, new_con);

            struct router_action *act = malloc(sizeof(struct router_action));
            act->vaddr = ntohl(payload->vaddr);
            act->raddr = ntohl(raddr.sin_addr.s_addr);
            act->rport = ntohs(raddr.sin_port);

            struct router_event rev;
            rev.type = PEERCONNECTED;
            rev.ptr = act;
            write(router->mngr_pipe_fd, &rev, sizeof(struct router_event));

            router_add_free_slot(router, slot);
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

    void *packeth;
    void *packetd;
    uint32_t vaddr;

    int key;
    struct itimerspec iti;
    memset(&iti, 0, sizeof(struct itimerspec));
    iti.it_interval.tv_sec = 0;
    iti.it_value.tv_sec = 5;

    struct router_buffer_slot *slot_to_send;
    while (1) {

        pthread_rwlock_rdlock(&router->buffer_threads_flag_lock);
        if (router->buffer_threads_flag == 1)
            return NULL;
        pthread_rwlock_unlock(&router->buffer_threads_flag_lock);

        pthread_mutex_lock(&router->send_buffer_lock);
        while (router->send_buffer == NULL) {
            pthread_cond_wait(&router->send_buffer_cond,
                              &router->send_buffer_lock);

            pthread_rwlock_rdlock(&router->buffer_threads_flag_lock);
            if (router->buffer_threads_flag == 1) {
                pthread_rwlock_unlock(&router->buffer_threads_flag_lock);
                pthread_mutex_unlock(&router->send_buffer_lock);
                return NULL;
            }
            pthread_rwlock_unlock(&router->buffer_threads_flag_lock);
        }
        slot_to_send = router->send_buffer;
        DL_DELETE(router->send_buffer, slot_to_send);
        pthread_mutex_unlock(&router->send_buffer_lock);

        packeth = ((struct router_packet_header *)slot_to_send->buffer);
        packetd = ((struct router_packet_header *)slot_to_send->buffer) + 1;

        vaddr = ntohl(((struct iphdr *)packetd)->daddr);

        if (vaddr > router->network_addr && vaddr < router->broadcast_addr) {
            key = vaddr - router->network_addr;
            pthread_rwlock_rdlock(&router->routing_table_lock);
            if (router->routing_table[key] != NULL) {

                saddr.sin_port = htons(router->routing_table[key]->rport);
                saddr.sin_addr.s_addr =
                    htonl(router->routing_table[key]->raddr);

                sendto(router->sockfd, packeth, slot_to_send->used_size, 0,
                       (struct sockaddr *)&saddr, slen);

                timerfd_settime(router->routing_table[key]->skinfo->timerfd, 0,
                                &iti, NULL);
            }
            pthread_rwlock_unlock(&router->routing_table_lock);
        } else if (vaddr == router->broadcast_addr) {
            pthread_rwlock_rdlock(&router->routing_table_lock);
            for (key = 0; key <= router->subnet_size; key++) {
                if (router->routing_table[key] != NULL) {

                    saddr.sin_port = htons(router->routing_table[key]->rport);
                    saddr.sin_addr.s_addr =
                        htonl(router->routing_table[key]->raddr);

                    sendto(router->sockfd, packeth, slot_to_send->used_size, 0,
                           (struct sockaddr *)&saddr, slen);

                    timerfd_settime(router->routing_table[key]->skinfo->timerfd,
                                    0, &iti, NULL);
                }
            }
            pthread_rwlock_unlock(&router->routing_table_lock);
        }

        router_add_free_slot(router, slot_to_send);
    }

    return NULL;
}

static void *keep_alive_worker(void *arg)
{
    struct router *router = (struct router *)arg;

    struct itimerspec iti;
    memset(&iti, 0, sizeof(struct itimerspec));
    iti.it_interval.tv_sec = 0;
    iti.it_value.tv_sec = 5;

    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;

    struct keep_alive_info *kinfo;
    int event_count, i;
    while (1) {
        event_count =
            epoll_wait(router->epoll_fd, router->events, MAX_EVENTS, -1);
        for (i = 0; i < event_count; i++) {
            kinfo = router->events[i].data.ptr;

            pthread_rwlock_rdlock(&kinfo->con_lock);
            if (kinfo->event == KEEPALIVEDIE) {
                close(kinfo->timerfd);
                pthread_rwlock_destroy(&kinfo->con_lock);
                free(kinfo);
                return NULL;
            } else if (kinfo->con == NULL) {
                close(kinfo->timerfd);
                pthread_rwlock_destroy(&kinfo->con_lock);
                free(kinfo);
            } else if (kinfo->event == KEEPALIVESEND) {
                uint64_t timerexps;
                read(kinfo->timerfd, &timerexps, sizeof(uint64_t));

                uint8_t spacket[sizeof(struct router_packet_header) +
                                sizeof(struct router_keepalive_payload)];
                struct router_packet_header *sheader =
                    (struct router_packet_header *)spacket;
                struct router_keepalive_payload *spayload =
                    (struct router_keepalive_payload *)ROUTER_PACKET_PAYLOAD(
                        spacket);
                sheader->type = KEEPALIVE;
                spayload->vaddr = htonl(router->vaddr);

                saddr.sin_port = htons(kinfo->con->rport);
                saddr.sin_addr.s_addr = htonl(kinfo->con->raddr);

                sendto(router->sockfd, &spacket, sizeof(spacket), 0,
                       (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

                timerfd_settime(kinfo->timerfd, 0, &iti, NULL);
            } else if (kinfo->event == KEEPALIVERECV) {
                uint64_t timerexps;
                read(kinfo->timerfd, &timerexps, sizeof(uint64_t));

                struct router_action *act =
                    malloc(sizeof(struct router_action));
                act->vaddr = kinfo->con->vaddr;
                act->raddr = 0;
                act->rport = 0;

                struct router_event rev;
                rev.type = PEERDISCONNECTED;
                rev.ptr = act;

                write(router->mngr_pipe_fd, &rev, sizeof(struct router_event));
            }
            pthread_rwlock_unlock(&kinfo->con_lock);
        }
    }
    return NULL;
}

static void allocate_free_slots(struct router *router, size_t slot_count)
{
    struct router_buffer_slot *slot;
    int s = 0;
    for (int i = 0; i < slot_count; i++) {
        slot = malloc(sizeof(struct router_buffer_slot));
        slot->used_size = 0;
        if (slot != NULL) {
            DL_APPEND(router->free_slots, slot);
            s++;
        }
    }
}

static struct router_connection *
create_connection(uint32_t vaddr, uint32_t raddr, uint16_t rport)
{
    struct router_connection *new_con =
        malloc(sizeof(struct router_connection));
    new_con->vaddr = vaddr;
    new_con->raddr = raddr;
    new_con->rport = rport;
    new_con->active = 0;

    new_con->skinfo = malloc(sizeof(struct keep_alive_info));
    new_con->skinfo->con = new_con;
    new_con->skinfo->event = KEEPALIVESEND;
    pthread_rwlock_init(&new_con->skinfo->con_lock, NULL);
    new_con->skinfo->timerfd = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);

    new_con->rkinfo = malloc(sizeof(struct keep_alive_info));
    new_con->rkinfo->con = new_con;
    new_con->rkinfo->event = KEEPALIVERECV;
    pthread_rwlock_init(&new_con->rkinfo->con_lock, NULL);
    new_con->rkinfo->timerfd = timerfd_create(CLOCK_REALTIME, TFD_CLOEXEC);

    return new_con;
}

void destroy_connection(struct router_connection *con)
{

    struct itimerspec iti;
    memset(&iti, 0, sizeof(struct itimerspec));
    iti.it_value.tv_nsec = 5;
    pthread_rwlock_wrlock(&con->skinfo->con_lock);
    con->skinfo->con = NULL;
    timerfd_settime(con->skinfo->timerfd, 0, &iti, NULL);
    pthread_rwlock_unlock(&con->skinfo->con_lock);

    pthread_rwlock_wrlock(&con->rkinfo->con_lock);
    con->rkinfo->con = NULL;
    timerfd_settime(con->rkinfo->timerfd, 0, &iti, NULL);
    pthread_rwlock_unlock(&con->rkinfo->con_lock);
    free(con);
}

static void set_timers(struct router *router, struct router_connection *con,
                       int send_tv, int recv_tv)
{
    router->event.events = EPOLLIN;
    router->event.data.ptr = con->skinfo;
    epoll_ctl(router->epoll_fd, EPOLL_CTL_ADD, con->skinfo->timerfd,
              &router->event);

    router->event.data.ptr = con->rkinfo;
    epoll_ctl(router->epoll_fd, EPOLL_CTL_ADD, con->rkinfo->timerfd,
              &router->event);

    struct itimerspec iti;
    memset(&iti, 0, sizeof(struct itimerspec));

    iti.it_value.tv_sec = send_tv;
    timerfd_settime(con->skinfo->timerfd, 0, &iti, NULL);

    iti.it_value.tv_sec = recv_tv;
    timerfd_settime(con->rkinfo->timerfd, 0, &iti, NULL);
}

static void update_routing_table(struct router *router, uint32_t vaddr,
                                 struct router_connection *new_con)
{
    int key = vaddr - router->network_addr;

    pthread_rwlock_wrlock(&router->routing_table_lock);
    router->routing_table[key] = new_con;
    pthread_rwlock_unlock(&router->routing_table_lock);
}
