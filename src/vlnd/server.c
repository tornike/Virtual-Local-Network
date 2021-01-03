
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <rxi_log.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <vln_constants.h>

#include "../lib/protocol.h"
#include "../lib/taskexecutor.h"
#include "../router.h"
#include "npb_manager.h"
#include "server.h"
#include "vln_epoll_event.h"
#include <uthash.h>

#define EPOLL_MAX_EVENTS 10
#define ACCEPT_BACKLOG 10

struct vln_host {
    uint32_t vaddr;
    uint32_t udp_addr;
    uint32_t udp_port;
    int sock_fd;

    struct mngr_packet_status rpacket;

    UT_hash_handle hh;
};

/* Global Variables */
static int _epoll_fd;
static struct vln_host *_hosts;
static struct vln_host *_root_host;
static struct vln_network *_network;
static struct router *_router;

void router_listener(void *args, struct task_info *tinfo)
{
    int pipe_fd = (int)args;

    write(pipe_fd, tinfo, sizeof(struct task_info));
}

static uint32_t get_available_address()
{
    struct vln_host *h;
    for (int vaddr = _network->address + 1; vaddr < _network->broadcast_address;
         vaddr++) {
        HASH_FIND_INT(_hosts, &vaddr, h);
        if (h == NULL) {
            return vaddr;
        }
    }
    return 0;
}

static void epoll_register(int fd, vln_descriptor_type desc_type,
                           uint32_t events, vln_epoll_data_t *data)
{
    /* TODO: Is not freed yet, memory leak !!! */
    struct vln_epoll_event *epoll_event =
        malloc(sizeof(struct vln_epoll_event));
    epoll_event->type = desc_type;
    if (data != NULL)
        epoll_event->data = *data;

    struct epoll_event event;
    event.events = events;
    event.data.ptr = epoll_event;

    if (epoll_ctl(_epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0) {
        log_error("Server: Failed to add descriptor to the epoll error:%s",
                  strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static struct vln_host *create_host(int fd)
{
    /* TODO:
     * Must be changed
     * Do after INIT not after accept
     */
    struct vln_host *h = malloc(sizeof(struct vln_host));

    h->sock_fd = fd;
    h->vaddr = get_available_address();
    h->udp_addr = 0;
    h->udp_port = 0;
    initialize_packet(&h->rpacket);

    HASH_ADD_INT(_hosts, vaddr, h);

    return h;
}

void destroy_host(struct vln_host *h)
{
    HASH_DEL(_hosts, h);
    close(h->sock_fd);
    free(h);
}

static void send_error(vln_packet_type type, int sock_fd)
{
    uint8_t serror[sizeof(struct vln_packet_header) +
                   sizeof(struct vln_error_payload)];
    memset(serror, 0, sizeof(serror));
    struct vln_packet_header *sheader = (struct vln_packet_header *)serror;
    sheader->payload_length = htonl(sizeof(struct vln_error_payload));
    sheader->type = ERROR;
    struct vln_error_payload *spayload =
        (struct vln_error_payload *)PACKET_PAYLOAD(serror);
    spayload->type = type;

    if (send(sock_fd, (void *)serror, sizeof(serror), 0) != sizeof(serror)) {
        log_error("failed to send error ");
    }
}

static void accept_connection(int listening_sock)
{
    int client_fd;
    struct sockaddr_in c_addr;
    socklen_t sockaddr_in_size = sizeof(struct sockaddr_in);

    if ((client_fd = accept(listening_sock, (struct sockaddr *)&c_addr,
                            &sockaddr_in_size)) < 0) {
        log_warn("failed to accept incoming connection error:%s",
                 strerror(errno));
    } else {
        vln_epoll_data_t d = {.ptr = create_host(client_fd)};
        epoll_register(client_fd, Host_Socket, EPOLLIN | EPOLLRDHUP, &d);
        log_info("accepted new connection");
    }
}

static void handle_host_disconnect(struct vln_host *h)
{
    log_info("handling host diconnect");
    router_remove_connection(_router, h->vaddr);
    epoll_ctl(_epoll_fd, EPOLL_CTL_DEL, h->sock_fd, NULL);

    //==============SEND PeerDisconnected===============
    do {
        uint8_t spacket[sizeof(struct vln_packet_header) +
                        sizeof(struct vln_updatedis_payload)];
        struct vln_packet_header *sheader = (struct vln_packet_header *)spacket;
        struct vln_updatedis_payload *spayload =
            (struct vln_updatedis_payload *)PACKET_PAYLOAD(spacket);
        sheader->type = UPDATEDIS;
        sheader->payload_length = htonl(sizeof(struct vln_updatedis_payload));
        spayload->vaddr = htonl(h->vaddr);

        struct vln_host *elem;
        for (elem = _hosts; elem != NULL;
             elem = (struct vln_host *)(elem->hh.next)) {
            if (elem == _root_host)
                continue;
            if (send(elem->sock_fd, (void *)spacket,
                     sizeof(struct vln_packet_header) +
                         sizeof(struct vln_updatedis_payload),
                     0) != sizeof(spacket)) {
                log_error("failed to send PEERCONNECTED 1 error: %s",
                          strerror(errno));
                exit(EXIT_FAILURE);
            }
        }
    } while (0);
    //==========================================

    destroy_host(h);
}

static void serve_packet(struct vln_host *h)
{
    if (h->rpacket.header->type == CONNECT) {
        log_trace("received connect packet");
        struct vln_connect_payload *payload =
            (struct vln_connect_payload *)payload;

        if (strcmp((const char *)_network->name, payload->network_name) != 0) {
            send_error(NAME_OR_PASSWOR, h->sock_fd);
            return;
        }
        //==============SEND INIT===============
        do {
            uint8_t spacket[sizeof(struct vln_packet_header) +
                            sizeof(struct vln_init_payload)];
            struct vln_packet_header *sheader =
                (struct vln_packet_header *)spacket;
            struct vln_init_payload *spayload =
                (struct vln_init_payload *)PACKET_PAYLOAD(spacket);
            sheader->type = INIT;
            sheader->payload_length = htonl(sizeof(struct vln_init_payload));
            spayload->vaddr = htonl(h->vaddr);
            spayload->maskaddr = htonl(_network->mask_address);
            spayload->broadaddr = htonl(_network->broadcast_address);

            if (send(h->sock_fd, (void *)spacket, sizeof(spacket), 0) !=
                sizeof(spacket)) {
                log_error("INIT Send Failed");
            }
        } while (0);
        //==========================================

        //==============SEND ROOTNODE===============
        do {
            uint8_t spacket[sizeof(struct vln_packet_header) +
                            sizeof(struct vln_rootnode_payload)];
            struct vln_packet_header *sheader =
                (struct vln_packet_header *)spacket;
            struct vln_rootnode_payload *spayload =
                (struct vln_rootnode_payload *)PACKET_PAYLOAD(spacket);
            sheader->type = ROOTNODE;
            sheader->payload_length =
                htonl(sizeof(struct vln_rootnode_payload));
            spayload->vaddr = htonl(_network->address);
            inet_pton(AF_INET, "192.168.33.17", &spayload->raddr);
            spayload->rport = htons(_root_host->udp_port);

            if (send(h->sock_fd, (void *)spacket, sizeof(spacket), 0) !=
                sizeof(spacket)) {
                log_error("ROOTNODE Send Failed");
            }
        } while (0);
        log_info("rootnode Sent");
        //=========================================
    } else if (h->rpacket.header->type == UPDATES) {
        log_trace("received updates packet");
        // TODO:
        // uint8_t *spacket = malloc(sizeof(struct vln_packet_header) +
        //                           ntohl(h->rpacket.header->payload_length));
        // memcpy(spacket, &h->rpacket, sizeof(struct vln_packet_header));
        // memcpy(PACKET_PAYLOAD(spacket), &h->rpacket.payload,
        //        ntohl(h->rpacket.header->payload_length));
    } else {
        log_error("received unknown packet");
        exit(EXIT_FAILURE);
    }
}

static void serve_router_event(int pipe_fd)
{
    struct task_info tinfo;
    read(pipe_fd, &tinfo, sizeof(struct task_info));

    log_info("serving router event");
    if (tinfo.operation == PEERCONNECTED) {
        struct router_action *act = (struct router_action *)tinfo.args;

        struct vln_host *curr_host;
        HASH_FIND_INT(_hosts, &act->vaddr, curr_host);
        if (curr_host != NULL) {
            curr_host->udp_addr = act->raddr; // Lock needed?
            curr_host->udp_port = act->rport;

            uint8_t spacket_to_curr[sizeof(struct vln_packet_header) +
                                    sizeof(struct vln_updates_payload)];
            struct vln_packet_header *stcheader =
                (struct vln_packet_header *)spacket_to_curr;
            struct vln_updates_payload *stcpayload =
                (struct vln_updates_payload *)PACKET_PAYLOAD(spacket_to_curr);
            stcheader->type = UPDATES;
            stcheader->payload_length =
                htonl(sizeof(struct vln_updates_payload));
            stcpayload->svaddr = htonl(_network->address); // TODO:
            stcpayload->dvaddr = htonl(curr_host->vaddr);

            uint8_t spacket_to_others[sizeof(struct vln_packet_header) +
                                      sizeof(struct vln_updates_payload)];
            struct vln_packet_header *stoheader =
                (struct vln_packet_header *)spacket_to_others;
            struct vln_updates_payload *stopayload =
                (struct vln_updates_payload *)PACKET_PAYLOAD(spacket_to_others);
            stoheader->type = UPDATES;
            stoheader->payload_length =
                htonl(sizeof(struct vln_updates_payload));
            stopayload->svaddr = htonl(_network->address);
            stopayload->vaddr = htonl(act->vaddr);
            stopayload->raddr = htonl(act->raddr);
            stopayload->rport = htons(act->rport);

            struct vln_host *elem;
            for (elem = _hosts; elem != NULL;
                 elem = (struct vln_host *)(elem->hh.next)) {
                if (elem->udp_addr != 0 && elem->udp_port != 0 &&
                    elem != curr_host) {

                    stopayload->dvaddr = htonl(elem->vaddr);

                    if (send(elem->sock_fd, (void *)spacket_to_others,
                             sizeof(struct vln_packet_header) +
                                 sizeof(struct vln_updates_payload),
                             0) != sizeof(struct vln_packet_header) +
                                       sizeof(struct vln_updates_payload)) {
                        log_error("failed to send PEERCONNECTED 1");
                        exit(EXIT_FAILURE);
                    }

                    stcpayload->vaddr = htonl(elem->vaddr);
                    stcpayload->raddr = htonl(elem->udp_addr);
                    stcpayload->rport = htons(elem->udp_port);
                    if (send(curr_host->sock_fd, (void *)spacket_to_curr,
                             sizeof(struct vln_packet_header) +
                                 sizeof(struct vln_updates_payload),
                             0) != sizeof(struct vln_packet_header) +
                                       sizeof(struct vln_updates_payload)) {
                        log_error("failed to send PEERCONNECTED 2");
                        exit(EXIT_FAILURE);
                    }
                }
            }
        }
        free(act);
    } else if (tinfo.operation == PEERDISCONNECTED) {
        struct router_action *act = (struct router_action *)tinfo.args;

        struct vln_host *curr_host;
        HASH_FIND_INT(_hosts, &act->vaddr, curr_host);
        if (curr_host != NULL) {
            // tcpwrapper_set_die_flag(curr_con->tcpwrapper); //TODO:
        }

        free(act);
    }
}

static int create_router()
{
    struct vln_host *root_host;
    struct sockaddr_in udp_addr;
    int router_sockfd;
    socklen_t socklen = sizeof(struct sockaddr_in);

    memset(&udp_addr, 0, socklen);
    udp_addr.sin_family = AF_INET;
    udp_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    udp_addr.sin_port = 0;

    if ((router_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        log_error("failed to open socket error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (bind(router_sockfd, (struct sockaddr *)&udp_addr,
             sizeof(struct sockaddr_in)) < 0) {
        log_error("failed to bind the socket error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (getsockname(router_sockfd, (struct sockaddr *)&udp_addr, &socklen) <
        0) {
        log_error("failed to get the socket name error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if ((root_host = malloc(sizeof(struct vln_host))) == NULL) {
        log_error("failed memory allocation error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    root_host->vaddr = get_available_address();
    root_host->udp_addr = 0;
    root_host->udp_port = ntohs(udp_addr.sin_port);
    root_host->sock_fd = -1;

    HASH_ADD_INT(_hosts, vaddr, root_host);

    int pipe_fds[2];
    pipe(pipe_fds);

    struct taskexecutor *rlistener =
        taskexecutor_create((Handler)&router_listener, pipe_fds[1]);
    taskexecutor_start(rlistener);

    _root_host = root_host;
    _router =
        router_create(_network->address, _network->address,
                      _network->broadcast_address, router_sockfd, rlistener);

    return pipe_fds[0];
}

void start_server(struct vln_network *network, const int nic_fd,
                  const int listening_sock)
{
    _network = network;
    _hosts = NULL;
    int pipe_fd = create_router();

    if ((_epoll_fd = epoll_create1(0)) < 0) {
        log_error("failed to create epoll file descriptor error:%s",
                  strerror(errno));
        exit(EXIT_FAILURE);
    }

    epoll_register(listening_sock, Listen_Socket, EPOLLIN, NULL);
    vln_epoll_data_t d = {.fd = pipe_fd};
    epoll_register(pipe_fd, Router_Pipe, EPOLLIN, &d);

    listen(listening_sock, ACCEPT_BACKLOG);

    struct epoll_event events[EPOLL_MAX_EVENTS];
    int event_count, event_i;
    struct vln_host *h;
    while (true) {
        event_count = epoll_wait(_epoll_fd, events, EPOLL_MAX_EVENTS, -1);
        for (event_i = 0; event_i < event_count; event_i++) {
            struct vln_epoll_event *epoll_event =
                (struct vln_epoll_event *)events[event_i].data.ptr;

            if (events[event_i].events & EPOLLRDHUP) {
                /*
                 * EPOLLRDHUP is registered only for hosts.
                 */
                h = (struct vln_host *)epoll_event->data.ptr;
                handle_host_disconnect(h);
            } else if (events[event_i].events & EPOLLIN) {
                switch (epoll_event->type) {
                case Listen_Socket:
                    accept_connection(listening_sock);
                    break;
                case Router_Pipe:
                    serve_router_event(epoll_event->data.fd);
                    break;
                case Host_Socket:
                    h = (struct vln_host *)epoll_event->data.ptr;
                    read_packet(h->sock_fd, &h->rpacket);
                    if (h->rpacket.state != Ready)
                        continue;
                    serve_packet(h);
                    reset_packet(&h->rpacket);
                    break;
                default:
                    log_error("unknown vln epoll event");
                    exit(EXIT_FAILURE);
                }
            } else {
                log_error("incorrect epoll event");
                exit(EXIT_FAILURE);
            }
        }
    }
}
