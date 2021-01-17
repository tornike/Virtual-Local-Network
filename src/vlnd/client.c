
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <rxi_log.h>
#include <stddef.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "../router.h"
#include "client.h"
#include "vln_epoll_event.h"
#include "vln_host.h"
#include <vln_types.h>

#define EPOLL_MAX_EVENTS 10

/* Global Variables */
static int _epoll_fd;
static struct vln_host *_hosts; /* should be all hosts in network */
static struct vln_host *_root_host;
static struct vln_network *_network;
static struct router *_router;
static struct vln_adapter *_adapter;
pthread_t _sender, _receiver;

/* Function prototypes */
static void connect_to_server(const uint32_t server_addr,
                              const uint16_t server_port);
static void epoll_register(int fd, vln_descriptor_type desc_type,
                           uint32_t events, vln_epoll_data_t *data);
static void serve_packet(struct vln_host *h);
static void serve_router_event(int pipe_fd);
static void *recv_thread(void *arg);
static void *send_thread(void *arg);
static void handle_host_disconnect(struct vln_host *h);
static void create_socket();

void start_client(const char *network_name, const uint32_t server_addr,
                  const uint16_t server_port, struct vln_adapter *adapter)
{
    _hosts = NULL;

    _network = malloc(sizeof(struct vln_network));
    strcpy(_network->name, network_name);

    _router = NULL;
    _adapter = adapter;

    if ((_root_host = malloc(sizeof(struct vln_host))) == NULL) {
        log_error("failed memory allocation error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    _root_host->udp_addr = server_addr;
    initialize_packet(&_root_host->rpacket);

    _root_host->sock_fd = -1;
    connect_to_server(server_addr, server_port);

    if ((_epoll_fd = epoll_create1(0)) < 0) {
        log_error("failed to create epoll object error:%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    vln_epoll_data_t d = {.ptr = _root_host};
    epoll_register(_root_host->sock_fd, Peer_Socket, EPOLLIN | EPOLLRDHUP, &d);

    //==============SEND CONNECT===============
    do {
        uint8_t spacket[sizeof(struct mngr_packet_header) +
                        sizeof(struct mngr_connect_payload)];
        struct mngr_packet_header *sheader =
            (struct mngr_packet_header *)spacket;
        struct mngr_connect_payload *spayload =
            (struct mngr_connect_payload *)PACKET_PAYLOAD(spacket);
        sheader->type = CONNECT;
        sheader->payload_length = htonl(sizeof(struct mngr_connect_payload));

        strcpy(spayload->network_name, _network->name);

        if (send(_root_host->sock_fd, (void *)spacket, sizeof(spacket), 0) !=
            sizeof(spacket)) {
            log_error("sending CONNECT failed");
            // close connection?
        }
    } while (0);
    //==========================================

    log_trace("starting waiting on epoll");
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
                log_debug("EPOLLRDHUP");
                h = (struct vln_host *)epoll_event->data.ptr;
                handle_host_disconnect(h);
            } else if (events[event_i].events & EPOLLIN) {
                switch (epoll_event->type) {
                case Router_Pipe:
                    serve_router_event(epoll_event->data.fd);
                    break;
                case Peer_Socket:
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

static void connect_to_server(const uint32_t server_addr,
                              const uint16_t server_port)
{
    struct sockaddr_in server_sockaddr;

    memset(&server_sockaddr, 0, sizeof(server_sockaddr));

    create_socket();

    server_sockaddr.sin_family = AF_INET;
    server_sockaddr.sin_addr.s_addr = htonl(server_addr);
    server_sockaddr.sin_port = htons(server_port);

    unsigned int sleep_secs = 10;
    while (connect(_root_host->sock_fd, (struct sockaddr *)&server_sockaddr,
                   sizeof(struct sockaddr)) < 0) {
        log_warn("failed connecting to server, retrying in %u seconds",
                 sleep_secs);
        sleep(sleep_secs);
        sleep_secs = sleep_secs + 10 > 30 ? 30 : sleep_secs + 10;
    }
    log_trace("connected to the server");
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
        log_error("failed to add descriptor to the epoll error:%s",
                  strerror(errno));
        exit(EXIT_FAILURE);
    }
}

static void serve_packet(struct vln_host *h)
{
    log_trace("serving packet");
    if (h->rpacket.header->type == UPDATES) {
        log_trace("received UPDATES packet");
        struct mngr_update_payload *rpayload =
            (struct mngr_update_payload *)h->rpacket.payload;

        router_try_connection(_router, ntohl(rpayload->vaddr),
                              ntohl(rpayload->raddr), ntohs(rpayload->rport));

        router_setup_pyramid(_router, ntohl(rpayload->vaddr));

    } else if (h->rpacket.header->type == UPDATEDIS) {
        log_trace("received UPDATEDIS packet");
        struct mngr_updatedis_payload *rpayload =
            (struct mngr_updatedis_payload *)h->rpacket.payload;

        router_remove_connection(_router, ntohl(rpayload->vaddr));
    } else if (h->rpacket.header->type == ROOTHOST) {
        log_trace("received ROOTHOST packet");
        struct mngr_roothost_payload *rpayload =
            (struct mngr_roothost_payload *)h->rpacket.payload;

        _root_host->vaddr = ntohl(rpayload->vaddr);
        _root_host->udp_port = ntohs(rpayload->rport);

        router_send_init(_router, _root_host->vaddr, _root_host->udp_addr,
                         _root_host->udp_port);
    } else if (h->rpacket.header->type == NETWORK) {
        log_trace("received NETWORK packet");
        struct mngr_network_payload *rpayload =
            (struct mngr_network_payload *)h->rpacket.payload;

        uint32_t vaddr = ntohl(rpayload->vaddr);

        _network->address = ntohl(rpayload->addr);
        _network->broadcast_address = ntohl(rpayload->broadaddr);
        _network->mask_address = ntohl(rpayload->maskaddr);

        int router_sockfd;
        if ((router_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            log_error("failed to open socket error: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        int pipe_fds[2];
        if (pipe(pipe_fds) != 0) {
            log_error("error occured during serving NETWORK packet error: %s",
                      strerror(errno));
            log_debug("failed to open pipe for the router error: %s",
                      strerror(errno));
            exit(EXIT_FAILURE);
        }

        _router =
            router_create(vaddr, _network->address, _network->broadcast_address,
                          router_sockfd, pipe_fds[1]);

        vln_epoll_data_t d = {.fd = pipe_fds[0]};
        epoll_register(pipe_fds[0], Router_Pipe, EPOLLIN, &d);

        vln_adapter_set_network2(_adapter, _network, vaddr);

        pthread_create(&_receiver, NULL, recv_thread, NULL);
        pthread_create(&_sender, NULL, send_thread, NULL);

    } else if (h->rpacket.header->type == ERROR) {
        struct mngr_error_payload *rpayload =
            (struct mngr_error_payload *)h->rpacket.payload;
        log_error("received error from server errorcode: %d", rpayload->type);
        // send_starter_response(starter_tcpwrapper, rpayload.type);
    } else {
        log_error("received unknown packet");
        exit(EXIT_FAILURE);
    }
}

static void serve_router_event(int pipe_fd)
{
    struct router_event rev;
    read(pipe_fd, &rev, sizeof(struct router_event));

    log_info("serving router event");
    if (rev.type == PEERDISCONNECTED) {
        log_info("recieved PEERDISCONNECTED event");
        struct router_action *act = (struct router_action *)rev.ptr;
        if (act->vaddr == _root_host->vaddr) {
            // TODO: retry connection
        } else {
            router_setup_pyramid(_router, act->vaddr);
        }
        free(act);
    }
}

static void handle_host_disconnect(struct vln_host *h)
{
    log_info("handling host diconnect");

    epoll_ctl(_epoll_fd, EPOLL_CTL_DEL, h->sock_fd, NULL);

    router_stop(_router);

    pthread_cancel(_sender);
    pthread_cancel(_receiver);

    pthread_join(_receiver, NULL);
    pthread_join(_sender, NULL);

    router_destroy(_router);

    vln_adapter_destroy(_adapter);

    exit(EXIT_SUCCESS);
}

static void cleanup_handler(void *arg)
{
    struct router_buffer_slot *slot = (struct router_buffer_slot *)arg;
    router_add_free_slot(_router, slot);
}

static void *recv_thread(void *arg)
{
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    struct router_buffer_slot *slot;
    while (true) {
        slot = router_receive(_router); // waiting point

        if (slot == NULL)
            break;

        pthread_cleanup_push(cleanup_handler, slot);

        write(_adapter->fd, slot->buffer + sizeof(struct router_packet_header),
              slot->used_size - sizeof(struct router_packet_header));

        pthread_cleanup_pop(0);

        router_add_free_slot(_router, slot);
    }
    return NULL;
}

static void *send_thread(void *arg)
{
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    struct router_buffer_slot *slot;
    while (true) {
        slot = router_get_free_slot(_router); // waiting point

        if (slot == NULL)
            break;

        pthread_cleanup_push(cleanup_handler, slot);

        slot->used_size = read(
            _adapter->fd, slot->buffer + sizeof(struct router_packet_header),
            SLOT_SIZE -
                sizeof(struct router_packet_header)); // Cancelation point.

        pthread_cleanup_pop(0);

        if (slot->used_size < 1) {
            router_add_free_slot(_router, slot);
            break;
        }

        slot->used_size += sizeof(struct router_packet_header);
        ((struct router_packet_header *)slot->buffer)->type = DATA;
        router_send(_router, slot);
    }
    return NULL;
}

static void create_socket()
{
    if (_root_host->sock_fd != -1)
        close(_root_host->sock_fd);

    if ((_root_host->sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        log_error("failed to create socket error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    int optval = 1;
    if (setsockopt(_root_host->sock_fd, SOL_SOCKET, SO_KEEPALIVE, &optval,
                   sizeof(int)) < 0) {
        log_error("setting socket options failed - %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
}
