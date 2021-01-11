
#include <arpa/inet.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "../vlnctl_protocol.h"
#include "client.h"
#include "server.h"
#include <rxi_log.h>
#include <uthash.h>
#include <vln_adapter.h>
#include <vln_default_config.h>
#include <vln_epoll_event.h>

#define ACCEPT_BACKLOG 5
#define EPOLL_MAX_EVENTS 10
#define TEST_NETWORK_NAME "test_network"

struct vlnctl_peer {
    int sock_fd;

    struct vlnctl_packet_header packet_header;
    union vlnctl_packet_payload packet_payload;
};

struct vlnd_server {
    pid_t child_pid;

    char network_name[NETWORK_NAME_MAX_LENGTH];
    uint32_t network_addr;
    uint32_t mask_addr;
    uint32_t host_addr;
    uint16_t host_port;

    UT_hash_handle hh;
};

struct vlnd_client {
    pid_t child_pid;

    char network_name[NETWORK_NAME_MAX_LENGTH];
    uint32_t raddr;
    uint16_t rport;

    UT_hash_handle hh;
};

/* Function prorotypes */
static void init();
static int open_ctl_socket();
static void epoll_register(int fd, vln_descriptor_type desc_type,
                           uint32_t events, vln_epoll_data_t *data);
static void accept_connection(int listening_sock);
static void serve_packet(struct vlnctl_peer *peer);
static void start_client_process(char *network_name, uint32_t raddr,
                                 uint16_t rport);
static void start_server_process(char *network_name, uint32_t network_addr,
                                 uint32_t mask_addr, uint32_t host_addr,
                                 uint16_t host_port);

/* Global Variables */
static FILE *_log_file;
struct vln_network *_network;
static int _epoll_fd;
static struct vlnd_client *_vlnd_clients;
static struct vlnd_server *_vlnd_servers;

struct vln_network *test_network_for_server()
{
    struct vln_network *network = malloc(sizeof(struct vln_network));

    inet_pton(AF_INET, "172.6.2.0", &network->address);
    network->address = ntohl(network->address);

    inet_pton(AF_INET, "172.6.2.255", &network->broadcast_address);
    network->broadcast_address = ntohl(network->broadcast_address);

    inet_pton(AF_INET, "255.255.255.0", &network->mask_address);
    network->mask_address = ntohl(network->mask_address);

    strcpy(network->name, TEST_NETWORK_NAME);
    _network = network;
    return network;
}

uint32_t test_addr_for_client()
{
    uint32_t addr;
    inet_pton(AF_INET, "192.168.33.17", &addr);
    addr = ntohl(addr);
    return addr;
}

int test_socket_for_server(uint16_t port)
{
    int sfd;
    struct sockaddr_in s_addr;
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    s_addr.sin_family = AF_INET;
    s_addr.sin_port = htons(port);
    s_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sfd, (struct sockaddr *)&s_addr, sizeof(struct sockaddr_in)) !=
        0) {
        log_error("bind failed");
        exit(EXIT_FAILURE);
    }
    return sfd;
}

struct vln_adapter *test_adapter(const char *name)
{
    struct vln_adapter *adapter = vln_adapter_create(name);
    return adapter;
}

int main(int argc, char **argv)
{
    _vlnd_clients = NULL;
    _vlnd_servers = NULL;

    int ctl_listening_sock;

    init();
    ctl_listening_sock = open_ctl_socket();

    if ((_epoll_fd = epoll_create1(0)) < 0) {
        log_error("failed to create epoll object error:%s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    epoll_register(ctl_listening_sock, Listen_Socket, EPOLLIN, NULL);

    if (listen(ctl_listening_sock, ACCEPT_BACKLOG) < 0) {
        log_error("failed starting listening to the unix socket error: %s",
                  strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct epoll_event events[EPOLL_MAX_EVENTS];
    int event_count, event_i;
    struct vlnctl_peer *peer;
    while (true) {
        event_count = epoll_wait(_epoll_fd, events, EPOLL_MAX_EVENTS, -1);
        for (event_i = 0; event_i < event_count; event_i++) {
            struct vln_epoll_event *epoll_event =
                (struct vln_epoll_event *)events[event_i].data.ptr;

            if (events[event_i].events & EPOLLRDHUP) {
                /*
                 * EPOLLRDHUP is registered only for hosts.
                 */
                // h = (struct vln_host *)epoll_event->data.ptr;
                // handle_host_disconnect(h);
            } else if (events[event_i].events & EPOLLIN) {
                switch (epoll_event->type) {
                case Listen_Socket:
                    accept_connection(ctl_listening_sock);
                    break;
                case Peer_Socket:
                    peer = (struct vlnctl_peer *)epoll_event->data.ptr;
                    ssize_t read_bytes =
                        recv(peer->sock_fd, &peer->packet_header,
                             sizeof(struct vlnctl_packet_header), MSG_DONTWAIT);
                    if (read_bytes != sizeof(struct vlnctl_packet_header)) {
                        log_error(
                            "packet_status: error reading socket error: %s",
                            strerror(errno));
                        exit(EXIT_FAILURE);
                    }
                    read_bytes =
                        recv(peer->sock_fd, &peer->packet_payload,
                             sizeof(union vlnctl_packet_payload), MSG_DONTWAIT);
                    if (read_bytes != sizeof(union vlnctl_packet_payload)) {
                        log_error(
                            "packet_status: error reading socket 2 error: %s",
                            strerror(errno));
                        exit(EXIT_FAILURE);
                    }
                    serve_packet(peer);
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

    return 0;
}

static void init()
{
    if (mkdir(VLN_RUN_DIR, 0755) != 0 && errno != EEXIST) {
        log_error("could not create directory %s error: %s", VLN_RUN_DIR,
                  strerror(errno));
        exit(EXIT_FAILURE);
    }

    // change dir owner

    if (mkdir(VLN_LOG_DIR, 0755) != 0 && errno != EEXIST) {
        log_error("could not create directory %s error: %s", VLN_RUN_DIR,
                  strerror(errno));
        exit(EXIT_FAILURE);
    }

    // change dir owner

#ifndef DEVELOP
    struct passwd *pwd;
    struct group *grp;
    if (getpwnam(VLN_USER) == NULL) {
        log_error("failed to get info about user %s", VLN_USER);
        exit(EXIT_FAILURE);
    }
    if (getgrnam(VLN_USER) == NULL) {
        log_error("failed to get info about group %s", VLN_USER);
        exit(EXIT_FAILURE);
    }
#endif

    // Maybe not in this function
    if ((_log_file = fopen(VLN_LOG_FILE, "w+")) == NULL) {
        log_error("failed to open file %s error: %s", VLN_LOG_FILE,
                  strerror(errno));
        exit(EXIT_FAILURE);
    }
    log_trace("%s file opened successfully", VLN_LOG_FILE);

    // change file owner
}

/* Opens Unix socket to listen to vlnctl connections */
static int open_ctl_socket()
{
    int ctl_listening_sock;
    struct sockaddr_un addr_un;

    if ((ctl_listening_sock = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        log_error("failed to open unix socket error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    memset(&addr_un, 0, sizeof(addr_un));
    addr_un.sun_family = AF_UNIX;
    strcpy(addr_un.sun_path, VLN_SOCK_FILE);

    unlink(VLN_SOCK_FILE);
    if (bind(ctl_listening_sock, (struct sockaddr *)&addr_un,
             sizeof(struct sockaddr_un)) < 0) {
        log_error("failed to bind the unix socket error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    return ctl_listening_sock;
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

static void serve_packet(struct vlnctl_peer *peer)
{
    if (peer->packet_header.type == CONNECT) {
        log_trace("received CONNECT packet");
        struct vlnctl_connect_payload *payload =
            &peer->packet_payload.connect_payload;

        // check if already connected

        start_client_process(payload->network_name, payload->raddr,
                             payload->rport);

    } else if (peer->packet_header.type == CREATE) {
        log_trace("received CREATE packet");
        struct vlnctl_create_payload *payload =
            &peer->packet_payload.create_payload;

        // check if already hosted

        start_server_process(payload->network_name, payload->network_addr,
                             payload->mask_addr, payload->host_addr,
                             payload->host_port);
    } else {
        log_error("received unknown packet");
        /* Must be handled somehow but process shouldn't die */
        // exit(EXIT_FAILURE);
    }
}

static void accept_connection(int listening_sock)
{
    int client_fd;

    if ((client_fd = accept(listening_sock, NULL, NULL)) < 0) {
        log_warn("failed to accept incoming connection error:%s",
                 strerror(errno));
    } else {
        struct vlnctl_peer *peer = malloc(sizeof(struct vlnctl_peer));
        vln_epoll_data_t d = {.ptr = peer};
        epoll_register(client_fd, Peer_Socket, EPOLLIN | EPOLLRDHUP, &d);
        log_info("accepted new vlnctl connection");
    }
}

static void start_client_process(char *network_name, uint32_t raddr,
                                 uint16_t rport)
{
    struct vlnd_client *c = malloc(sizeof(struct vlnd_client));
    strcpy(c->network_name, network_name);
    c->raddr = raddr;
    c->rport = rport;

    pid_t child_pid;
    if ((child_pid = fork()) < 0) {
        log_error("error occured during creation of the child process");
        log_debug("fork failed error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    } else if (child_pid > 0) {
        log_trace("child with %lu created", child_pid);

        c->child_pid = child_pid;
        HASH_ADD_STR(_vlnd_clients, network_name, c);
    } else {
        log_trace("logging from child process");

        start_client(c->network_name, c->raddr, c->rport,
                     vln_adapter_create(c->network_name));

        // if (strcmp(argv[1], "s") == 0)
        //     start_server(test_network_for_server(), test_socket_for_server(),
        //                  test_adapter(TEST_NETWORK_NAME));
        // else if (strcmp(argv[1], "c") == 0)
        //     start_client(TEST_NETWORK_NAME, test_addr_for_client(), 33508,
        //                  test_adapter(TEST_NETWORK_NAME));
        // else
        //     exit(EXIT_FAILURE);
    }
}

static void start_server_process(char *network_name, uint32_t network_addr,
                                 uint32_t mask_addr, uint32_t host_addr,
                                 uint16_t host_port)
{
    struct vlnd_server *s = malloc(sizeof(struct vlnd_server));
    strcpy(s->network_name, network_name);
    s->host_addr = host_addr;
    s->host_port = host_port;
    s->network_addr = network_addr;
    s->mask_addr = mask_addr;

    pid_t child_pid;
    if ((child_pid = fork()) < 0) {
        log_error("error occured during creation of the child process");
        log_debug("fork failed error: %s", strerror(errno));
        exit(EXIT_FAILURE);
    } else if (child_pid > 0) {
        log_trace("child with %lu created", child_pid);

        s->child_pid = child_pid;
        HASH_ADD_STR(_vlnd_servers, network_name, s);
    } else {
        log_trace("logging from child process");
        struct vln_network *network = malloc(sizeof(struct vln_network));
        network->address = network_addr;
        network->mask_address = mask_addr;
        network->broadcast_address = network_addr + 255; // TODO: Temp
        strcpy(network->name, network_name);

        start_server(network, test_socket_for_server(s->host_port),
                     vln_adapter_create(s->network_name));
    }
}