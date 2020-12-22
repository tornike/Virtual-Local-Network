#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <json-c/json.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "../../lib/protocol.h"
#include "../../lib/taskexecutor.h"
#include "../../lib/tcpwrapper.h"
#include "../router.h"
#include "starterprotocol.h"
#include "vlnadapter.h"

#include <uthash.h>

struct vln_interface {
    uint32_t address;
    uint32_t mask_address;
    uint32_t broadcast_address;
    uint8_t network_bits;

    struct tcpwrapper *server_connection;

    struct router *router;

    struct vln_adapter *adapter;

    pthread_t sender;
    pthread_t receiver;

    UT_hash_handle hh;
};

struct cleanup_handler_arg {
    struct vln_interface *vln_int;
    struct router_buffer_slot *slot;
};

/* Prototypes */
static struct vln_interface *create_interface(uint32_t addr_be,
                                              uint32_t broad_addr_be,
                                              uint32_t mask_addr_be,
                                              struct tcpwrapper *wrap);
static void destroy_interface(struct vln_interface *vln_int);

//===========GLOBALS===========
char *_installation_dir;
char *_server_addr;
int _server_port_temp;
struct vln_interface *_vln_interfaces;
pthread_t _worker;
pthread_mutex_t _interface_lock;
//===========GLOBALS===========

void router_listener(void *args, struct task_info *tinfo)
{
    struct vln_interface *vln_int = (struct vln_interface *)args;

    if (tinfo->operation == PEERDISCONNECTED) {
        struct router_action *act = (struct router_action *)tinfo->args;
        if (act->vaddr == (vln_int->address & vln_int->mask_address)) {
            tcpwrapper_set_die_flag(vln_int->server_connection);
        } else {
            router_setup_pyramid(vln_int->router, act->vaddr);
        }
        free(act);
    }
}

static void cleanup_handler(void *arg)
{
    struct cleanup_handler_arg *cha = (struct cleanup_handler_arg *)arg;
    router_add_free_slot(cha->vln_int->router, cha->slot);
    free(cha);
}

void *recv_thread(void *arg)
{
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    struct cleanup_handler_arg *cha =
        malloc(sizeof(struct cleanup_handler_arg));
    cha->vln_int = (struct vln_interface *)arg;
    while (1) {
        cha->slot = router_receive(cha->vln_int->router); // waiting point

        if (cha->slot == NULL)
            break;

        pthread_cleanup_push(cleanup_handler, cha);

        write(cha->vln_int->adapter->fd,
              cha->slot->buffer + sizeof(struct vln_data_packet_header),
              cha->slot->used_size - sizeof(struct vln_data_packet_header));

        pthread_cleanup_pop(0);

        router_add_free_slot(cha->vln_int->router, cha->slot);
    }
    free(cha);
    return NULL;
}

void *send_thread(void *arg)
{
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);

    struct cleanup_handler_arg *cha =
        malloc(sizeof(struct cleanup_handler_arg));
    cha->vln_int = (struct vln_interface *)arg;
    while (1) {
        cha->slot = router_get_free_slot(cha->vln_int->router); // waiting point

        if (cha->slot == NULL)
            break;

        pthread_cleanup_push(cleanup_handler, cha);

        cha->slot->used_size = read(
            cha->vln_int->adapter->fd,
            cha->slot->buffer + sizeof(struct vln_data_packet_header),
            SLOT_SIZE -
                sizeof(struct vln_data_packet_header)); // Cancelation point.

        pthread_cleanup_pop(0);

        if (cha->slot->used_size < 1) {
            router_add_free_slot(cha->vln_int->router, cha->slot);
            break;
        }

        cha->slot->used_size += sizeof(struct vln_data_packet_header);
        ((struct vln_data_packet_header *)cha->slot->buffer)->type = DATA;
        router_send(cha->vln_int->router, cha->slot);
    }
    free(cha);
    return NULL;
}

void *manager_worker(void *arg)
{
    struct vln_interface *vln_int = (struct vln_interface *)arg;
    struct vln_packet_header rpacket;

    while (1) {
        if (recv_wrap(vln_int->server_connection, (void *)&rpacket,
                      sizeof(struct vln_packet_header)) != 0) {
            break;
        }
        if (rpacket.type == ROOTNODE) {
            struct vln_rootnode_payload rpayload;
            if (recv_wrap(vln_int->server_connection, (void *)&rpayload,
                          sizeof(struct vln_rootnode_payload)) != 0) {
                break;
            }

            router_send_init(vln_int->router, ntohl(rpayload.raddr),
                             ntohs(rpayload.rport));

        } else if (rpacket.type == UPDATES) {
            struct vln_updates_payload rpayload;
            if (recv_wrap(vln_int->server_connection, (void *)&rpayload,
                          sizeof(struct vln_updates_payload)) != 0) {
                break;
            }

            router_try_connection(vln_int->router, ntohl(rpayload.vaddr),
                                  ntohl(rpayload.raddr), ntohs(rpayload.rport));

            router_setup_pyramid(vln_int->router, ntohl(rpayload.vaddr));

        } else if (rpacket.type == UPDATEDIS) {
            struct vln_updatedis_payload rpayload;
            if (recv_wrap(vln_int->server_connection, (void *)&rpayload,
                          sizeof(struct vln_updatedis_payload)) != 0) {
                break;
            }
            router_remove_connection(vln_int->router, ntohl(rpayload.vaddr));
        } else {
            break;
        }
    }

    tcpwrapper_destroy(vln_int->server_connection);

    router_stop(vln_int->router);

    pthread_cancel(vln_int->sender);
    pthread_cancel(vln_int->receiver);

    pthread_join(vln_int->receiver, NULL);
    pthread_join(vln_int->sender, NULL);

    router_destroy(vln_int->router);

    destroy_interface(vln_int);

    pthread_mutex_lock(&_interface_lock);
    _vln_interfaces = NULL;
    pthread_mutex_unlock(&_interface_lock);

    exit(0);

    return NULL;
}

static struct vln_interface *create_interface(uint32_t addr_be,
                                              uint32_t broad_addr_be,
                                              uint32_t mask_addr_be,
                                              struct tcpwrapper *wrap)
{
    struct vln_adapter *adapter = vln_adapter_create(IFF_TUN | IFF_NO_PI);

    if (vln_adapter_set_network(adapter, addr_be, mask_addr_be,
                                broad_addr_be) == -1) {
        dprintf(STDERR_FILENO, "Adding payload in interface failed: %s\n ",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    struct vln_interface *new_int = malloc(sizeof(struct vln_interface));
    new_int->address = ntohl(addr_be);
    new_int->broadcast_address = ntohl(broad_addr_be);
    new_int->mask_address = ntohl(mask_addr_be);
    new_int->server_connection = wrap;
    new_int->adapter = adapter;

    struct taskexecutor *rlistener =
        taskexecutor_create((Handler)&router_listener, new_int);

    int router_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    new_int->router = router_create(
        new_int->address, new_int->address & new_int->mask_address,
        new_int->broadcast_address, router_sockfd, rlistener);

    pthread_create(&new_int->receiver, NULL, recv_thread, (void *)new_int);
    pthread_create(&new_int->sender, NULL, send_thread, (void *)new_int);

    taskexecutor_start(rlistener);

    return new_int;
}

static void destroy_interface(struct vln_interface *vln_int)
{
    vln_adapter_destroy(vln_int->adapter);
    free(vln_int);
}

struct tcpwrapper *create_server_tcpwrapper()
{
    int sockfd;
    int server_port = _server_port_temp;
    char *tcp_server_addr = _server_addr;
    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }
    inet_pton(AF_INET, tcp_server_addr, &server_addr.sin_addr.s_addr);

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);

    if (connect(sockfd, (struct sockaddr *)&server_addr,
                sizeof(struct sockaddr)) == -1) {
        perror("connect");
        exit(1);
    }

    return tcpwrapper_create(sockfd, 1024); // TODO error cheking
}

int send_starter_response(struct tcpwrapper *starter_tcpwrapper,
                          starter_packet_type type)
{
    uint8_t spacket[sizeof(struct starter_packet_header) +
                    sizeof(struct starter_response_payload)];
    memset(spacket, 0, sizeof(spacket));
    struct starter_packet_header *sheader =
        (struct starter_packet_header *)spacket;
    sheader->type = STARTER_RESPONSE;
    sheader->payload_length = sizeof(struct starter_response_payload);

    struct starter_response_payload *spayload =
        (struct starter_response_payload *)(spacket +
                                            sizeof(
                                                struct starter_packet_header));

    spayload->type = type;
    return send_wrap(starter_tcpwrapper, (void *)spacket, sizeof(spacket));
}

int starter_recv_connections()
{
    int starter_sfd, starter_socket;
    struct sockaddr_un address;
    pthread_mutex_init(&_interface_lock, NULL);

    if ((starter_sfd = socket(AF_UNIX, SOCK_STREAM, 0)) == 0) {
        perror("starter_sfd failed");
        exit(EXIT_FAILURE);
    }

    char sockpath[50];
    memset(sockpath, 0, 50);
    strcpy(sockpath, "/run/vln/");
    strcat(sockpath, "socket");

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, sockpath);

    unlink(sockpath);
    if (bind(starter_sfd, (struct sockaddr *)&address,
             sizeof(struct sockaddr_un)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(starter_sfd, 1) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    struct tcpwrapper *server_tcpwrapper = create_server_tcpwrapper();
    struct vln_interface *interfaces_checker;
    while (1) {
        if ((starter_socket = accept(starter_sfd, NULL, NULL)) < 1) {
            tcpwrapper_destroy(server_tcpwrapper);
            break;
        }

        struct tcpwrapper *starter_tcpwrapper =
            tcpwrapper_create(starter_socket, 1024);

        struct starter_packet_header rheader;
        if (recv_wrap(starter_tcpwrapper, (void *)&rheader,
                      sizeof(struct starter_packet_header)) != 0) {
            tcpwrapper_destroy(starter_tcpwrapper);
            tcpwrapper_destroy(server_tcpwrapper);
            break;
        }

        if (rheader.type == STARTER_CREATE) {

            pthread_mutex_lock(&_interface_lock);
            interfaces_checker = _vln_interfaces;
            pthread_mutex_unlock(&_interface_lock);

            if (interfaces_checker == NULL) {

                struct starter_create_payload rpayload;
                if (recv_wrap(starter_tcpwrapper, (void *)&rpayload,
                              sizeof(struct starter_create_payload)) != 0) {

                    tcpwrapper_destroy(starter_tcpwrapper);
                    tcpwrapper_destroy(server_tcpwrapper);
                    break;
                }

                uint8_t spacket[sizeof(struct vln_packet_header) +
                                sizeof(struct vln_create_payload)];
                memset(spacket, 0, sizeof(spacket));
                struct vln_packet_header *sheader =
                    (struct vln_packet_header *)spacket;

                sheader->type = CREATE;
                sheader->payload_length =
                    htonl(sizeof(struct vln_create_payload));

                struct vln_create_payload *spayload =
                    (struct vln_create_payload *)PACKET_PAYLOAD(spacket);
                strcpy(spayload->addres, rpayload.subnet);
                strcpy(spayload->bit, rpayload.bit);
                strcpy(spayload->network_name, rpayload.networck_name);
                strcpy(spayload->network_password, rpayload.networck_password);
                if (send_wrap(server_tcpwrapper, (void *)spacket,
                              sizeof(spacket)) != 0) {
                    send_starter_response(starter_tcpwrapper,
                                          LOST_SERVER_CONNECTION);
                    tcpwrapper_destroy(starter_tcpwrapper);
                    tcpwrapper_destroy(server_tcpwrapper);
                    break;
                }
            } else {
                send_starter_response(starter_tcpwrapper, STARTER_EXIST);
            }

        } else if (rheader.type == STARTER_CONNECT) {

            pthread_mutex_lock(&_interface_lock);
            interfaces_checker = _vln_interfaces;
            pthread_mutex_unlock(&_interface_lock);

            if (interfaces_checker == NULL) {

                struct starter_connect_payload rpayload;
                if (recv_wrap(starter_tcpwrapper, (void *)&rpayload,
                              sizeof(struct starter_connect_payload)) != 0) {
                    tcpwrapper_destroy(starter_tcpwrapper);
                    tcpwrapper_destroy(server_tcpwrapper);

                    break;
                }

                uint8_t spacket[sizeof(struct vln_packet_header) +
                                sizeof(struct vln_connect_payload)];
                memset(spacket, 0, sizeof(spacket));
                struct vln_packet_header *sheader =
                    (struct vln_packet_header *)spacket;

                sheader->type = CONNECT;
                sheader->payload_length =
                    htonl(sizeof(struct vln_connect_payload));

                struct vln_connect_payload *spayload =
                    (struct vln_connect_payload *)PACKET_PAYLOAD(spacket);

                strcpy(spayload->network_name, rpayload.networck_name);
                strcpy(spayload->network_password, rpayload.networck_password);
                if (send_wrap(server_tcpwrapper, (void *)spacket,
                              sizeof(spacket)) != 0) {
                    send_starter_response(starter_tcpwrapper,
                                          LOST_SERVER_CONNECTION);
                    tcpwrapper_destroy(starter_tcpwrapper);
                    tcpwrapper_destroy(server_tcpwrapper);
                    break;
                }
            } else {
                send_starter_response(starter_tcpwrapper, STARTER_EXIST);
            }

        } else if (rheader.type == STARTER_DISCONNECT) {
            pthread_mutex_lock(&_interface_lock);
            if (_vln_interfaces != NULL) {
                tcpwrapper_set_die_flag(_vln_interfaces->server_connection);
            }
            pthread_mutex_unlock(&_interface_lock);
            send_starter_response(starter_tcpwrapper, STARTER_DISCONNECT_DONE);

            tcpwrapper_destroy(starter_tcpwrapper);
            tcpwrapper_destroy(server_tcpwrapper);
            break;
        } else {
            send_starter_response(starter_tcpwrapper, STARTER_ERROR);
            tcpwrapper_destroy(starter_tcpwrapper);
            tcpwrapper_destroy(server_tcpwrapper);

            break;
        }

        pthread_mutex_lock(&_interface_lock);
        interfaces_checker = _vln_interfaces;
        pthread_mutex_unlock(&_interface_lock);

        if ((rheader.type == STARTER_CONNECT ||
             rheader.type == STARTER_CREATE) &&
            interfaces_checker == NULL) {

            struct vln_packet_header rpacket;
            if (recv_wrap(server_tcpwrapper, (void *)&rpacket,
                          sizeof(struct vln_packet_header)) != 0) {
                send_starter_response(starter_tcpwrapper,
                                      LOST_SERVER_CONNECTION);
                tcpwrapper_destroy(starter_tcpwrapper);
                tcpwrapper_destroy(server_tcpwrapper);
                break;
            }

            if (rpacket.type == INIT) {
                send_starter_response(starter_tcpwrapper, STARTER_DONE);
                struct vln_init_payload rpayload;
                if (recv_wrap(server_tcpwrapper, (void *)&rpayload,
                              sizeof(struct vln_init_payload)) != 0) {
                    send_starter_response(starter_tcpwrapper,
                                          LOST_SERVER_CONNECTION);
                    tcpwrapper_destroy(starter_tcpwrapper);
                    tcpwrapper_destroy(server_tcpwrapper);
                    break;
                }
                pthread_mutex_lock(&_interface_lock);
                _vln_interfaces =
                    create_interface(rpayload.vaddr, rpayload.broadaddr,
                                     rpayload.maskaddr, server_tcpwrapper);
                pthread_mutex_unlock(&_interface_lock);

                pthread_create(&_worker, NULL, manager_worker,
                               (void *)_vln_interfaces);

            } else if (rpacket.type == ERROR) {
                struct vln_error_payload rpayload;
                if (recv_wrap(server_tcpwrapper, (void *)&rpayload,
                              sizeof(struct vln_error_payload)) != 0) {
                    send_starter_response(starter_tcpwrapper,
                                          LOST_SERVER_CONNECTION);
                    tcpwrapper_destroy(starter_tcpwrapper);
                    tcpwrapper_destroy(server_tcpwrapper);
                    break;
                }
                send_starter_response(starter_tcpwrapper, rpayload.type);

            } else {
                send_starter_response(starter_tcpwrapper, STARTER_ERROR);
                tcpwrapper_destroy(starter_tcpwrapper);
                tcpwrapper_destroy(server_tcpwrapper);
                break;
            }
        }

        tcpwrapper_destroy(starter_tcpwrapper);

        pthread_mutex_lock(&_interface_lock);
        interfaces_checker = _vln_interfaces;
        pthread_mutex_unlock(&_interface_lock);

        if (interfaces_checker == NULL) {
            tcpwrapper_destroy(server_tcpwrapper);
            break;
        }
    }
    close(starter_sfd);
    return 0;
}

int read_config()
{
    FILE *fp;
    char buffer[1024];
    struct json_object *parsed_json;
    struct json_object *server_ip;
    struct json_object *server_port;
    struct json_object *installation_directory;

    struct passwd *pw = getpwuid(getuid());
    const char *homedir = pw->pw_dir;

    char configpath[strlen(homedir) + strlen("/.vln/vln.config") + 1];
    memset(configpath, 0, strlen(homedir) + strlen("/.vln/vln.config") + 1);
    strcpy(configpath, homedir);
    strcat(configpath, "/.vln/vln.config");

    fp = fopen("../../src/client/vln.config", "r");

    if (fp == NULL) {
        return -1;
    }
    fread(buffer, 1024, 1, fp);
    fclose(fp);

    parsed_json = json_tokener_parse(buffer);

    json_object_object_get_ex(parsed_json, "server_ip", &server_ip);
    json_object_object_get_ex(parsed_json, "server_port", &server_port);
    json_object_object_get_ex(parsed_json, "installation_directory",
                              &installation_directory);
    if (server_ip == NULL || server_port == NULL ||
        installation_directory == NULL) {

        return -1;
    }
    _server_addr = (char *)json_object_get_string(server_ip);

    _server_port_temp = json_object_get_int(server_port);

    _installation_dir = (char *)json_object_get_string(installation_directory);

    return 1;
}
int main(int argc, char **argv)
{
    if (read_config() == -1) {
        return -1;
    }
    _vln_interfaces = NULL;
    starter_recv_connections();
    pthread_mutex_destroy(&_interface_lock);

    pthread_exit(NULL);
    return 0;
}