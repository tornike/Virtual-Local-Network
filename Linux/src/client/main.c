#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "../connection.h"
#include "../lib/protocol.h"
#include "../lib/taskexecutor.h"
#include "../lib/tcpwrapper.h"
#include "../lib/uthash.h"
#include "../router.h"
#include "starterprotocol.h"
#include "vlnadapter.h"

// TODO!!!!!!!
#define UPDATETABLE 700
#define BUFFERSIZE 4096

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

//===========GLOBALS===========
char *_server_addr = "34.65.27.69"; // Must be changed.
int _server_port_temp = 33507; // Must be changed.
//===========GLOBALS===========

void router_listener(void *args, struct task_info *tinfo)
{
    struct vln_interface *vln_int = (struct vln_interface *)args;
    // TODO;
    // check if its server die and if its p2p setup pyramid.
    printf("Peers Changed\n");
    if (tinfo->operation == PEERDISCONNECTED) {
        struct router_action *act = (struct router_action *)tinfo->args;
        router_setup_pyramid(vln_int->router, act->vaddr);
        free(act);
    }
}

static void cleanup_handler(void *arg)
{
    struct cleanup_handler_arg *cha = (struct cleanup_handler_arg *)arg;
    router_add_free_slot(cha->vln_int->router, cha->slot);
    free(cha);
    printf("Cleanup Done\n");
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

        // void *buff = DATA_PACKET_PAYLOAD(slot->buffer);
        // char saddr[INET_ADDRSTRLEN];
        // char daddr[INET_ADDRSTRLEN];
        // inet_ntop(AF_INET, &((struct iphdr *)buff)->saddr, saddr,
        //           INET_ADDRSTRLEN);
        // inet_ntop(AF_INET, &((struct iphdr *)buff)->daddr, daddr,
        //           INET_ADDRSTRLEN);

        // printf("Received from V %s %s %d bytes\n", saddr, daddr,
        //        slot->used_size - sizeof(struct vln_data_packet_header));

        pthread_cleanup_push(cleanup_handler, cha);

        write(cha->vln_int->adapter->fd,
              cha->slot->buffer + sizeof(struct vln_data_packet_header),
              cha->slot->used_size - sizeof(struct vln_data_packet_header));

        pthread_cleanup_pop(0);

        router_add_free_slot(cha->vln_int->router, cha->slot);
    }
    printf("Recv Thread Returns\n");
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
    printf("Send Thread Returns\n");
    free(cha);
    return NULL;
}

// if some code needed.
// void manager_sender_handler(void *args, struct task_info *task_info)
// {
//     struct tcpwrapper *tcpwrapper = (struct tcpwrapper *)args;

//     struct vln_packet_header *spacket;
//     switch (task_info->operation) {
//     case INIT: {
//         printf("Send INIT\n");
//         spacket = (struct vln_packet_header *)task_info->args;
//         if (send_wrap(tcpwrapper, (void *)spacket,
//                       sizeof(struct vln_packet_header) +
//                           ntohl(spacket->payload_length)) != 0) {
//             printf("error send_wrap INIT\n");
//         } else {
//             printf("send_wrap INIT\n");
//         }
//         free(spacket);
//         break;
//     }
//     case UPDATES: {
//         spacket = (struct vln_packet_header *)task_info->args;
//         if (send_wrap(tcpwrapper, (void *)task_info->args,
//                       sizeof(struct vln_packet_header) +
//                           ntohl(spacket->payload_length)) != 0) {
//             printf("error send_wrap INIT\n");
//         } else {
//             printf("send_wrap INIT\n");
//         }
//         free(spacket);
//         break;
//     }
//     default:
//         printf("ERROR: Unknown Packet Type\n");
//         break;
//     }
// }

void manager_worker()
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

    struct tcpwrapper *tcpwrapper =
        tcpwrapper_create(sockfd, 1024); // TODO error cheking

    uint8_t spacket[sizeof(struct vln_packet_header) +
                    sizeof(struct vln_connect_payload)];
    struct vln_packet_header *sheader = (struct vln_packet_header *)spacket;

    sheader->type = CONNECT;
    sheader->payload_length = htonl(sizeof(struct vln_connect_payload));

    struct vln_connect_payload *spayload =
        (struct vln_connect_payload *)PACKET_PAYLOAD(spacket);

    strcpy(spayload->network_name, "22222222");
    strcpy(spayload->network_password, "22222222");

    // creat
    // uint8_t *spacket = malloc(sizeof(struct vln_packet_header) +
    //                           sizeof(struct vln_create_payload));
    // struct vln_packet_header *sheader = (struct vln_packet_header *)spacket;

    // sheader->type = CREATE;
    // sheader->payload_length = htonl(sizeof(struct vln_create_payload));

    // struct vln_create_payload *spayload =
    //     (struct vln_create_payload *)PACKET_PAYLOAD(spacket);
    // strcpy(spayload->addres, "198.168.7.0");
    // strcpy(spayload->bit, "28");
    // strcpy(spayload->network_name, "222222222");
    // strcpy(spayload->network_password, "222222222");

    if (send_wrap(tcpwrapper, (void *)spacket,
                  sizeof(struct vln_packet_header) +
                      htonl(sheader->payload_length)) != 0) {
        printf("error send_wrap CONNECT\n");
    } else {
        printf("send_wrap CONNECT\n");
    }

    struct vln_packet_header rpacket;
    struct vln_interface *vln_int;
    while (1) {
        printf("recv\n");
        if (recv_wrap(tcpwrapper, (void *)&rpacket,
                      sizeof(struct vln_packet_header)) != 0) {
            break;
        }
        printf("Type: %d\n", rpacket.type);
        switch (rpacket.type) {
        case CONNECT: {
            printf("Receive CONNECT\n");

            // struct vln_connect_payload rpaylod;
            // if (recv_wrap(tcpwrapper, (void *)&rpaylod,
            //               sizeof(struct vln_connect_payload)))
            //     printf("error recv_wrap CONNECT_TO_SERVER \n");

            // // router_add_connection(rpaylod.con_type, rpaylod.vaddr,
            // //                       rpaylod.raddr, rpaylod.rport);
            break;
        }
        case INIT: {
            printf("Received INIT\n");
            struct vln_init_payload rpayload;
            if (recv_wrap(tcpwrapper, (void *)&rpayload,
                          sizeof(struct vln_init_payload)) != 0)
                printf("error recv_wrap INIT \n");

            vln_int = create_interface(rpayload.vaddr, rpayload.broadaddr,
                                       rpayload.maskaddr, tcpwrapper);

            break;
        }
        case ROOTNODE: {
            printf("Recived: ROOTNODE\n");
            struct vln_rootnode_payload rpayload;
            if (recv_wrap(tcpwrapper, (void *)&rpayload,
                          sizeof(struct vln_rootnode_payload)) != 0)
                printf("error recv_wrap ROOTNODE \n");

            printf("Root raddr: %u\n", ntohl(rpayload.raddr));
            printf("Root port: %u\n", ntohs(rpayload.rport));
            printf("Root vaddr: %u\n", ntohl(rpayload.vaddr));

            router_send_init(vln_int->router, ntohl(rpayload.raddr),
                             ntohs(rpayload.rport));

            break;
        }
        case UPDATES: {
            printf("Updates Received\n");
            struct vln_updates_payload rpayload;
            if (recv_wrap(tcpwrapper, (void *)&rpayload,
                          sizeof(struct vln_updates_payload)) != 0) {
                // TODO
            }
            printf("Update %u %u %u %u %u\n", ntohl(rpayload.svaddr),
                   ntohl(rpayload.dvaddr), ntohl(rpayload.vaddr),
                   ntohl(rpayload.raddr), ntohs(rpayload.rport));

            router_try_connection(vln_int->router, ntohl(rpayload.vaddr),
                                  ntohl(rpayload.raddr), ntohs(rpayload.rport));

            router_setup_pyramid(vln_int->router, ntohl(rpayload.vaddr));

            break;
        }
        case UPDATEDIS: {
            printf("UPDATEDIS Received\n");
            struct vln_updatedis_payload rpayload;
            if (recv_wrap(tcpwrapper, (void *)&rpayload,
                          sizeof(struct vln_updatedis_payload)) != 0) {
                // TODO
            }
            // router_remove_connection(router, ntohl(rpayload.vaddr));
            break;
        }
        case ERROR: {
            printf("ERROR Received\n");
            struct vln_error_payload rpayload;
            if (recv_wrap(tcpwrapper, (void *)&rpayload,
                          sizeof(struct vln_error_payload)) != 0) {
                // TODO
            }
            printf("error: %d\n", rpayload.type);
            break;
        }
        default:
            printf("ERROR: Unknown Packet Type\n");
            break;
        }
    }

    tcpwrapper_destroy(tcpwrapper);

    router_stop(vln_int->router);
    printf("Router stopped\n");

    pthread_cancel(vln_int->sender);
    pthread_cancel(vln_int->receiver);

    pthread_join(vln_int->receiver, NULL);
    printf("Client Receiver died\n");
    pthread_join(vln_int->sender, NULL);
    printf("Client Sender died\n");

    router_destroy(vln_int->router);

    // destroy router
    printf("client died\n");
}

int send_starter_respons(int fd, starter_packet_type type, char *respons)
{
    uint8_t *spacket[sizeof(struct starter_packet_header) +
                     sizeof(struct starter_respons_payload)];
    struct starter_packet_header *sheader =
        (struct starter_packet_header *)spacket;
    sheader->type = type;
    sheader->payload_length = sizeof(struct starter_respons_payload);
    struct starter_respons_payload *spaload =
        (struct starter_respons_payload *)spacket +
        sizeof(struct starter_packet_header);
    strcpy(spaload->respons_text, respons);
    return send(fd, spacket, sizeof(spacket), 0);
}

int starter_server()
{
    int server_fd, new_socket;
    struct sockaddr_un address;
    char buffer[BUFFER_SIZE];

    // Creating socket file descriptor
    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, PATH);

    if (bind(server_fd, (struct sockaddr *)&address,
             sizeof(struct sockaddr_un)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 1) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    int aqtive = 1;
    while (aqtive) {
        if ((new_socket = accept(server_fd, NULL, NULL)) < 1) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        while (1) {
            memset(buffer, 0, BUFFER_SIZE);
            int r = 0;
            if ((r = recv(new_socket, buffer, BUFFER_SIZE, 0)) < 1) {
                // printf("%d %s\n", r, strerror(errno));
                break;
            }
            // struct starter_packet_header *user =
            //     (struct starter_packet_header *)buffer;
            // printf("%d\n", (int)user->type);
            // if (send(new_socket, done, strlen(done), 0) < 1)
            //     break;
            struct starter_packet_header *rheader =
                (struct starter_packet_header *)buffer;

            if (rheader->type == STARTER_CREATE) {
                struct starter_create_payload *rpayload =
                    (struct starter_create_payload
                         *)(buffer + sizeof(struct starter_packet_header));
                printf("name: %s\n", rpayload->networck_name);
                printf("password: %s\n", rpayload->networck_password);
                printf("subnet: %s\n", rpayload->subnet);

                send_starter_respons(new_socket, STARTER_DONE,
                                     "STARTER_CREATE");

            } else if (rheader->type == STARTER_CONNECT) {
                struct starter_connect_payload *rpayload =
                    (struct starter_connect_payload
                         *)(buffer + sizeof(struct starter_packet_header));
                printf("name: %s\n", rpayload->networck_name);
                printf("password: %s\n", rpayload->networck_password);

                send_starter_respons(new_socket, STARTER_DONE,
                                     "STARTER_CONNECT");
            } else if (rheader->type == STARTER_DISCONNECT) {
                printf("Discnnect\n");
                // if (_interface != NULL) {
                //     // TODO
                // }
                send_starter_respons(new_socket, STARTER_DONE,
                                     "STARTER_DISCONNECT");
            } else if (rheader->type == STARTER_STOP) {
                printf("Stop\n");
                aqtive = 0;
                send_starter_respons(new_socket, STARTER_DONE, "STARTER_STOP");
            } else {
                printf("ERROR: Unknown Packet Type Send %d\n", rheader->type);
                send_starter_respons(new_socket, STARTER_ERROR,
                                     "ERROR: Unknown Packet Type Send");
                break;
            }
        }
        close(new_socket);
    }
    close(server_fd);
    unlink(PATH);
    return 0;
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
        exit(EXIT_FAILURE); // TODO
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

int main(int argc, char **argv)
{
    manager_worker();
    // starter_server();

    /// yvelafris washlaa dasaweri

    pthread_exit(NULL);
    return 0;
}