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
#include <unistd.h>

#include "../connection.h"
#include "../lib/protocol.h"
#include "../lib/tcpwrapper.h"

#define BUFFERSIZE 1024

char *myip;
char *server_addr = "35.228.37.164"; // Must be changed.
int server_port_temp = 33507; // Must be changed.
int sfd;
int tunfd;

struct TEMP {
    uint16_t port;
    int sfd;
};

/* Arguments taken by the function:
 *
 * char *name is the name of an interface (or '\0'). MUST have enough
 * space to hold the interface name if '\0'.
 *
 * int flags: interface (TUNSETIFF) flags (eg, IFF_TUN etc.)
 */
int create_adapter(char *name, int flags)
{
    int fd, err;
    struct ifreq ifr;

    /* open the clone device */
    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return fd;
    }

    memset(&ifr, 0, sizeof(struct ifreq));

    ifr.ifr_flags = flags;

    if (*name) {
        strcpy(ifr.ifr_name, name);
    }

    /* try to create the device */
    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        close(fd);
        return err;
    }

    /* get actual name of an interface */
    strcpy(name, ifr.ifr_name);

    return fd;
}

int configure_adapter(char *name)
{

    struct ifreq ifr;
    strcpy(ifr.ifr_name, name);

    int sfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (ioctl(sfd, SIOCGIFFLAGS, &ifr) < 0) {
        printf("Getting interface flags failed: %s\n", strerror(errno));
    }

    printf("Flags %d\n", ifr.ifr_flags);
    ifr.ifr_flags = IFF_UP | IFF_RUNNING | IFF_NOARP | IFF_POINTOPOINT;
    if (ioctl(sfd, SIOCSIFFLAGS, &ifr) < 0) {
        printf("Setting interface flags failed: %s\n", strerror(errno));
    }

    close(sfd);

    return 0;
}

void *recv_thread(void *arg)
{
    struct sockaddr_in raddr;
    memset(&raddr, 0, sizeof(struct sockaddr_in));

    socklen_t slen = sizeof(struct sockaddr_in);
    while (100) {
        char buff[BUFFERSIZE];
        int size = recvfrom(sfd, buff, BUFFERSIZE, 0, (struct sockaddr *)&raddr,
                            &slen);

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &raddr.sin_addr, (void *)&ip, INET_ADDRSTRLEN);

        printf("Received from %s:%d %d bytes\n", ip, raddr.sin_port, size);

        char saddr[INET_ADDRSTRLEN];
        char daddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((struct iphdr *)buff)->saddr, saddr,
                  INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &((struct iphdr *)buff)->daddr, daddr,
                  INET_ADDRSTRLEN);

        if (strcmp(daddr, myip) == 0) {
            write(tunfd, buff, size);
        }
    }
}

void *send_thread(void *arg)
{
    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(5000);
    inet_pton(AF_INET, server_addr, &saddr.sin_addr.s_addr);

    while (100) {
        char buff[BUFFERSIZE];
        int size = read(tunfd, buff, BUFFERSIZE);
        sendto(sfd, buff, size, 0, (struct sockaddr *)&saddr,
               sizeof(struct sockaddr_in));
    }
}

int connect_network_udp()
{
    int sockfd;
    struct sockaddr_in servaddr;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(0);
    servaddr.sin_addr.s_addr = INADDR_ANY;
    bind(sockfd, (struct sockaddr *)&servaddr, sizeof(struct sockaddr_in));
    printf("Create UDP\n");
    return sockfd;
}

void *send_keep_alive(void *arg)
{
    struct TEMP *temp = (struct TEMP *)arg;
    struct vln_packet_header keep_alive;
    keep_alive.payload_length = 0;
    keep_alive.type = KEEPALIVE;
    uint8_t buff[BUFFERSIZE];
    struct sockaddr_in servaddr;
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(temp->port);
    inet_pton(AF_INET, server_addr, &servaddr.sin_addr.s_addr);
    while (1) {

        sendto(temp->sfd, (struct vln_packet_header *)&keep_alive,
               sizeof(struct vln_packet_header), 0,
               (const struct sockaddr *)&servaddr, sizeof(servaddr));
        sleep(3);
        printf("Wait...\n");
        recvfrom(temp->sfd, &buff, BUFFERSIZE, 0, NULL, 0);
        struct vln_packet_header *pak = (struct vln_packet_header *)&buff;
        printf("recv: %d\n", pak->type);
    }
}

int add_tunnel_interface(int port)
{
    char adapter_name[IFNAMSIZ];
    strcpy(adapter_name, "testint1");

    tunfd = create_adapter(adapter_name, IFF_TUN | IFF_NO_PI);
    if (tunfd < 0) {
        printf("Creating interface failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    configure_adapter(adapter_name);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "0.0.0.0", &addr.sin_addr.s_addr);

    sfd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(sfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

    pthread_t rt;
    pthread_t wt;

    pthread_create(&rt, NULL, recv_thread, NULL);
    pthread_create(&wt, NULL, send_thread, NULL);
    return EXIT_SUCCESS;
}

int add_vaddr_tunnel_interface(struct vln_vaddr_payload *paylod)
{

    struct sockaddr_in *addr;
    struct ifreq ifr;

    strcpy(ifr.ifr_name, "testint1");

    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_addr.s_addr = paylod->ip_addr;
    addr->sin_family = AF_INET;

    if (ioctl(sfd, SIOCSIFADDR, &ifr) < 0) {
        printf("Setting IP address failed: %s\n", strerror(errno));
        return -1;
    } else {
        printf("Set Inet\n");
    }

    int mask;
    // shesacvlelia
    inet_pton(AF_INET, "255.255.255.0", &mask);

    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    addr->sin_addr.s_addr = mask;
    addr->sin_family = AF_INET;

    if (ioctl(sfd, SIOCSIFNETMASK, &ifr) < 0) {
        printf("Setting mask address failed: %s\n", strerror(errno));
        return -1;
    } else {
        printf("Set Mask Address\n");
    }
    return 1;
}

void connect_network_tcp()
{
    int sockfd;
    int server_port = server_port_temp;
    char *tcp_server_addr = server_addr;
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
    init_tcpwrapper(sockfd, BUFFERSIZE);

    struct vln_packet_header sheader;
    sheader.type = INIT;
    sheader.payload_length = 0;

    if (send_wrap((void *)&sheader, sizeof(struct vln_packet_header))) {
        printf("error send_wrap INIT\n");
    } else {
        printf("send_wrap INIT\n");
    }

    vln_packet_type type;
    while (1) {
        printf("recv\n");
        struct vln_packet_header rheader;
        if (recv_wrap((void *)&rheader, sizeof(struct vln_packet_header))) {
            type = 0;
        } else {
            type = rheader.type;
        }
        printf("Type: %d\n", type);

        if (type == CONNECT) {
            printf("Receive CONNECT\n");

            struct vln_connect_payload rpaylod;
            if (recv_wrap((void *)&rpaylod, sizeof(struct vln_connect_payload)))
                printf("error recv_wrap CONNECT_TO_SERVER \n");

            char ip[15]; ////
            inet_ntop(AF_INET, &rpaylod.vaddr, &ip, 15); ///
            printf("IP: %s\n", ip);

            // int sockfd = connect_network_udp();

        } else if (type == INITR) {
            printf("Receive INITR\n");

            struct vln_vaddr_payload rpayload;
            if (recv_wrap((void *)&rpayload, sizeof(struct vln_initr_payload)))
                printf("error recv_wrap INITR \n");

            int tunnel_interface = add_vaddr_tunnel_interface(&rpayload);

            if (tunnel_interface) {

                struct vln_packet_header sheader;
                sheader.payload_length = 0;
                sheader.type = HOSTS;

                if (send_wrap((void *)&sheader,
                              sizeof(struct vln_packet_header))) {
                    printf("error send_wrap HOSTS\n");
                } else {
                    printf("send_wrap HOSTS\n");
                }
            }
        } else if (type == HOSTSR) {
            printf("Enter: HOSTSR\n");
            int struct_count =
                rheader.payload_length / sizeof(struct vln_vaddr_payload);

            uint8_t spacket[sizeof(struct vln_server_connect_payload) +
                            sizeof(struct vln_packet_header)];

            struct vln_packet_header *sheader =
                (struct vln_packet_header *)spacket;
            sheader->payload_length = sizeof(struct vln_server_connect_payload);
            sheader->type = CONNECT;

            struct vln_server_connect_payload *spayload =
                (struct vln_server_connect_payload
                     *)(spacket + sizeof(struct vln_packet_header));

            spayload->con_type = PYRAMID;

            for (size_t i = 0; i < struct_count; i++) {
                struct vln_vaddr_payload rpayload;
                if (recv_wrap((void *)&rpayload,
                              sizeof(struct vln_vaddr_payload)))
                    printf("error recv_wrap HOSTSR \n");
                char ip[15]; ////
                inet_ntop(AF_INET, &rpayload.ip_addr, &ip, 15); ///
                printf("IP: %s\n", ip); ///

                spayload->vaddr = rpayload.ip_addr;

                if (send_wrap(spacket, sizeof(spacket))) {
                    printf("error send_wrap HOSTSR: %lu\n", i);
                } else {
                    printf("send_wrap HOSTSR: %lu\n", i);
                }
            }

        } else {
            printf("Invalid Type!\n");
            break;
        }
    }
}

int main(int argc, char **argv)
{
    add_tunnel_interface(0);
    connect_network_tcp();

    pthread_exit(NULL);

    return 0;
}