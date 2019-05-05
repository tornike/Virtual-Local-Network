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

#include "../lib/protocol.h"

#define BUFFERSIZE 1024

char *myip;
char *server_addr = "168.63.36.239"; // Must be changed.
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
        int sent = sendto(sfd, buff, size, 0, (struct sockaddr *)&saddr,
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

void connect_network_tcp()
{
    int sockfd, recv_buff;
    int server_port = 33507; ///////////////// Server Port
    char *tcp_server_addr = server_addr;
    uint8_t buff[BUFFERSIZE];
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

    struct vln_packet_header init;
    init.type = INIT;
    init.payload_length = 0;
    if (send(sockfd, (void *)&init, sizeof(struct vln_packet_header), 0) ==
        -1) {
        perror("send");
        exit(1);
    }
    while (1) {
        printf("recv\n");
        recv_buff = recv(sockfd, &buff, BUFFERSIZE, 0);
        struct vln_packet_header *header = ((struct vln_packet_header *)buff);
        VLN_PACKET_TYPE type = header->type;
        printf("Type: %d\n", type);
        if (type == UADDR) {
            printf("Receive UADDR\n");
            // uint16_t port =
            //     ((struct vln_uaddr_paylod *)(buff +
            //                                  sizeof(struct
            //                                  vln_packet_header)))
            //         ->port;

            // int sockfd = connect_network_udp();

            // struct TEMP temp;
            // temp.port = port;
            // temp.sfd = sockfd;

            // pthread_t wu;
            // pthread_create(&wu, NULL, send_keep_alive, &temp);
            printf("Send Keep Alive\n");

        } else if (type == ADDR) {
            printf("Receive ADDR\n");
            // printf("Receive ADDR: %d\n", type);
            struct vln_vaddr_payload *paylod = ((
                struct vln_vaddr_payload *)(buff +
                                            sizeof(struct vln_packet_header)));

            struct sockaddr_in *addr;
            struct ifreq ifr;

            strcpy(ifr.ifr_name, "testint1");

            addr = (struct sockaddr_in *)&ifr.ifr_addr;
            addr->sin_addr.s_addr = paylod->ip_addr;
            addr->sin_family = AF_INET;

            if (ioctl(sfd, SIOCSIFADDR, &ifr) < 0) {
                printf("Setting IP address failed: %s\n", strerror(errno));
            } else {
                printf("Set Inet\n");
            }

            int mask;
            inet_pton(AF_INET, "255.255.255.0", &mask);

            addr = (struct sockaddr_in *)&ifr.ifr_netmask;
            addr->sin_addr.s_addr = mask;
            addr->sin_family = AF_INET;

            if (ioctl(sfd, SIOCSIFNETMASK, &ifr) < 0) {
                printf("Setting mask address failed: %s\n", strerror(errno));
            } else {
                printf("Set Mask Address\n");
            }

        } else if (type == INITS) {
            printf("Enter: INITS\n");
            int struct_count =
                header->payload_length / sizeof(struct vln_vaddr_payload);
            struct vln_vaddr_payload *paylod = ((
                struct vln_vaddr_payload *)(buff +
                                            sizeof(struct vln_packet_header)));
            struct vln_vaddr_payload *temp = paylod;
            for (size_t i = 0; i < struct_count; i++) {
                // inet_pton(AF_INET, "0.0.0.0", &addr.sin_addr.s_addr);
                char ip[15];
                inet_ntop(AF_INET, &temp->ip_addr, &ip, 15);
                printf("IP: %s\n", ip);
                temp = temp + 1;
            }

        } else {
            printf("Invalid Type!\n");
        }
    }
}

int main(int argc, char **argv)
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
    addr.sin_port = htons(atoi(argv[2]));
    inet_pton(AF_INET, "0.0.0.0", &addr.sin_addr.s_addr);

    sfd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(sfd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

    // pthread_t rt;
    // pthread_t wt;

    // pthread_create(&rt, NULL, recv_thread, NULL);
    // pthread_create(&wt, NULL, send_thread, NULL);
    // printf("Create Tunnel Interface\n");
    connect_network_tcp();

    pthread_exit(NULL);

    return 0;
}
// struct sockaddr_in *addr;
//     addr = (struct sockaddr_in *)&ifr.ifr_addr;
//     addr->sin_addr.s_addr = ip;
//     addr->sin_family = AF_INET;

//     if (ioctl(sfd, SIOCSIFADDR, &ifr) < 0) {
//         printf("Setting IP address failed: %s\n", strerror(errno));
//         return -1;
//     }