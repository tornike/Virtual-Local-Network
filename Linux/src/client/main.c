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

char *myip;
int sfd;
int tunfd;

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
    int ip;
    inet_pton(AF_INET, "10.1.1.1", &ip);

    int mask;
    inet_pton(AF_INET, "255.255.255.0", &mask);

    struct ifreq ifr;
    strcpy(ifr.ifr_name, name);

    int sfd = socket(AF_INET, SOCK_DGRAM, 0);

    struct sockaddr_in *addr;
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_addr.s_addr = ip;
    addr->sin_family = AF_INET;

    if (ioctl(sfd, SIOCSIFADDR, &ifr) < 0) {
        printf("Setting IP address failed: %s\n", strerror(errno));
        return -1;
    }

    addr = (struct sockaddr_in *)&ifr.ifr_netmask;
    addr->sin_addr.s_addr = mask;
    addr->sin_family = AF_INET;

    if (ioctl(sfd, SIOCSIFNETMASK, &ifr) < 0) {
        printf("Setting mask address failed: %s\n", strerror(errno));
    }

    if (ioctl(sfd, SIOCGIFFLAGS, &ifr) < 0) {
        printf("Getting interface flags failed: %s\n", strerror(errno));
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sfd, SIOCSIFFLAGS, &ifr) < 0) {
        printf("Setting nterface flags failed: %s\n", strerror(errno));
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
        char buff[1024];
        int size =
            recvfrom(sfd, buff, 1024, 0, (struct sockaddr *)&raddr, &slen);
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &raddr.sin_addr, (void *)&ip, INET_ADDRSTRLEN);
        printf("Received from %s:%d %d bytes\n", ip, raddr.sin_port, size);

        char saddr[INET_ADDRSTRLEN];
        char daddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((struct iphdr *)buff)->saddr, saddr,
                  INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &((struct iphdr *)buff)->daddr, daddr,
                  INET_ADDRSTRLEN);

        if (strcmp(ip, myip) == 0) {
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
    inet_pton(AF_INET, "192.168.0.101", &saddr.sin_addr.s_addr);
    while (100) {
        char buff[1024];
        int size = read(tunfd, buff, 1024);
        int sent = sendto(sfd, buff, size, 0, (struct sockaddr *)&saddr,
                          sizeof(struct sockaddr_in));
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

    myip = argv[1];
    struct sockaddr_in addr;
    int ip;
    inet_pton(AF_INET, "192.168.0.101", &ip);

    addr.sin_family = AF_INET;
    addr.sin_port = htons(atoi(argv[2]));
    addr.sin_addr.s_addr = ip;

    int server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(server_fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

    sfd = server_fd;

    pthread_t rt;
    pthread_t wt;

    pthread_create(&rt, NULL, recv_thread, NULL);
    pthread_create(&wt, NULL, send_thread, NULL);

    pthread_exit(NULL);
    return 0;
}
