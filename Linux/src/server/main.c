#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

int ips[2];
int ports[2];

int main(int argc, char **argv)
{
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5000);
    inet_pton(AF_INET, "10.0.0.4", &addr.sin_addr.s_addr);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

    printf("Bound\n");

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;

    struct sockaddr_in raddr;
    memset(&raddr, 0, sizeof(struct sockaddr_in));
    socklen_t rslen = sizeof(struct sockaddr_in);

    while (100) {
        char buff[1024];
        int size =
            recvfrom(fd, buff, 1024, 0, (struct sockaddr *)&raddr, &rslen);
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &raddr.sin_addr, ip, INET_ADDRSTRLEN);
        printf("Received from %s:%d %d bytes\n", ip, raddr.sin_port, size);

        char v_saddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, (const void *)&((struct iphdr *)buff)->saddr,
                  v_saddr, INET_ADDRSTRLEN);

        char v_daddr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, (const void *)&((struct iphdr *)buff)->daddr,
                  v_daddr, INET_ADDRSTRLEN);

        printf("Source addr %s\n", v_saddr);
        if (strcmp(v_saddr, "10.1.1.1") == 0) {
            ips[0] = raddr.sin_addr.s_addr;
            ports[0] = raddr.sin_port;
            printf("10.1.1.1 Stored %d\n", raddr.sin_port);
        } else if (strcmp(v_saddr, "10.1.1.2") == 0) {
            ips[1] = raddr.sin_addr.s_addr;
            ports[1] = raddr.sin_port;
            printf("10.1.1.2 Stored %d\n", raddr.sin_port);
        }

        printf("Destionation addr %s\n", v_daddr);
        if (strcmp(v_daddr, "10.1.1.1") == 0) {
            saddr.sin_port = ports[0];
            saddr.sin_addr.s_addr = ips[0];
            int sent = sendto(fd, buff, size, 0, (struct sockaddr *)&saddr,
                              sizeof(struct sockaddr_in));
            printf("Retransmitted1 %d bytes\n", sent);
        } else if (strcmp(v_daddr, "10.1.1.2") == 0) {
            saddr.sin_port = ports[1];
            saddr.sin_addr.s_addr = ips[1];
            int sent = sendto(fd, buff, size, 0, (struct sockaddr *)&saddr,
                              sizeof(struct sockaddr_in));
            printf("Retransmitted2 %d bytes\n", sent);
        } else {
            printf("Some Packets Dropped\n");
        }
    }

    return 0;
}