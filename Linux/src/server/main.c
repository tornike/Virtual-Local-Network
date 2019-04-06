#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

int main(int argc, char **argv)
{
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5000);
    inet_pton(AF_INET, "192.168.0.101", &addr.sin_addr.s_addr);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(fd, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));

    struct sockaddr_in raddr;
    memset(&raddr, 0, sizeof(struct sockaddr_in));
    socklen_t rslen = sizeof(struct sockaddr_in);

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.0.101", &saddr.sin_addr.s_addr);

    while (100) {
        char buff[1024];
        int size =
            recvfrom(fd, buff, 1024, 0, (struct sockaddr *)&raddr, &rslen);
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &raddr.sin_addr, ip, INET_ADDRSTRLEN);
        printf("Received from %s:%d %d bytes\n", ip, raddr.sin_port, size);

        char x[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, (const void *)&((struct iphdr *)buff)->daddr, x,
                  INET_ADDRSTRLEN);

        if (strcmp(x, "10.1.1.1") == 0) {
            saddr.sin_port = htons(5001);
        } else {
            saddr.sin_port = htons(5002);
        }

        int sent = sendto(fd, buff, size, 0, (struct sockaddr *)&saddr,
                          sizeof(struct sockaddr_in));
        printf("Retransmitted %d bytes\n", sent);
    }

    return 0;
}