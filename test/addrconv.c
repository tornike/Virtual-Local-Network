
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>

int main()
{
    uint32_t addr;
    inet_pton(AF_INET, "192.168.33.17", &addr);

    printf("%u\n", addr);
    printf("%u\n", ntohl(addr));
    printf("%u\n", ntohl(ntohl(addr)));
    printf("%u\n", htonl(ntohl(addr)));

    return 0;
}