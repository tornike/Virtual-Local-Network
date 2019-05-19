#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "tcpwrapper.h"

uint8_t *current_buffer;
int sock;
size_t start_point;
size_t end_point;
size_t buff_size;

void init_tcpwrapper(int sockfd, size_t buffer_size)
{
    buff_size = buffer_size;
    current_buffer = malloc(buffer_size);
    sock = sockfd;
    start_point = 0;
    end_point = 0;
}

void tcpwrapper_free()
{
    free(current_buffer);
}

int recv_wrap(void *buffer, size_t size)
{
    while (size != 0) {

        size_t avilable_buff_size = end_point - start_point;

        if (avilable_buff_size == 0) {
            int recv_count = recv(sock, current_buffer, buff_size, 0);
            if (recv_count == 0)
                return 1;
            start_point = 0;
            end_point = recv_count;
            avilable_buff_size = end_point - start_point;
        }

        int t = size > avilable_buff_size ? avilable_buff_size : size;
        memcpy((uint8_t *)buffer, current_buffer + start_point, t);
        size -= t;
        buffer = (uint8_t *)buffer + t;
        start_point += t;
    }
    return 0;
}

int send_wrap(void *buffer, size_t size)
{
    size_t send_size = 0;
    while (1) {
        if (send_size == size)
            return 0;
        size_t send_amount =
            send(sock, (buffer + send_size), (size - send_size), 0);
        if (send_amount == -1)
            return 1;
        send_size += send_amount;
    }
    return 1;
}
