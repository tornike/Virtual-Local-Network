#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "tcpwrapper.h"

struct tcpwrapper {
    uint8_t *buffer;
    size_t buffer_size;
    int sockfd;
    size_t start_point;
    size_t end_point;
};

struct tcpwrapper *tcpwrapper_create(int sockfd, size_t buffer_size)
{
    struct tcpwrapper *wrapper = malloc(sizeof(struct tcpwrapper));
    wrapper->buffer_size = buffer_size;
    wrapper->buffer = malloc(buffer_size);
    wrapper->sockfd = sockfd;
    wrapper->start_point = 0;
    wrapper->end_point = 0;
    return wrapper;
}

void tcpwrapper_destroy(struct tcpwrapper *wrapper)
{
    free(wrapper->buffer);
    free(wrapper);
}

int recv_wrap(struct tcpwrapper *wrapper, void *buffer, size_t size)
{
    size_t available_bytes = 0;
    while (size != 0) {
        available_bytes = wrapper->end_point - wrapper->start_point;

        if (available_bytes == 0) {
            size_t recv_tmp =
                recv(wrapper->sockfd, wrapper->buffer, wrapper->buffer_size, 0);
            if (recv_tmp == 0)
                return 1;
            wrapper->start_point = 0;
            wrapper->end_point = recv_tmp;
        } else {
            size_t min = size > available_bytes ? available_bytes : size;
            memcpy((uint8_t *)buffer, wrapper->buffer + wrapper->start_point,
                   min);
            size -= min;
            buffer = (uint8_t *)buffer + min;
            wrapper->start_point += min;
        }
    }
    return 0;
}

int send_wrap(struct tcpwrapper *wrapper, void *buffer, size_t size)
{
    while (size != 0) {
        size_t sent_tmp = send(wrapper->sockfd, buffer, size, 0);
        if (sent_tmp == -1)
            return 1;
        size -= sent_tmp;
        buffer = (uint8_t *)buffer + sent_tmp;
    }
    return 0;
}
