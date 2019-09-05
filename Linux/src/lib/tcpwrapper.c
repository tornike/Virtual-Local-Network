#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "tcpwrapper.h"

struct connection_die_flag {
    pthread_mutex_t lock;
    uint8_t flag;
};

struct tcpwrapper {
    uint8_t *buffer;
    size_t buffer_size;
    int sockfd;
    size_t start_point;
    size_t end_point;

    struct connection_die_flag dflag;

    pthread_mutex_t send_lock;
};

struct tcpwrapper *tcpwrapper_create(int sockfd, size_t buffer_size)
{
    struct tcpwrapper *wrapper = malloc(sizeof(struct tcpwrapper));
    wrapper->buffer_size = buffer_size;
    wrapper->buffer = malloc(buffer_size);
    wrapper->sockfd = sockfd;
    wrapper->start_point = 0;
    wrapper->end_point = 0;
    pthread_mutex_init(&wrapper->send_lock, NULL);
    wrapper->dflag.flag = 0;
    pthread_mutex_init(&wrapper->dflag.lock, NULL);

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    return wrapper;
}

void tcpwrapper_set_die_flag(struct tcpwrapper *wrapper)
{
    pthread_mutex_lock(&wrapper->dflag.lock);
    wrapper->dflag.flag = 1;
    pthread_mutex_unlock(&wrapper->dflag.lock);
}

void tcpwrapper_destroy(struct tcpwrapper *wrapper)
{
    pthread_mutex_destroy(&wrapper->send_lock);
    pthread_mutex_destroy(&wrapper->dflag.lock);
    close(wrapper->sockfd);
    free(wrapper->buffer);
    free(wrapper);
}

int recv_wrap(struct tcpwrapper *wrapper, void *buffer, size_t size)
{
    size_t available_bytes = 0;
    while (size != 0) {
        available_bytes = wrapper->end_point - wrapper->start_point;

        if (available_bytes == 0) {
            ssize_t recv_tmp;
            while ((recv_tmp = recv(wrapper->sockfd, wrapper->buffer,
                                    wrapper->buffer_size, 0)) < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    pthread_mutex_lock(&wrapper->dflag.lock);
                    if (wrapper->dflag.flag == 1) {
                        pthread_mutex_unlock(&wrapper->dflag.lock);
                        printf("Returning cause of flag\n");
                        return 1;
                    }
                    pthread_mutex_unlock(&wrapper->dflag.lock);
                    printf("TCP TIMEOUT\n");
                    continue;
                }

                printf("Not EAGAIN or EWOULDBLOCK %d %s\n", errno,
                       strerror(errno));
                return 1;
            }
            if (recv_tmp == 0) {
                printf("Peer Died\n");
                return 1;
            }
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
    int res = 0;
    pthread_mutex_lock(&wrapper->send_lock);
    while (size != 0) {
        ssize_t sent_tmp = send(wrapper->sockfd, buffer, size, 0);
        if (sent_tmp == -1)
            res = 1;
        size -= sent_tmp;
        buffer = (uint8_t *)buffer + sent_tmp;
    }
    pthread_mutex_unlock(&wrapper->send_lock);
    return res;
}
