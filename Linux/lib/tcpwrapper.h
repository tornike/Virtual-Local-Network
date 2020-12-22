#ifndef __TCP_WRAPPER__
#define __TCP_WRAPPER__

#include <stddef.h>

struct tcpwrapper;

struct tcpwrapper *tcpwrapper_create(int sockfd, size_t buffer_size);

void tcpwrapper_destroy(struct tcpwrapper *wrapper);

void tcpwrapper_set_die_flag(struct tcpwrapper *);

int recv_wrap(struct tcpwrapper *wrapper, void *buffer, size_t size);

int send_wrap(struct tcpwrapper *wrapper, void *buffer, size_t size);

#endif