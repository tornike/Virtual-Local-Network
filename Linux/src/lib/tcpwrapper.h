#ifndef __TCP_WRAPPER__
#define __TCP_WRAPPER__

#include <stddef.h>

void init_tcpwrapper(int sockfd, size_t buffer_size);

int recv_wrap(void *buffer, size_t size);

int send_wrap(void *buffer, size_t size);

void tcpwrapper_free();

#endif