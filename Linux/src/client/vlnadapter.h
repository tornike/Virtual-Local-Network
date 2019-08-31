#ifndef __VLN_ADAPTER__
#define __VLN_ADAPTER__

#include <stdint.h>

#define INTERFACE_NAME "testint1"

struct tunnel_interface {
    int fd;
};

struct tunnel_interface *tunnel_interface_create(int flags);

void tunnel_interface_destroy(struct tunnel_interface *);

int tunnel_interface_set_network(uint32_t vaddr, uint32_t maskaddr,
                                 uint32_t broadaddr);

#endif