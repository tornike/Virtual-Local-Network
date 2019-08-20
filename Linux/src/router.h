#ifndef __VLN_ROUTER__
#define __VLN_ROUTER__

#include "lib/protocol.h"
#include "lib/taskexecutor.h"
#include <stdlib.h>

struct router;

struct router *router_create(uint32_t vaddr, uint32_t net_addr,
                             uint32_t broad_addr,
                             struct taskexecutor *taskexecutor);

void router_destroy(struct router *);

int router_add_connection(struct router *, vln_connection_type ctype,
                          uint32_t vaddr, uint32_t raddr, uint16_t rport,
                          int isActive, int sendInit);

// int router_remove_connection(uint32_t vaddr);

int router_transmit(struct router *, void *packet, size_t size);

int router_receive(struct router *, void *buffer,
                   size_t size); /* size must be big enough */

void router_get_raddr(struct router *, uint32_t *raddr, uint16_t *rport);

#endif