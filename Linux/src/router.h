#ifndef __VLN_ROUTER__
#define __VLN_ROUTER__

#include "lib/protocol.h"
#include <stdlib.h>

void router_init(size_t subnet_size);

void router_destroy();

int router_add_connection(vln_connection_type ctype, uint32_t vaddr,
                          uint32_t raddr, uint16_t rport);

int router_remove_connection(uint32_t vaddr);

int router_transmit(void *packet, size_t size);

int router_receive(void *buffer, size_t size); /* size must be big enough */

void router_set_vaddr(uint32_t ip_addr);

void router_get_raddr(uint32_t vaddr, uint32_t *raddr, uint16_t *rport);

#endif