#ifndef __VLN_ROUTER__
#define __VLN_ROUTER__

#include "lib/protocol.h"
#include "lib/taskexecutor.h"
#include <stdlib.h>

#define SLOT_SIZE 4096

/* Listener Actions */
#define PEERCONNECTED 1
#define PEERDISCONNECTED 2

struct router_action {
    uint32_t vaddr;
    uint32_t raddr;
    uint32_t rport;
};

/* Only buffer and used_size should be changed by external classes. */
struct router_buffer_slot {
    uint8_t buffer[SLOT_SIZE];
    size_t used_size;

    struct router_buffer_slot *next;
    struct router_buffer_slot *prev;
};

struct router;

struct router *router_create(uint32_t vaddr, uint32_t net_addr,
                             uint32_t broad_addr, int sockfd,
                             struct taskexecutor *taskexecutor);

void router_destroy(struct router *);

// int router_add_connection(struct router *, vln_connection_type ctype,
//                           uint32_t vaddr, uint32_t raddr, uint16_t rport,
//                           int isActive, int sendInit);

void router_remove_connection(struct router *router, uint32_t vaddr);

int router_transmit(struct router *, void *packet, size_t size);

struct router_buffer_slot *router_get_free_slot(struct router *);

void router_add_free_slot(struct router *, struct router_buffer_slot *);

struct router_buffer_slot *router_receive(struct router *);

void router_send(struct router *router, struct router_buffer_slot *);

void router_get_raddr(struct router *, uint32_t *raddr, uint16_t *rport);

void router_send_init(struct router *router, uint32_t raddr, uint32_t rport);

void router_update_routing_table(struct router *router, uint32_t svaddr,
                                 uint32_t vaddr, uint32_t raddr,
                                 uint32_t rport);

#endif