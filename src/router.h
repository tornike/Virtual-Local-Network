/*
 * Virtual Local Network
 *
 * Copyright (C) 2020 VLN authors:
 *
 * Tornike Khachidze <tornike@github>
 * Luka Macharadze <lmach14@github>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __VLN_ROUTER__
#define __VLN_ROUTER__

#include "router_protocol.h"
#include <stdlib.h>

#define SLOT_SIZE 4096

/* Listener Actions */
#define PEERCONNECTED 1
#define PEERDISCONNECTED 2

typedef uint8_t router_event_type;

struct router_event {
    router_event_type type;
    void *ptr;
};

struct router_action {
    uint32_t vaddr;
    uint32_t raddr;
    uint32_t rport;
};

/* Only buffer and used_size should be changed by external classes. */
struct router_buffer_slot {
    uint8_t buffer[SLOT_SIZE];
    ssize_t used_size;

    struct router_buffer_slot *next;
    struct router_buffer_slot *prev;
};

struct router;

struct router *router_create(uint32_t vaddr, uint32_t net_addr,
                             uint32_t broad_addr, int sockfd, int mngr_pipe_fd);

void router_stop(struct router *);

void router_destroy(struct router *);

void router_try_connection(struct router *, uint32_t vaddr, uint32_t raddr,
                           uint16_t rport);

void router_remove_connection(struct router *, uint32_t vaddr);

struct router_buffer_slot *router_get_free_slot(struct router *);

void router_add_free_slot(struct router *, struct router_buffer_slot *);

struct router_buffer_slot *router_receive(struct router *);

void router_send(struct router *router, struct router_buffer_slot *);

void router_send_init(struct router *router, uint32_t root_vaddr,
                      uint32_t root_raddr, uint16_t root_rport);

void router_setup_pyramid(struct router *, uint32_t vaddr);

#endif