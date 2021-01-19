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

#ifndef __VLN_ROUTER_PROTOCOL__
#define __VLN_ROUTER_PROTOCOL__

#include <stdint.h>

#define __VLN_PACKED __attribute__((packed))

typedef uint8_t router_packet_type;

#define INIT 1
#define KEEPALIVE 2
#define DATA 3

struct router_packet_header {
    router_packet_type type;
} __VLN_PACKED;

struct router_init_payload {
    uint32_t vaddr; /* Addr of init sender */
} __VLN_PACKED;

struct router_keepalive_payload {
    uint32_t vaddr; /* Addr of keepalive sender */
} __VLN_PACKED;

#define ROUTER_PACKET_PAYLOAD(packet)                                          \
    ((uint8_t *)packet + sizeof(struct router_packet_header))

#endif