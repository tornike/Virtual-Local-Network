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

/*
 * Nonblocking packet buffer
 */

#ifndef __VLN_NPB_MANAGER__
#define __VLN_NPB_MANAGER__

#include "mngr_protocol.h"
#include <stddef.h>

typedef enum { Waiting_Header, Waiting_Payload, Ready } mngr_packet_state_t;

struct mngr_packet_status {
    mngr_packet_state_t state;
    struct mngr_packet_header *header;
    void *payload;
    size_t left_bytes;
    void *buffer_pos;

    uint8_t __buffer[sizeof(struct mngr_packet_header) +
                     sizeof(union mngr_packet_payload)];
};

void initialize_packet(struct mngr_packet_status *p);
void reset_packet(struct mngr_packet_status *p);
void read_packet(int sock_fd, struct mngr_packet_status *p);

#endif