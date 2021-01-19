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

#ifndef __VLN_HOST__
#define __VLN_HOST__

#include "npb_manager.h"
#include <stdint.h>
#include <uthash.h>

struct vln_host {
    uint32_t vaddr;
    uint32_t udp_addr;
    uint16_t udp_port;
    int sock_fd;

    struct mngr_packet_status rpacket;

    UT_hash_handle hh;
};

#endif