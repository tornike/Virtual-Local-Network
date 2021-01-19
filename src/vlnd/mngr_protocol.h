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

#ifndef __VLN_MANAGER_PROTOCOL__
#define __VLN_MANAGER_PROTOCOL__

#include <stdint.h>
#include <vln_constants.h>
#include <vln_types.h>

#define CONNECT 1
#define NETWORK 2
#define ROOTHOST 3
#define UPDATES 4
#define UPDATEDIS 5
#define ERROR 6
#define NAME_OR_PASSWOR 7

typedef uint8_t mngr_packet_type;

struct mngr_packet_header {
    mngr_packet_type type;
    uint32_t payload_length;
} __VLN_PACKED;

struct mngr_connect_payload {
    char network_name[NETWORK_NAME_MAX_LENGTH];
    // char network_password[NETWORK_NAME_MAX_LENGTH];
} __VLN_PACKED;

struct mngr_network_payload {
    uint32_t vaddr;
    uint32_t addr;
    uint32_t maskaddr;
    uint32_t broadaddr;
} __VLN_PACKED;

struct mngr_roothost_payload {
    uint32_t vaddr;
    uint16_t rport;
} __VLN_PACKED;

struct mngr_update_payload {
    uint32_t svaddr;
    uint32_t dvaddr;
    uint32_t vaddr;
    uint32_t raddr;
    uint16_t rport;
} __VLN_PACKED;

struct mngr_updatedis_payload {
    uint32_t vaddr;
} __VLN_PACKED;

struct mngr_error_payload {
    uint8_t type;
} __VLN_PACKED;

union mngr_packet_payload {
    struct mngr_connect_payload connect_payload;
    struct mngr_network_payload network_payload;
    struct mngr_roothost_payload roothost_payload;
    struct mngr_update_payload update_payload;
    struct mngr_updatedis_payload updatedis_payload;
    struct mngr_error_payload error_payload;
} __VLN_PACKED;

#define PACKET_PAYLOAD(packet)                                                 \
    ((uint8_t *)packet + sizeof(struct mngr_packet_header))

#endif