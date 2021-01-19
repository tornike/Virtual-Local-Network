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

#ifndef __VLN_EPOLL_EVENT__
#define __VLN_EPOLL_EVENT__

typedef enum vln_descriptor_type {
    Peer_Socket,
    Router_Pipe,
    Listen_Socket
} vln_descriptor_type;

typedef union vln_epoll_data {
    void *ptr;
    int fd;
} vln_epoll_data_t;

struct vln_epoll_event {
    vln_descriptor_type type;
    vln_epoll_data_t data;
};

#endif
