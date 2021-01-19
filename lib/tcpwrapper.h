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

#ifndef __TCP_WRAPPER__
#define __TCP_WRAPPER__

#include <stddef.h>

struct tcpwrapper;

struct tcpwrapper *tcpwrapper_create(int sockfd, size_t buffer_size);

void tcpwrapper_destroy(struct tcpwrapper *wrapper);

void tcpwrapper_set_die_flag(struct tcpwrapper *);

int recv_wrap(struct tcpwrapper *wrapper, void *buffer, size_t size);

int send_wrap(struct tcpwrapper *wrapper, void *buffer, size_t size);

#endif