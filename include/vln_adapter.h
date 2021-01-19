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

#ifndef __VLN_ADAPTER__
#define __VLN_ADAPTER__

#include <linux/if.h>
#include <stdint.h>
#include <vln_types.h>

#define VLN_ADAPTER_NAME_SIZE IFNAMSIZ

struct vln_adapter {
    int fd;
    char name[VLN_ADAPTER_NAME_SIZE];
};

struct vln_adapter *vln_adapter_create(const char *name);

void vln_adapter_destroy(struct vln_adapter *);

int vln_adapter_set_network(struct vln_adapter *adapter, uint32_t addr,
                            uint32_t maskaddr, uint32_t broadaddr);

void vln_adapter_set_network2(struct vln_adapter *adapter,
                              struct vln_network *network, uint32_t vaddr);

#endif