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

#ifndef __VLN_DEFAULT_CONFIG__
#define __VLN_DEFAULT_CONFIG__

#define VLN_USER "vln"

#define __VLN_LOG_FILENAME "vln.log"
#define __VLN_CONFIG_FILENAME "vln.conf"
#define __VLN_SOCK_FILENAME "vln.socket"

#ifdef DEVELOP
#define VLN_CONFIG_DIR "../etc/"
#define VLN_LOG_DIR "log/"
#define VLN_RUN_DIR "run/"
#define __VLN_CLIENT_CONFIG_FILENAME "vln_client.conf"
#define __VLN_SERVER_CONFIG_FILENAME "vln_server.conf"
#define VLN_CLIENT_CONFIG_FILE VLN_CONFIG_DIR __VLN_CLIENT_CONFIG_FILENAME
#define VLN_SERVER_CONFIG_FILE VLN_CONFIG_DIR __VLN_SERVER_CONFIG_FILENAME
#else
#define VLN_CONFIG_DIR "/etc/vln/"
#define VLN_LOG_DIR "/var/log/vln/"
#define VLN_RUN_DIR "/run/vln/"
#endif

#define VLN_LOG_FILE VLN_LOG_DIR __VLN_LOG_FILENAME
#define VLN_CONFIG_FILE VLN_CONFIG_DIR __VLN_CONFIG_FILENAME
#define VLN_SOCK_FILE VLN_RUN_DIR __VLN_SOCK_FILENAME

#endif