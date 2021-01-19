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

#ifndef __TASK_EXECUTOR__
#define __TASK_EXECUTOR__

/* Executes passed Task with provided by user Handler function.
 * Users Handler function runs in separate thread created by taskexecutor.
 * Adding tasks is thread safe. */

struct task_info {
    /* Operations outside executor must be defined more than zero,
     * Otherwise task executor will be destroyed and cause undefined result. */
    int operation;
    void *args;
};

typedef void (*Handler)(void *args, struct task_info *);

struct taskexecutor;

struct taskexecutor *taskexecutor_create(Handler handler, void *args);

void taskexecutor_destroy(struct taskexecutor *executor);

void taskexecutor_start(struct taskexecutor *executor);

/*  task_info must be allocated by malloc.
 *  after execution finishes executor will free it.
 */
void taskexecutor_add_task(struct taskexecutor *executor,
                           struct task_info *task_info);

#endif