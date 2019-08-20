
#include <pthread.h>
#include <stdlib.h>

#include "taskexecutor.h"
#include "utlist.h"

struct task_info_wrapper {
    struct task_info *tinfo;
    struct task_info_wrapper *next;
    struct task_info_wrapper *prev;
};

struct taskexecutor {
    Handler handler;
    void *handler_args;
    struct task_info_wrapper *queue;
    pthread_mutex_t queue_lock;
    pthread_cond_t queue_cond;
};

struct taskexecutor *taskexecutor_create(Handler handler, void *args)
{
    struct taskexecutor *new_exec;
    if (((void *)(new_exec = malloc(sizeof(struct taskexecutor))) == NULL))
        return new_exec;

    new_exec->handler = handler;
    new_exec->handler_args = args;
    new_exec->queue = NULL;
    pthread_mutex_init(&new_exec->queue_lock, NULL);
    pthread_cond_init(&new_exec->queue_cond, NULL);

    return new_exec;
}

void taskexecutor_destroy(struct taskexecutor *executor)
{
    pthread_mutex_destroy(&executor->queue_lock);
    pthread_cond_destroy(&executor->queue_cond);
    free(executor);
}

void taskexecutor_start(struct taskexecutor *executor)
{
    struct task_info *cur_task_info;
    struct task_info_wrapper *tiw;
    while (1) {
        pthread_mutex_lock(&executor->queue_lock);
        if (executor->queue == NULL) {
            pthread_cond_wait(&executor->queue_cond, &executor->queue_lock);
        }
        tiw = executor->queue;
        cur_task_info = tiw->tinfo;
        DL_DELETE(executor->queue, executor->queue);
        pthread_mutex_unlock(&executor->queue_lock);

        free(tiw);
        executor->handler(executor->handler_args, cur_task_info);
        free(cur_task_info);
    }
}

void taskexecutor_add_task(struct taskexecutor *executor,
                           struct task_info *task_info)
{
    struct task_info_wrapper *new_tiw;
    int was_empty;
    pthread_mutex_lock(&executor->queue_lock);
    was_empty = executor->queue == NULL ? 1 : 0;
    new_tiw = malloc(sizeof(struct task_info_wrapper));
    new_tiw->tinfo = task_info;
    DL_APPEND(executor->queue, new_tiw);
    if (was_empty)
        pthread_cond_signal(&executor->queue_cond);
    pthread_mutex_unlock(&executor->queue_lock);
}