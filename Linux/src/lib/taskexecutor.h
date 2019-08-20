#ifndef __TASK_EXECUTOR__
#define __TASK_EXECUTOR__

struct task_info {
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