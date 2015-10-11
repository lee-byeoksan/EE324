#ifndef PROJ2_THREAD_POOL_H
#define PROJ2_THREAD_POOL_H

#include <pthread.h>

struct thread_pool;

typedef int (*workfunc)(void *arg);

struct thread_pool *thread_pool_new(size_t size);
void thread_pool_del(struct thread_pool *pool);
int thread_pool_add_work(struct thread_pool *pool, workfunc func, void *arg);
void thread_pool_stop(struct thread_pool *pool);

#endif /* PROJ2_THREAD_POOL_H */
