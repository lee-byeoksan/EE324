#include "thread_pool.h"

#include <pthread.h>
#include <sys/types.h>
#include <stdbool.h>

#define MAX_THREAD_NUM 128

struct work {
    struct work *prev, *next;
    workfunc func;
    void *arg;
};

struct thread {
    struct thread *prev, *next;
    pthread_t pthread;
    struct thread_pool *pool;
};

struct thread_pool {
    bool running;
    size_t size;
    size_t running_size;
    struct thread *thread_head;
    struct work *work_head;
    pthread_cond_t work_cv;
    pthread_mutex_t work_mtx;
    pthread_cond_t finish_cv;
    pthread_mutex_t finish_mtx;
};

#define THREAD_POOL_LIST_ADD(pool, member, type, entry) \
    do { \
        if (pool->member == NULL) { \
            entry->next = entry->prev = entry; \
            pool->member = entry; \
        } else { \
            type *prev; \
            prev = pool->member->prev; \
            entry->prev = prev; \
            entry->next = pool->member; \
            prev->next = entry; \
            pool->member->prev = entry; \
        } \
    } while(0)

static int thread_pool_init(struct thread_pool *pool, size_t size);
static void thread_pool_insert_thread(struct thread_pool *pool, struct thread *thread);
static void thread_pool_insert_work(struct thread_pool *pool, struct work *work);
static struct work *thread_pool_remove_work(struct thread_pool *pool);
static void thread_loop(void *self);
static void thread_pool_release_threads(struct thread_pool *pool);
static void thread_pool_release_works(struct thread_pool *pool);

static struct thread *new_thread(struct thread_pool *pool);
static struct work *new_work(workfunc work, void *arg);

struct thread_pool *thread_pool_new(size_t size) {
    struct thread_pool *pool = malloc(sizeof(*pool));

    if (pool == NULL) {
        return NULL;
    }

    if (!thread_pool_init(pool, size)) {
        thread_pool_del(pool);
        return NULL;
    }

    return pool;
}

void thread_pool_del(struct thread_pool *pool) {
    thread_pool_stop(pool);

    thread_pool_release_threads(pool);
    thread_pool_release_works(pool);

    pthread_cond_destroy(&pool->work_cv);
    pthread_mutex_destroy(&pool->work_mtx);
    pthread_cond_destroy(&pool->finish_cv);
    pthread_mutex_destroy(&pool->finish_mtx);

    free(pool);
}

int thread_pool_add_work(struct thread_pool *pool, workfunc func, void *arg)
{
    struct work *work;
    if (!pool->running) {
        return 1;
    }

    work = new_work(func, arg);
    if (work == NULL) {
        return 1;
    }

    thread_pool_insert_work(pool, work);
    return 0;
}

void thread_pool_stop(struct thread_pool *pool)
{
    pool->running = false;
    pthread_mutex_lock(&pool->finish_mtx);
    while (pool->running_size > 0) {
        pthread_cond_wait(&pool->finish_cv, &pool->finish_mtx);
    }
    pthread_mutex_unlock(&pool->finish_mtx);
}

/*
 * returns 0 on success, 1 otherwise.
 */
static int thread_pool_init(struct thread_pool *pool, size_t size)
{
    int i;
    int result = 0;
    size = (size == 0) ? 1 : size;
    size = (size > MAX_THREAD_NUM) ? MAX_THREAD_NUM : size;
    pool->size = size;
    pool->work_head = NULL;
    pool->thread_head = NULL;
    pool->running = true;

    /* assume no error */
    pthread_cond_init(&pool->work_cv, NULL);
    pthread_mutex_init(&pool->work_mtx, NULL);
    pthread_cond_init(&pool->finish_cv, NULL);
    pthread_mutex_init(&pool->finish_mtx, NULL);

    for (i = 0; i < pool->size; i++) {
        struct thread *thread = new_thread(pool);
        if (thread == NULL) {
            result = 1;
            goto out;
        }

        thread_pool_insert_thread(pool, thread);
        if (pthread_create(&thread->pthread, NULL, thread_loop, thread)) {
            result = 1;
            goto out;
        }

        if (pthread_detach(&thread->pthread)) {
            result = 1;
            goto out;
        }
    }

out:
    pool->running_size = i;
    return result;
}

static struct thread *new_thread(struct thread_pool *pool)
{
    struct thread *thread;
    thread = malloc(sizeof(*thread));
    if (thread == NULL) {
        return NULL;
    }

    thread->pool = pool;
    return thread;
}

static struct work *new_work(workfunc func, void *arg)
{
    struct work *work;
    work = malloc(sizeof(*work));
    if (work == NULL) {
        return NULL;
    }

    work->func = work;
    work->arg = arg;
    return work;
}

static void thread_pool_insert_thread(struct thread_pool *pool, struct thread *thread)
{
    THREAD_POOL_LIST_ADD(pool, thread_head, struct thread, thread);
}

static void thread_pool_insert_work(struct thread_pool *pool, struct work *work)
{
    pthread_mutex_lock(&pool->work_mtx);
    THREAD_POOL_LIST_ADD(pool, work_head, struct work, work);
    pthread_mutex_unlock(&pool->work_mtx);
}

static struct work *thread_pool_remove_work(struct thread_pool *pool)
{
    struct work *work;
    pthread_mutex_lock(&pool->work_mtx);
    if (pool->work_head == NULL) {
        pthread_mutex_unlock(&pool->work_mtx);
        return NULL;
    }

    work = pool->work_head;
    if (work->next == work) {
        pool->work_head = NULL;
        pthread_mutex_unlock(&pool->work_mtx);
        return work;
    }

    struct work *prev, *next;
    prev = work->prev;
    next = work->next;
    prev->next = next;
    next->prev = prev;

    pool->work_head = next;
    pthread_mutex_unlock(&pool->work_mtx);
    return work;
}

static void *thread_loop(void *self)
{
    struct thread *thread = (struct thread *)self;

    while (true) {
        struct work *work;

        /* wait until work is available */
        pthread_mutex_lock(&pool->work_mtx);
        while (pool->work_head == NULL && pool->running) {
            pthread_cond_wait(&pool->work_cv, &pool->work_mtx);
        }

        /* no pending work and !pool->running */
        if (pool->work_head == NULL) {
            pthread_mutex_unlock(&pool->work_mtx);
            break;
        }

        work = thread_pool_remove_work(pool);
        pthread_mutex_unlock(&pool->work_mtx);

        work->func(work->args);
        free(work);
    }

    /* signal I am done */
    pthread_mutex_lock(&pool->finish_mtx);
    --pool->running_size;
    pthread_cond_signal(&pool->finish_cv);
    pthread_mutex_unlock(&pool->finish_mtx);

    return NULL;
}

static void thread_pool_release_threads(struct thread_pool *pool)
{
    struct thread *thread_head, *thread, *thread_next;
    thread_head = pool->thread_head;
    if (thread_head != NULL) {
        thread_head->prev->next = NULL;
    }
    for (thread = thread_head; thread != NULL; thread = thread_next) {
        thread_next = thread->next;
        free(thread);
    }
    pool->thread_head = NULL;
}

static void thread_pool_release_works(struct thread_pool *pool)
{
    struct work *work_head, *work, *work_next;
    work_head = pool->work_head;
    if (work_head != NULL) {
        work_head->prev->next = NULL;
    }
    for (work = work_head; work != NULL; work = work_next) {
        work_next = work->next;
        free(work);
    }
    pool->work_head = NULL;
}

