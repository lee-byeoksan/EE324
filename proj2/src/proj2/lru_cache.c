#include "lru_cache.h"
#include "centry.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdio.h>

struct lru_cache {
    size_t count;
    size_t size; /* bytes */
    size_t max_size; /* bytes */
    size_t max_obj_size; /* bytes */
    struct centry *entries;
    pthread_mutex_t mutex;
};

static struct centry *__lru_cache_find(struct lru_cache *cache, const char *key, int update);
static void __lru_cache_evict(struct lru_cache *cache, size_t size);

struct lru_cache *lru_cache_new(size_t max_size, size_t max_obj_size)
{
    struct lru_cache *cache;
    cache = (struct lru_cache *)malloc(sizeof(*cache));
    if (cache != NULL) {
        cache->count = 0;
        cache->size = 0;
        cache->max_size = max_size;
        cache->max_obj_size = max_obj_size;
        cache->entries = NULL;
        pthread_mutex_init(&cache->mutex, NULL);
    }
    return cache;
}

void lru_cache_del(struct lru_cache *cache)
{
    struct centry *entry, *next_entry;
    if (cache == NULL) {
        return;
    }

    next_entry = cache->entries;
    for (entry = next_entry; entry != NULL; entry = next_entry) {
        next_entry = centry_next(entry);
        centry_del(entry);
    }

    pthread_mutex_destroy(&cache->mutex);
    free(cache);
}

/*
 * Returns 0 on success or 1 otherwise.
 */
int lru_cache_add(struct lru_cache *cache, struct centry *entry)
{
    if (entry == NULL) {
        return LRU_CACHE_EINVAL;
    }

    if (centry_key(entry) == NULL) {
        return LRU_CACHE_ENOKEY;
    }

    if (centry_size(entry) > cache->max_obj_size) {
        return LRU_CACHE_ELARGE;
    }

    if (__lru_cache_find(cache, centry_key(entry), false)) {
        return LRU_CACHE_EEXIST;
    }

    if (cache->size + centry_size(entry) > cache->max_size) {
        printf("evict\n");
        __lru_cache_evict(cache, centry_size(entry));
    }

    if (cache->entries == NULL) {
        cache->entries = entry;
    } else {
        centry_add_prev(cache->entries, entry);
        cache->entries = entry;
    }

    cache->size += centry_size(entry);
    cache->count += 1;
    return 0;
}

static struct centry *__lru_cache_find(struct lru_cache *cache, const char *key, int update)
{
    struct centry *entry, *next_entry;
    if (cache == NULL) {
        return NULL;
    }

    next_entry = cache->entries;
    for (entry = next_entry; entry != NULL; entry = next_entry) {
        next_entry = centry_next(entry);
        if (!strcmp(centry_key(entry), key)) {
            break;
        }
    }

    if (entry != NULL && entry != cache->entries && update) {
        centry_remove(entry);
        centry_add_prev(cache->entries, entry);
        cache->entries = entry;
    }

    return entry;
}

/*
 * Evict cache entries to add entry with size of "size"
 */
static void __lru_cache_evict(struct lru_cache *cache, size_t size)
{
    if (cache->entries == NULL) {
        return;
    }

    struct centry *entry, *next_entry;
    for (entry = next_entry; next_entry != NULL; entry = next_entry) {
        next_entry = centry_next(entry);
    }

    struct centry *last = entry;

    while (cache->size + size > cache->max_size) {
        struct centry *prev_entry;
        prev_entry = centry_prev(last);
        centry_remove(last);
        cache->size -= centry_size(last);
        printf("evict\n");
        centry_del(last);
        entry = prev_entry;
        cache->count -= 1;
    }
}

struct centry *lru_cache_find(struct lru_cache *cache, const char *key)
{
    struct centry *entry;
    entry = __lru_cache_find(cache, key, true);
    return entry;
}

size_t lru_cache_max_size(struct lru_cache *cache)
{
    return cache->max_size;
}

size_t lru_cache_max_obj_size(struct lru_cache *cache)
{
    return cache->max_obj_size;
}

void lru_cache_lock(struct lru_cache *cache)
{
    pthread_mutex_lock(&cache->mutex);
}

void lru_cache_unlock(struct lru_cache *cache)
{
    pthread_mutex_unlock(&cache->mutex);
}
