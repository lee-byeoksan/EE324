#ifndef PROJ2_LRU_CACHE_H
#define PROJ2_LRU_CACHE_H

#include <stdlib.h>
#include "centry.h"

#define LRU_CACHE_ENOKEY -1
#define LRU_CACHE_EINVAL -2
#define LRU_CACHE_EEXIST -3
#define LRU_CACHE_ELARGE -4

struct lru_cache;

struct lru_cache *lru_cache_new(size_t max_size, size_t max_obj_size);
void lru_cache_del(struct lru_cache *cache);
int lru_cache_add(struct lru_cache *cache, struct centry *entry);
struct centry *lru_cache_find(struct lru_cache *cache, const char *key);
size_t lru_cache_max_size(struct lru_cache *cache);
size_t lru_cache_max_obj_size(struct lru_cache *cache);
void lru_cache_lock(struct lru_cache *cache);
void lru_cache_unlock(struct lru_cache *cache);

#endif /* PROJ2_LRU_CACHE_H */
