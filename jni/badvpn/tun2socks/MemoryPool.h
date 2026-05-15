#ifndef MEMORY_POOL_H
#define MEMORY_POOL_H

#include <stddef.h>
#include <pthread.h>

typedef struct PoolNode {
    struct PoolNode *next;
} PoolNode;

typedef struct {
    PoolNode *head;
    size_t block_size;
    size_t cached;
    size_t max_cached;
    size_t total_allocations;
    size_t cache_hits;
    size_t outstanding;
    size_t high_watermark;
    pthread_mutex_t lock;
    int initialized;
} MemoryPool;

void pool_init(MemoryPool *pool, size_t block_size);
void pool_set_max_cached(MemoryPool *pool, size_t max_cached);
void pool_free_all(MemoryPool *pool);
void *pool_alloc(MemoryPool *pool);
void *pool_alloc_zero(MemoryPool *pool);
void pool_free(MemoryPool *pool, void *ptr);
void pool_get_stats(MemoryPool *pool, size_t *cached, size_t *outstanding, size_t *high_watermark);

#endif
