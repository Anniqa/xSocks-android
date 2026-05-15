#include "MemoryPool.h"
#include <stdlib.h>
#include <string.h>

static size_t effective_block_size(MemoryPool *pool) {
    size_t alloc_size = pool->block_size;
    if (alloc_size < sizeof(PoolNode)) {
        alloc_size = sizeof(PoolNode);
    }
    return alloc_size;
}

void pool_init(MemoryPool *pool, size_t block_size) {
    pool->head = NULL;
    pool->block_size = block_size;
    pool->cached = 0;
    pool->max_cached = 0;
    pool->total_allocations = 0;
    pool->cache_hits = 0;
    pool->outstanding = 0;
    pool->high_watermark = 0;
    pthread_mutex_init(&pool->lock, NULL);
    pool->initialized = 1;
}

void pool_set_max_cached(MemoryPool *pool, size_t max_cached) {
    if (!pool->initialized) return;

    pthread_mutex_lock(&pool->lock);
    pool->max_cached = max_cached;
    while (pool->cached > pool->max_cached && pool->head) {
        PoolNode *node = pool->head;
        pool->head = node->next;
        pool->cached--;
        free(node);
    }
    pthread_mutex_unlock(&pool->lock);
}

void pool_free_all(MemoryPool *pool) {
    if (!pool->initialized) return;

    pthread_mutex_lock(&pool->lock);
    PoolNode *current = pool->head;
    while (current) {
        PoolNode *next = current->next;
        free(current);
        current = next;
    }
    pool->head = NULL;
    pool->cached = 0;
    pthread_mutex_unlock(&pool->lock);

    pthread_mutex_destroy(&pool->lock);
    pool->initialized = 0;
}

void *pool_alloc(MemoryPool *pool) {
    if (!pool->initialized) return NULL;

    pthread_mutex_lock(&pool->lock);
    if (pool->head) {
        void *ptr = pool->head;
        pool->head = pool->head->next;
        pool->cached--;
        pool->cache_hits++;
        pool->outstanding++;
        if (pool->outstanding > pool->high_watermark) {
            pool->high_watermark = pool->outstanding;
        }
        pthread_mutex_unlock(&pool->lock);
        return ptr;
    }
    pthread_mutex_unlock(&pool->lock);

    void *ptr = malloc(effective_block_size(pool));
    if (!ptr) return NULL;

    pthread_mutex_lock(&pool->lock);
    pool->total_allocations++;
    pool->outstanding++;
    if (pool->outstanding > pool->high_watermark) {
        pool->high_watermark = pool->outstanding;
    }
    pthread_mutex_unlock(&pool->lock);

    return ptr;
}

void *pool_alloc_zero(MemoryPool *pool) {
    void *ptr = pool_alloc(pool);
    if (ptr) {
        memset(ptr, 0, effective_block_size(pool));
    }
    return ptr;
}

void pool_free(MemoryPool *pool, void *ptr) {
    if (!ptr) return;
    if (!pool->initialized) {
        free(ptr);
        return;
    }

    pthread_mutex_lock(&pool->lock);
    if (pool->outstanding > 0) {
        pool->outstanding--;
    }
    if (pool->max_cached > 0 && pool->cached >= pool->max_cached) {
        pthread_mutex_unlock(&pool->lock);
        free(ptr);
        return;
    }
    PoolNode *node = (PoolNode *)ptr;
    node->next = pool->head;
    pool->head = node;
    pool->cached++;
    pthread_mutex_unlock(&pool->lock);
}

void pool_get_stats(MemoryPool *pool, size_t *cached, size_t *outstanding, size_t *high_watermark) {
    if (!pool->initialized) {
        if (cached) *cached = 0;
        if (outstanding) *outstanding = 0;
        if (high_watermark) *high_watermark = 0;
        return;
    }

    pthread_mutex_lock(&pool->lock);
    if (cached) *cached = pool->cached;
    if (outstanding) *outstanding = pool->outstanding;
    if (high_watermark) *high_watermark = pool->high_watermark;
    pthread_mutex_unlock(&pool->lock);
}
