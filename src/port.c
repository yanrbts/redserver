#include <stdlib.h>
#include <string.h>
#include "port.h"

port_pool_t* port_pool_create() {
    port_pool_t *pool = (port_pool_t*)calloc(1, sizeof(port_pool_t));
    if (pool) pthread_mutex_init(&pool->lock, NULL);
    return pool;
}

uint16_t port_pool_get(port_pool_t *pool) {
    pthread_mutex_lock(&pool->lock);
    
    uint16_t start = pool->last_pos;
    for (uint16_t i = 0; i < POOL_SIZE; i++) {
        uint16_t current = (start + i) % POOL_SIZE;
        // 检查位图中该位是否为 0
        if (!(pool->bitmap[current / 8] & (1 << (current % 8)))) {
            // 标记为已占用
            pool->bitmap[current / 8] |= (1 << (current % 8));
            pool->last_pos = (current + 1) % POOL_SIZE;
            
            pthread_mutex_unlock(&pool->lock);
            return (uint16_t)(current + PORT_RANGE_START);
        }
    }
    
    pthread_mutex_unlock(&pool->lock);
    return 0; // 池满
}

void port_pool_put(port_pool_t *pool, uint16_t port) {
    if (port < PORT_RANGE_START || port > PORT_RANGE_END) return;
    
    uint16_t pos = port - PORT_RANGE_START;
    pthread_mutex_lock(&pool->lock);
    // 清位操作
    pool->bitmap[pos / 8] &= ~(1 << (pos % 8));
    pthread_mutex_unlock(&pool->lock);
}

void port_pool_destroy(port_pool_t *pool) {
    if (pool) {
        pthread_mutex_destroy(&pool->lock);
        free(pool);
    }
}