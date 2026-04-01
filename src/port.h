#ifndef __PORT_H__
#define __PORT_H__

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#define PORT_RANGE_START 60000
#define PORT_RANGE_END   65000
#define POOL_SIZE (PORT_RANGE_END - PORT_RANGE_START + 1)

typedef struct {
    uint8_t bitmap[POOL_SIZE / 8 + 1]; // 位图空间
    uint16_t last_pos;                 // 上次分配位置，用于循环查找
    pthread_mutex_t lock;              // 端口分配必须保证原子性
} port_pool_t;

port_pool_t* port_pool_create();
uint16_t port_pool_get(port_pool_t *pool);      // 申请一个随机/可用端口
void port_pool_put(port_pool_t *pool, uint16_t port); // 释放端口
void port_pool_destroy(port_pool_t *pool);

#endif