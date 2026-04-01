/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __NAT_H__
#define __NAT_H__

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

#define NAT_HASH_SIZE 1024  // 哈希桶数量
#define MAX_PROXY_PORT 65535
#define MIN_PROXY_PORT 10000 // 代理端口起始范围

typedef struct nat_entry {
    uint16_t proxy_port;     // Key: 映射端口 (NBO)
    uint32_t term_ip;        // Value: 终端原始 IP (NBO)
    uint16_t term_port;      // Value: 终端原始端口 (NBO)
    uint8_t  term_mac[6];    // Value: 终端 MAC
    time_t   last_active;    // 上次活跃时间

    struct nat_entry *hash_next; // 哈希桶链表指针
    struct nat_entry *lru_next;  // LRU 全局链表后继
    struct nat_entry *lru_prev;  // LRU 全局链表前驱
} nat_entry_t;

typedef struct nat_table {
    nat_entry_t *hash_table[NAT_HASH_SIZE];
    nat_entry_t *lru_head;
    nat_entry_t *lru_tail;
    pthread_rwlock_t lock;
    uint32_t timeout_sec;
    uint32_t current_count;
} nat_table_t;

nat_table_t* nat_table_create(uint32_t timeout_sec);
void nat_table_destroy(nat_table_t *table);
bool nat_table_insert(nat_table_t *table, uint16_t proxy_port, uint32_t ip, uint16_t port, uint8_t *mac);
bool nat_table_lookup(nat_table_t *table, uint16_t proxy_port, uint32_t *ip, uint16_t *port, uint8_t *mac);
void nat_table_gc(nat_table_t *table);

#endif