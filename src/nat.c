#include <stdlib.h>
#include <string.h>
#include "nat.h"

#define GET_HASH(port) (port % NAT_HASH_SIZE)

// 内部函数：从 LRU 链表中移除节点
static void nat_lru_remove(nat_table_t *table, nat_entry_t *entry) {
    if (entry->lru_prev) 
        entry->lru_prev->lru_next = entry->lru_next;
    else 
        table->lru_head = entry->lru_next;
    
    if (entry->lru_next)
        entry->lru_next->lru_prev = entry->lru_prev;
    else
        table->lru_tail = entry->lru_prev;
}

// 内部函数：移动节点到 LRU 头部 (表示最新活跃)
static void nat_lru_add_head(nat_table_t *table, nat_entry_t *entry) {
    entry->lru_next = table->lru_head;
    entry->lru_prev = NULL;

    if (table->lru_head) 
        table->lru_head->lru_prev = entry;

    table->lru_head = entry;
    if (!table->lru_tail) 
        table->lru_tail = entry;
}

nat_table_t* nat_table_create(uint32_t timeout_sec) {
    nat_table_t *table = (nat_table_t*)calloc(1, sizeof(nat_table_t));
    if (!table) return NULL;
    
    table->timeout_sec = timeout_sec;
    pthread_rwlock_init(&table->lock, NULL);
    return table;
}

bool nat_table_insert(nat_table_t *table, uint16_t proxy_port, uint32_t ip, uint16_t port, uint8_t *mac) {
    pthread_rwlock_wrlock(&table->lock);
    
    uint32_t hash = GET_HASH(proxy_port);
    nat_entry_t *entry = table->hash_table[hash];
    
    // 1. 查找是否存在旧项
    while (entry) {
        if (entry->proxy_port == proxy_port) {
            entry->term_ip = ip;
            entry->term_port = port;
            if (mac) memcpy(entry->term_mac, mac, 6);
            entry->last_active = time(NULL);
            nat_lru_remove(table, entry);
            nat_lru_add_head(table, entry);
            pthread_rwlock_unlock(&table->lock);
            return true;
        }
        entry = entry->hash_next;
    }
    
    // 2. 创建新项
    entry = (nat_entry_t*)calloc(1, sizeof(nat_entry_t));
    if (!entry) {
        pthread_rwlock_unlock(&table->lock);
        return false;
    }
    
    entry->proxy_port = proxy_port;
    entry->term_ip = ip;
    entry->term_port = port;
    if (mac) memcpy(entry->term_mac, mac, 6);
    entry->last_active = time(NULL);
    
    // 插入哈希表
    entry->hash_next = table->hash_table[hash];
    table->hash_table[hash] = entry;
    
    // 插入 LRU
    nat_lru_add_head(table, entry);
    table->current_count++;
    
    pthread_rwlock_unlock(&table->lock);
    return true;
}

bool nat_table_lookup(nat_table_t *table, uint16_t proxy_port, uint32_t *ip, uint16_t *port, uint8_t *mac) {
    pthread_rwlock_wrlock(&table->lock); // 回程需要更新活跃时间，故使用写锁或通过原子操作优化
    
    uint32_t hash = GET_HASH(proxy_port);
    nat_entry_t *entry = table->hash_table[hash];
    
    while (entry) {
        if (entry->proxy_port == proxy_port) {
            *ip = entry->term_ip;
            *port = entry->term_port;
            if (mac) memcpy(mac, entry->term_mac, 6);
            
            // 更新活跃度
            entry->last_active = time(NULL);
            nat_lru_remove(table, entry);
            nat_lru_add_head(table, entry);
            
            pthread_rwlock_unlock(&table->lock);
            return true;
        }
        entry = entry->hash_next;
    }
    
    pthread_rwlock_unlock(&table->lock);
    return false;
}

void nat_table_gc(nat_table_t *table) {
    pthread_rwlock_wrlock(&table->lock);
    time_t now = time(NULL);
    nat_entry_t *curr = table->lru_tail;
    
    // 从链表尾部（最旧的）开始检查
    while (curr && (now - curr->last_active > table->timeout_sec)) {
        nat_entry_t *to_delete = curr;
        curr = curr->lru_prev; // 向上移动
        
        // 1. 从哈希表中移除
        uint32_t hash = GET_HASH(to_delete->proxy_port);
        nat_entry_t **pp = &table->hash_table[hash];
        while (*pp) {
            if (*pp == to_delete) {
                *pp = to_delete->hash_next;
                break;
            }
            pp = &((*pp)->hash_next);
        }
        
        // 2. 从 LRU 移除并释放
        nat_lru_remove(table, to_delete);
        free(to_delete);
        table->current_count--;
    }
    pthread_rwlock_unlock(&table->lock);
}

void nat_table_destroy(nat_table_t *table) {
    if (!table) return;

    nat_entry_t *curr = table->lru_head;
    while (curr) {
        nat_entry_t *next = curr->lru_next;
        free(curr);
        curr = next;
    }
    pthread_rwlock_destroy(&table->lock);

    free(table);
}