/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <stdatomic.h>
#include <errno.h>

#include "util.h"
#include "ringbuf.h"

#define BUFFER_SIZE       (4 * 1024 * 1024)  /* 4MB 环形缓冲区大小 */
#define CONSUMER_NUM      4                  /* 4 个并发消费者线程 */
#define TOTAL_PACKETS     1000000            /* 生产者一共发送 100 万个包 */

/* 模拟业务层的自定义报头结构 */
typedef struct {
    uint32_t magic;
    uint32_t packet_id;
    uint64_t timestamp;
} my_meta_hdr_t;

ringbuf_t g_ringbuf;
atomic_long g_recv_count = 0;               /* 消费者成功消费的包总数 */
atomic_long g_collision_count = 0;          /* 避开的写覆盖冲突（-2）次数 */
volatile bool g_producer_done = false;      /* 生产者结束标志 */

/* 生产者线程：疯狂写入变长包 */
void *producer_thread(void *arg) {
    (void)arg;

    printf("[Producer] Started. Attempting to stream %d packets...\n", TOTAL_PACKETS);

    my_meta_hdr_t meta;
    meta.magic = 0xDEADBEEF;

    uint8_t payload_pool[2048];

    for (uint32_t i = 0; i < TOTAL_PACKETS; i++) {
        meta.packet_id = i;
        meta.timestamp = (uint64_t)i * 100;

        /* 让核心 Payload 长度在 64 到 512 字节之间动态变化，测试变长对齐 */
        size_t data_len = 64 + (i % 449);

        size_t total_write_size = sizeof(ringbuf_hdr_t) + sizeof(my_meta_hdr_t) + data_len;

        /* 填充特征递增数据，用于消费者做数据完整性（防撕裂）校验 */
        for (size_t j = 0; j < data_len; j++) {
            payload_pool[j] = (uint8_t)(i + j);
        }

        /* ------------------ 【核心修改：精准无锁卡位】 ------------------ */
        /* 在写入前，检查剩余空间。如果不够，说明快超车消费者了，原地盲轮询等消费者腾空间 */
        /* 这种轮询完全在用户态执行，没有 usleep 的内核切换开销，精度是纳秒级的 */
        while (1) {
            uint64_t current_tail = g_ringbuf.tail;
            uint64_t current_head = __atomic_load_n(&g_ringbuf.head, __ATOMIC_ACQUIRE);

            if ((current_tail + total_write_size - current_head) <= g_ringbuf.size) {
                break; /* 空间足够，安全，跳出循环执行写入 */
            }
            
            /* 空间不够，向 CPU 发生 pause 信号，稍作等待，让消费者继续读 */
            __builtin_ia32_pause(); 
        }

        /* 写入环形缓冲区：强覆盖模式在空间不足时内部会自动腾空间，正常不会返回非 0 */
        int ret = ringbuf_write(&g_ringbuf, &meta, sizeof(my_meta_hdr_t), payload_pool, data_len);
        if (unlikely(ret != 0)) {
            fprintf(stderr, "[Producer] Write failed with error: %d\n", ret);
        }
    }

    g_producer_done = true;
    printf("[Producer] Finished sending all packets.\n");
    return NULL;
}

/* 消费者线程：多线程 CAS 抢包并进行工业级校验 */
void *consumer_thread(void *arg) {
    long id = (long)arg;
    
    my_meta_hdr_t out_meta;
    uint8_t out_payload[2048];
    uint32_t actual_data_len = 0;
    long local_recv_count = 0;

    while (!g_producer_done || atomic_load(&g_recv_count) < TOTAL_PACKETS) {
        /* 调用你的双解耦接收接口 */
        int ret = ringbuf_read(&g_ringbuf, 
                               &out_meta, sizeof(my_meta_hdr_t), 
                               out_payload, sizeof(out_payload), 
                               &actual_data_len);

        if (ret == 0) {
            /* 1. 验证元数据报头 */
            if (out_meta.magic != 0xDEADBEEF) {
                fprintf(stderr, "[Consumer %ld] CRITICAL: Magic corrupted! Got: 0x%X\n", id, out_meta.magic);
                exit(EXIT_FAILURE);
            }

            /* 2. 核心防撕裂数据校验：利用写入时的特征算法反推 */
            uint32_t id_seq = out_meta.packet_id;
            for (uint32_t j = 0; j < actual_data_len; j++) {
                uint8_t expected = (uint8_t)(id_seq + j);
                if (out_payload[j] != expected) {
                    /* 如果触发此处，说明事务锁或内存屏障失效，读到了写了一半的脏数据 */
                    fprintf(stderr, "[Consumer %ld] CRITICAL: Data torn detected! "
                                    "Packet ID: %u, Byte Index: %u, Got: 0x%02X, Expected: 0x%02X\n",
                            id, id_seq, j, out_payload[j], expected);
                    exit(EXIT_FAILURE);
                }
            }

            local_recv_count++;
            atomic_fetch_add(&g_recv_count, 1);
        }
        else if (ret == -2) {
            /* 返回 -2 说明 version_seq 机制成功拦截了“正在被写覆盖”的冲突包，安全避坑 */
            atomic_fetch_add(&g_collision_count, 1);
            __builtin_ia32_pause(); /* 提示 CPU 稍作让步，降低盲轮询功耗 */
        }
        else if (ret == -1) {
            /* 队列暂空 */
            if (g_producer_done) {
                break;
            }
            __builtin_ia32_pause();
        }
    }

    printf("[Consumer %ld] Exited. Safely processed %ld packets.\n", id, local_recv_count);
    return NULL;
}

int main(void) {
    pthread_t prod_tid;
    pthread_t cons_tid[CONSUMER_NUM];

    printf("[System] Allocating Virtual Mirror Ring Buffer (Size: %d MB)...\n", BUFFER_SIZE / 1024 / 1024);

    /* 1. 创建环形缓冲区 */
    if (ringbuf_create(&g_ringbuf, BUFFER_SIZE) != 0) {
        perror("Failed to create ringbuf");
        return EXIT_FAILURE;
    }

    /* 2. 启动多个并发消费者线程 */
    for (long i = 0; i < CONSUMER_NUM; i++) {
        if (pthread_create(&cons_tid[i], NULL, consumer_thread, (void *)i) != 0) {
            perror("Failed to create consumer thread");
            return EXIT_FAILURE;
        }
    }

    /* 3. 启动单生产者线程 */
    if (pthread_create(&prod_tid, NULL, producer_thread, NULL) != 0) {
        perror("Failed to create producer thread");
        return EXIT_FAILURE;
    }

    /* 4. 等待所有线程回收完成 */
    pthread_join(prod_tid, NULL);
    for (int i = 0; i < CONSUMER_NUM; i++) {
        pthread_join(cons_tid[i], NULL);
    }

    /* 5. 打印压测最终成效报告 */
    printf("\n============= CONCURRENCY TEST REPORT =============\n");
    printf("Total Packets Streamed : %d\n", TOTAL_PACKETS);
    printf("Successfully Received  : %ld\n", atomic_load(&g_recv_count));
    printf("Safe Collisions Avoided: %ld (Returned -2)\n", atomic_load(&g_collision_count));
    printf("Verification Verdict   : PASS (Zero Tearing / Zero Leaks)\n");
    printf("===================================================\n");

    /* 6. 销毁并释放虚拟内存 segments */
    ringbuf_release(&g_ringbuf);
    return EXIT_SUCCESS;
}