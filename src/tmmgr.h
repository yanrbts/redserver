/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __TMMGR_H__
#define __TMMGR_H__

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

typedef void (*timer_callback_fn)(void *user_data);

typedef struct {
    uint64_t           expire_ms;
    uint32_t           interval_ms;
    timer_callback_fn  callback;
    void              *user_data;
    uint32_t           id;
} timer_node_t;

typedef struct {
    timer_node_t    **heap;
    uint32_t          size;
    uint32_t          capacity;
    uint32_t          next_id;
    pthread_mutex_t   lock;
    pthread_t         thread_id;
    volatile bool     running;
    uint32_t          tick_ms;    /* Precision of the thread loop */
} timer_manager_t;

/**
 * @brief Create and initialize a timer manager instance.
 * @param capacity Max concurrent timers.
 * @return Pointer to the manager, or NULL on failure.
 */
timer_manager_t* tm_create(uint32_t capacity);

/**
 * @brief Starts a background thread to drive the timer (tm_tick).
 * @param tm Pointer to the manager.
 * @param tick_ms Sleep interval for the thread (e.g., 10ms).
 * @return 0 on success, -1 on failure.
 */
int tm_run(timer_manager_t *tm, uint32_t tick_ms);

/**
 * @brief Registers a new timer into the management system.
 * * This function allocates a new timer node and inserts it into the min-priority heap.
 * The operation is thread-safe and utilizes a recursive mutex to allow calls from 
 * within other timer callbacks.
 * @param tm           Pointer to the timer manager instance.
 * @param delay_ms     Relative delay in milliseconds before the first execution.
 * @param interval_ms  Periodic interval in milliseconds. If 0, the timer is one-shot.
 * @param cb           Function pointer to the user-defined callback.
 * @param arg          User-defined context passed as an argument to the callback.
 * @return uint32_t    A unique Timer ID (positive) on success, or 0 if the manager 
 * is full or the allocation failed.
 * @note Complexity: O(log n) for heap insertion (sift_up).
 */
uint32_t tm_add(timer_manager_t *tm, uint32_t delay_ms, uint32_t interval_ms, timer_callback_fn cb, void *arg);
void tm_del(timer_manager_t *tm, uint32_t timer_id);

/**
 * @brief Stops the thread and destroys the manager.
 */
void tm_destroy(timer_manager_t *tm);

#endif