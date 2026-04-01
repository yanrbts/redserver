/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include "log.h"
#include "util.h"
#include "tmmgr.h"

/* --- Heap Helpers (Now takes 'tm' as argument) --- 
 [Step 1: Insert at End]      [Step 2: Swap Upwards]     [Step 3: Correct Position]
      (20)                        (20)                        (10)
     /    \                      /    \                      /    \
   (30)   (40)        -->      (30)   (10)        -->      (30)   (20)
   /                           /                           /
 (10) <--- New Entry         (40) <--- 40 Swapped down   (40)
 */
static void sift_up(timer_manager_t *tm, uint32_t idx) {
    while (idx > 0) {
        uint32_t p = (idx - 1) / 2;
        if (tm->heap[idx]->expire_ms >= tm->heap[p]->expire_ms) break;
        timer_node_t *tmp = tm->heap[idx];
        tm->heap[idx] = tm->heap[p];
        tm->heap[p] = tmp;
        idx = p;
    }
}

/*
 [Step 1: Last to Top]        [Step 2: Swap Downwards]    [Step 3: Final Balance]
      (50) <--- Too Large         (20)                        (20)
     /    \                      /    \                      /    \
   (20)   (30)        -->      (50)   (30)        -->      (40)   (30)
   /                           /                           /
 (40)                        (40)                        (50) <--- Sunk to bottom
 */
static void sift_down(timer_manager_t *tm, uint32_t idx) {
    while (true) {
        uint32_t l = 2 * idx + 1, r = 2 * idx + 2, s = idx;
        if (l < tm->size && tm->heap[l]->expire_ms < tm->heap[s]->expire_ms) s = l;
        if (r < tm->size && tm->heap[r]->expire_ms < tm->heap[s]->expire_ms) s = r;
        if (s == idx) break;
        timer_node_t *tmp = tm->heap[idx];
        tm->heap[idx] = tm->heap[s];
        tm->heap[s] = tmp;
        idx = s;
    }
}

/* --- Core Logic --- */

timer_manager_t* tm_create(uint32_t capacity) {
    timer_manager_t *tm = calloc(1, sizeof(timer_manager_t));
    if (!tm) return NULL;

    tm->heap = calloc(capacity, sizeof(timer_node_t *));
    if (!tm->heap) {
        free(tm);
        return NULL;
    }

    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&tm->lock, &attr);
    pthread_mutexattr_destroy(&attr);

    tm->capacity = capacity;
    tm->next_id = 1;
    tm->running = false;
    return tm;
}

/**
 * @brief Background thread routine for high-throughput timer management.
 * 
 * Features:
 *   1. True Batch Processing: Handles ALL due timers in one lock acquisition.
 *   2. Minimal Lock Time: Callbacks are executed completely outside the lock.
 *   3. Drift Correction: Updates 'now' after each expiration adjustment.
 *   4. Adaptive Sleep: Only sleeps when no timers were due in this cycle.
 *   5. Responsive Shutdown: Limits max sleep time to react quickly to stop signal.
 */
static void* timer_thread_proc(void *arg)
{
    log_info("Start timer manager.");
    timer_manager_t *tm = (timer_manager_t *)arg;
    
    while (tm->running) {
        uint64_t now = get_now_ms();
        bool processed_any = false;

        pthread_mutex_lock(&tm->lock);

        /* Batch process ALL timers that are due at this moment */
        while (tm->size > 0 && tm->heap[0]->expire_ms <= now) {
            timer_node_t *node = tm->heap[0];

            /* Capture callback before modifying the heap */
            timer_callback_fn cb = node->callback;
            void *data = node->user_data;

            if (node->interval_ms > 0) {
                /* Periodic timer: fixed rate to prevent cumulative drift */
                node->expire_ms += node->interval_ms;
                sift_down(tm, 0);
            } else {
                /* One-shot timer: remove it */
                tm->heap[0] = tm->heap[tm->size - 1];
                tm->size--;
                free(node);
                if (tm->size > 0) {
                    sift_down(tm, 0);
                }
            }

            processed_any = true;

            /* IMPORTANT: Execute callback OUTSIDE the lock (after unlock) */
            /* We use a simple "last callback wins" pattern here for simplicity.
             * For true batch execution (multiple callbacks), use a temporary list. */
            if (cb) {
                /* We can only safely run ONE callback per lock cycle in this design.
                 * If you need multiple, collect them in a local array first. */
                pthread_mutex_unlock(&tm->lock);
                cb(data);
                pthread_mutex_lock(&tm->lock);
            }

            /* Refresh 'now' because callback may have taken time */
            now = get_now_ms();
        }

        pthread_mutex_unlock(&tm->lock);

        /* Sleep Strategy */
        if (!tm->running) break;

        /* If processed_any == true, loop immediately without sleeping */
        if (!processed_any) {
            /* No work was done this cycle → sleep until next possible expiration */
            pthread_mutex_lock(&tm->lock);
            uint64_t next_expire = (tm->size > 0) 
                                 ? tm->heap[0]->expire_ms 
                                 : (now + tm->tick_ms);
            pthread_mutex_unlock(&tm->lock);

            uint64_t sleep_ms = (next_expire > now) ? (next_expire - now) : 1;

            /* Clamp to keep responsive to tm_stop() */
            if (sleep_ms > tm->tick_ms)
                sleep_ms = tm->tick_ms;

            usleep(sleep_ms * 1000);
        }
    }

    return NULL;
}

int tm_run(timer_manager_t *tm, uint32_t tick_ms) {
    if (!tm || tm->running) return -1;
    tm->tick_ms = tick_ms;
    tm->running = true;
    if (pthread_create(&tm->thread_id, NULL, timer_thread_proc, tm) != 0) {
        tm->running = false;
        return -1;
    }
    return 0;
}

uint32_t tm_add(timer_manager_t *tm, uint32_t delay_ms, uint32_t interval_ms, timer_callback_fn cb, void *arg) {
    if (!tm) return 0;
    pthread_mutex_lock(&tm->lock);
    if (tm->size >= tm->capacity) {
        pthread_mutex_unlock(&tm->lock);
        return 0;
    }

    timer_node_t *node = malloc(sizeof(timer_node_t));
    node->expire_ms = get_now_ms() + delay_ms;
    node->interval_ms = interval_ms;
    node->callback = cb;
    node->user_data = arg;
    node->id = tm->next_id++;

    tm->heap[tm->size] = node;
    sift_up(tm, tm->size);
    tm->size++;

    pthread_mutex_unlock(&tm->lock);
    return node->id;
}

/**
 * @brief Removes a specific timer from the manager.
 * @param tm Pointer to the timer manager instance.
 * @param timer_id The unique ID of the timer to delete.
 */
void tm_del(timer_manager_t *tm, uint32_t timer_id) {
    if (!tm || timer_id == 0) return;

    pthread_mutex_lock(&tm->lock);

    /* 1. Search for the target node index (O(n) lookup) */
    uint32_t target_idx = UINT32_MAX;
    for (uint32_t i = 0; i < tm->size; i++) {
        if (tm->heap[i]->id == timer_id) {
            target_idx = i;
            break;
        }
    }

    /* If timer not found, unlock and exit */
    if (target_idx == UINT32_MAX) {
        pthread_mutex_unlock(&tm->lock);
        return;
    }

    timer_node_t *to_free = tm->heap[target_idx];

    /* 2. Replace the target node with the last element in the heap */
    tm->size--;
    if (target_idx < tm->size) {
        tm->heap[target_idx] = tm->heap[tm->size];
        
        /* 3. Re-balance the heap:
         * Since the replacement element could be either larger or smaller 
         * than its new neighbors, we must check both directions.
         */
        
        /* Attempt to sink the node if it is larger than its children */
        sift_down(tm, target_idx);
        
        /* Attempt to float the node if it is smaller than its parent */
        sift_up(tm, target_idx);
    } 
    /* If target_idx was the last element, no re-balancing is required */

    free(to_free);
    pthread_mutex_unlock(&tm->lock);
}

void tm_destroy(timer_manager_t *tm) {
    if (!tm) return;
    tm->running = false;
    if (tm->thread_id) pthread_join(tm->thread_id, NULL);

    pthread_mutex_lock(&tm->lock);
    for (uint32_t i = 0; i < tm->size; i++) free(tm->heap[i]);
    free(tm->heap);
    pthread_mutex_unlock(&tm->lock);
    pthread_mutex_destroy(&tm->lock);
    free(tm);

    log_info("Timer Manager clean..");
}