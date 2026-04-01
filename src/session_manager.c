/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * Professional Industrial-Grade Session Management.
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "session_manager.h"
#include "util.h"
#include "log.h"

/**
 * @brief Thread-safe session manager initialization.
 */
session_manager_t* session_mgr_create(const uint32_t timeout_ms) {
    /* Use calloc to ensure the entire manager handle is zero-initialized */
    session_manager_t *mgr = calloc(1, sizeof(session_manager_t));
    if (unlikely(!mgr)) {
        log_fatal("Failed to allocate session manager");
        return NULL;
    }

    mgr->table = NULL;
    mgr->timeout_ms = timeout_ms;
    
    /* Initialize Read-Write lock. Using default attributes for standard recursive safety. */
    if (unlikely(pthread_rwlock_init(&mgr->rwlock, NULL) != 0)) {
        log_fatal("Failed to initialize session manager rwlock");
        free(mgr);
        return NULL;
    }
    
    return mgr;
}

/**
 * @brief High-concurrency session update (Red -> Black).
 */
void session_mgr_update(session_manager_t *mgr, const session_key_t *key, const session_context_t *ctx) {
    if (unlikely(!mgr || !key || !ctx)) return;

    /* Cache current time to minimize system call overhead inside the lock */
    const uint64_t now_ms = get_now_ms();

    pthread_rwlock_wrlock(&mgr->rwlock);
    
    session_entry_t *entry = NULL;
    
    /* uthash lookup: O(1) */
    HASH_FIND(hh, mgr->table, key, sizeof(session_key_t), entry);

    if (entry) {
        /* Update existing context - Deep copy context values */
        memcpy(&entry->ctx, ctx, sizeof(session_context_t));
        entry->ctx.last_seen = now_ms;
    } else {
        /* Allocation on the cold path */
        entry = malloc(sizeof(session_entry_t));
        if (likely(entry)) {
            /**
             * Industrial Safety: Zero-fill the entire entry.
             * Prevents uthash lookup misses caused by random stack/heap junk in padding bytes.
             */
            memset(entry, 0, sizeof(session_entry_t));
            
            entry->key = *key; 
            memcpy(&entry->ctx, ctx, sizeof(session_context_t));
            entry->ctx.last_seen = now_ms;
            
            HASH_ADD(hh, mgr->table, key, sizeof(session_key_t), entry);
        } else {
            log_error("Session Manager: Out of memory during entry allocation");
        }
    }
    pthread_rwlock_unlock(&mgr->rwlock);
}

/**
 * @brief Fast-path session lookup (Black -> Red).
 * Optimized with Read-Lock for maximum throughput.
 */
bool session_mgr_lookup(session_manager_t *mgr, const session_key_t *key, session_context_t *out_ctx) {
    if (unlikely(!mgr || !key || !out_ctx)) return false;
    
    bool found = false;

    /* Shared read lock: multiple threads can look up simultaneously */
    pthread_rwlock_rdlock(&mgr->rwlock);
    
    session_entry_t *entry = NULL;
    HASH_FIND(hh, mgr->table, key, sizeof(session_key_t), entry);
    
    if (entry) {
        /* Fast copy of the context to the caller's stack */
        memcpy(out_ctx, &entry->ctx, sizeof(session_context_t));
        found = true;
    }

    pthread_rwlock_unlock(&mgr->rwlock);
    return found;
}

/**
 * @brief Background aging process.
 * Effectively cleans stale sessions to prevent memory exhaustion.
 */
void session_mgr_aging(session_manager_t *mgr) {
    if (unlikely(!mgr)) return;
    
    const uint64_t now = get_now_ms();
    session_entry_t *curr, *tmp;
    uint32_t expired_count = 0;

    /* Exclusive lock required for safe HASH_DEL */
    pthread_rwlock_wrlock(&mgr->rwlock);
    
    HASH_ITER(hh, mgr->table, curr, tmp) {
        /* Check if the session has exceeded the idle timeout */
        if (now - curr->ctx.last_seen > mgr->timeout_ms) {
            HASH_DEL(mgr->table, curr);
            free(curr);
            expired_count++;
        }
    }

    pthread_rwlock_unlock(&mgr->rwlock);

    /* Log summary instead of per-session details to avoid I/O bottlenecks */
    if (expired_count > 0) {
        log_debug("Session Aging: Cleared %u expired sessions", expired_count);
    }
}

/**
 * @brief Graceful shutdown and resource reclamation.
 */
void session_mgr_destroy(session_manager_t *mgr) {
    if (!mgr) return;
    
    session_entry_t *curr, *tmp;
    
    /* Ensure no other thread is accessing during destruction */
    pthread_rwlock_wrlock(&mgr->rwlock);
    
    HASH_ITER(hh, mgr->table, curr, tmp) {
        HASH_DEL(mgr->table, curr);
        free(curr);
    }
    
    pthread_rwlock_unlock(&mgr->rwlock);
    pthread_rwlock_destroy(&mgr->rwlock);
    
    free(mgr);
    log_info("Session Manager destroyed successfully.");
}