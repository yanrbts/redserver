/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 * * Description: Header for the session management system.
 * This module tracks bidirectional network flows to enable source-routing
 * and stateful inspection between isolated network zones.
 */

#ifndef __SESSION_MANAGER_H__
#define __SESSION_MANAGER_H__

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include "uthash.h"

/**
 * @brief Session Key structure.
 * Uniquely identifies a connection flow directed toward the Black Zone.
 */
typedef struct {
    uint16_t v_port;    /**< Unique virtual port/session ID assigned within the tunnel */
    uint8_t  rcp_id;    /**< RCP ID associated with the session */
}  __attribute__((packed)) session_key_t;

/**
 * @brief Session Context structure.
 * Stores the original Red Zone source information required for return routing.
 */
typedef struct {
    uint32_t src_ip;     /**< Original source IP address from the Red Zone */
    uint16_t src_port;   /**< Original source Port from the Red Zone */
    uint8_t  src_mac[6]; /**< Original source MAC address from the Red Zone */
    uint32_t dst_ip;     /**< Original dst IP address from the Red Zone */
    uint16_t dst_port;   /**< Original dst Port from the Red Zone */
    uint8_t  dst_mac[6]; /**< Original dest MAC address from the Red Zone */
    uint64_t last_seen;  /**< Timestamp of the last activity (in milliseconds) */
} session_context_t;

/**
 * @brief Hash Table Entry.
 * Internal structure for the uthash-based session table.
 */
typedef struct {
    session_key_t key;      /**< Hash Key (Lookup criteria) */
    session_context_t ctx;  /**< Hash Value (Session data) */
    UT_hash_handle hh;      /**< uthash handle for internal linkage */
} session_entry_t;

/**
 * @brief Session Manager handle.
 * Manages the session table, thread synchronization, and timeout policies.
 */
typedef struct {
    session_entry_t *table;     /**< Pointer to the head of the hash table */
    pthread_rwlock_t rwlock;    /**< Read-Write lock for thread-safe access */
    uint32_t timeout_ms;        /**< Session expiration threshold in milliseconds */
} session_manager_t;

/* --- API Definitions --- */

/**
 * @brief Creates a new session manager instance.
 * @param timeout_ms Session idle timeout threshold.
 * @return Pointer to the initialized session manager, or NULL on failure.
 */
session_manager_t* session_mgr_create(uint32_t timeout_ms);

/**
 * @brief Destroys the session manager and releases all associated memory.
 * @param mgr Pointer to the session manager to destroy.
 */
void session_mgr_destroy(session_manager_t *mgr);

/**
 * @brief Updates an existing session or inserts a new one.
 * Called during the Red Zone -> Black Zone forward path.
 * @param mgr Pointer to the session manager.
 * @param key Pointer to the session lookup key.
 * @param ctx Pointer to the session context data.
 */
void session_mgr_update(session_manager_t *mgr, const session_key_t *key, const session_context_t *ctx);

/**
 * @brief Looks up a session context using a key.
 * Called during the Black Zone return path to find the original source.
 * @param mgr Pointer to the session manager.
 * @param key Pointer to the session lookup key.
 * @param out_ctx [Out] Pointer to store the found session context.
 * @return true if the session exists, false otherwise.
 */
bool session_mgr_lookup(session_manager_t *mgr, const session_key_t *key, session_context_t *out_ctx);

/**
 * @brief Performs aging of expired sessions.
 * Should be called periodically in a worker thread or main loop to clean up stale entries.
 * @param mgr Pointer to the session manager.
 */
void session_mgr_aging(session_manager_t *mgr);

#endif /* __SESSION_MANAGER_H__ */