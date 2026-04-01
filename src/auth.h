/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __AUTH_H__
#define __AUTH_H__

#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "udp.h"

#define AUTH_MIN_REFRESH_TIME 300
#define AUTH_MAX_REFRESH_TIME 600

typedef struct {
    uint32_t auth_interval;     /* Interval for Auth refresh (seconds) */
    uint32_t auth_value;        /* Current Auth value */
    time_t last_auth_update;    /* Last Auth update time */
} auth_t;

/**
 * @brief Create and initialize an auth_t object.
 *
 * This function allocates memory for an auth_t structure and
 * initializes it using the specified interval value. The interval
 * is typically used to control timing-related behavior such as
 * authentication refresh, expiration, or periodic validation,
 * depending on the implementation.
 *
 * @param interval Interval value (in implementation-defined units)
 *                 used to configure the auth_t object.
 *
 * @return Pointer to the newly created auth_t structure on success,
 *         or NULL if memory allocation or initialization fails.
 */
auth_t* auth_create(uint32_t interval);

/**
 * @brief Performs a network request to update the cached authentication value.
 * * This function is designed to be called by a dedicated background thread or a 
 * timer-driven event. It encapsulates the network I/O required to communicate 
 * with the Authentication Server (Black Zone). By updating the shared auth_t 
 * structure, it ensures the main processing loop has access to valid credentials.
 * @param at    Pointer to the auth_t management structure.
 * @param aip   The IP address of the Authentication Server.
 * @param aport The port number of the Authentication Server.
 * @return      Returns 0 on successful update, or -1 if the network request fails.
 */
int auth_refresh(auth_t *at, const char *aip, uint16_t aport);

/**
 * Get cached Auth value 
 * @param at auth_t ponter
 * @param aip auth server ip
 * @param aport auth server port
 * @param out_auth Output: cached Auth value
 * @return 0 on success, negative error code on failure
 */
int auth_get(auth_t *at, uint32_t *out_auth);

/**
 * @brief Retrieves the static cached Auth value.
 * This function provides quick access to the most recently updated
 * authentication value without needing to reference the auth_t structure.
 * if the value has never been set, it returns 0.
 * 
 * @return The current static cached Auth value, or 0 if it has never been set.
 */
uint32_t auth_get_static_value(void);

/**
 * @brief Free and clean up an auth_t structure.
 *
 * This function releases all resources associated with the given
 * auth_t object. It frees any dynamically allocated memory owned
 * by the structure and performs necessary cleanup to prevent
 * memory leaks.
 *
 * @param at Pointer to the auth_t structure to be freed.
 *           If NULL, the function does nothing.
 */
void auth_free(auth_t *at);


/**
 * @brief Probes a remote host to verify network liveness using a UDP-based echo mechanism.
 * * This function implements a synchronous "Application-level Ping". It sends a 
 * specialized heartbeat packet and waits for an identical echo response from the target.
 *
 * @param conn  Pointer to the persistent UDP connection handle.
 * @param host  Destination IPv4 address string.
 * @param port  Destination port number.
 * @return int  0 on success (Pong received), 
 * -2 on timeout (No response within 800ms), 
 * -1 on fatal socket or validation error.
 */
int auth_ping_probe(udp_conn_t *conn, const char *host, uint16_t port);

#endif