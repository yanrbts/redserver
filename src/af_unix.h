/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */

#ifndef LRM_UNIX_SERVER_H
#define LRM_UNIX_SERVER_H

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

/**
 * Internal Detail Structure
 * Captured from Red LRM service via AF_UNIX
 */
typedef struct {
    uint16_t version_major;
    uint16_t version_minor;
    uint16_t version_patch;
    uint32_t mem_usage_kb;    // Memory footprint in KB
    uint16_t cpu_load;        // CPU load percentage (0-100)
    uint16_t custom_err;      // Specific internal error codes
} __attribute__((packed)) lrm_internal_status_t;

/**
 * @brief Initialize and start the AF_UNIX telemetry server.
 * This function creates a background thread to handle incoming 
 * connections from the Health Service.
 * @param interval_ms Data collection interval in milliseconds (minimum 10ms).
 * @return 0 on success, -1 on failure.
 */
int lrm_unix_server_start(int interval_ms);

/**
 * @brief Stop the server and cleanup resources (unlink socket file).
 */
void lrm_unix_server_stop(void);

#endif /* LRM_UNIX_SERVER_H */