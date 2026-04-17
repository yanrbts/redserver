/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __HEALTH_H__
#define __HEALTH_H__

#include <stdint.h>
#include <stdbool.h>

#define LRM_HEALTH_INTERVAL     5 /* 5 seconds */
#define LRM_RED_UNIX_PATH       "/tmp/redlrm_internal.sock"

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
 * Network Report Structure (ICMP Payload)
 * This is what gets sent over the wire.
 */
typedef struct {
    uint32_t magic;           // 0x484C5448
    uint8_t  rack_id;
    uint8_t  slot_id;
    uint16_t status_bits;     // General status flags
    uint32_t uptime;          // System/Service uptime
    /* Nesting the internal status object */
    lrm_internal_status_t detail;
} __attribute__((packed)) lrm_health_payload_t;

typedef struct lrm_health_server lrm_health_server_t;
/**
 * @brief Initializes and allocates the LRM health monitoring server.
 * @param rack      Physical rack identifier (Rack ID).
 * @param slot      Physical slot position within the rack (Slot ID).
 * @param interval  Reporting interval in seconds (defines telemetry frequency).
 * @return          Pointer to the initialized server instance, or NULL on failure.
 */
lrm_health_server_t* lrm_health_create(uint8_t rack, uint8_t slot, const int interval);

/**
 * @brief Starts the main health reporting loop.
 * This is typically a blocking call or spawns a worker thread to periodically
 * transmit health telemetry packets to the specified target.
 * @param server    Pointer to the health server instance.
 * @param target_ip Destination IP address for the telemetry reports.
 * @return          0 on success, or a negative error code on failure.
 */
int lrm_health_run(lrm_health_server_t *server, const char *target_ip);

/**
 * @brief Releases all resources associated with the health server.
 * Closes network sockets, stops internal timers, and frees allocated memory.
 * @param server    Pointer to the health server instance to be destroyed.
 */
void lrm_health_destroy(lrm_health_server_t *server);

/**
 * @brief Updates the internal status code of the health server.
 * This status code will be included in the next periodic or active report
 * to inform the collector of the current node state.
 * @param server    Pointer to the health server instance.
 * @param status    16-bit status/error code (e.g., 0x0000 for NORMAL).
 */
void lrm_health_set_status(lrm_health_server_t *server, uint16_t status);

/**
 * @brief Triggers an immediate (on-demand) health report transmission.
 * Unlike the periodic reporting in lrm_health_run, this function forces 
 * a telemetry packet to be sent immediately to a specific destination.
 * @param server    Pointer to the health server instance.
 * @param dst_ip    Target destination IP address for this specific report.
 * @return          0 on success, or a negative error code if transmission fails.
 */
int lrm_health_send_active_report(lrm_health_server_t *server, const char *dst_ip);

#endif