/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __WBS_H__
#define __WBS_H__

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Start WebSocket server in background thread mode.
 * @param host Bind address (e.g., "0.0.0.0", "127.0.0.1")
 * @param port Listening port (e.g., 8080)
 * @return 0 on success, -1 on fatal error
 */
int wbs_start(const char *host, uint16_t port);

/**
 * @brief Thread-safe blast text/binary payload to all online panel clients.
 * @param pkt Pointer to the packet buffer (can be text or binary)
 * @param len Explicit length of the bytes to shift out
 */
void wbs_bcast(const void *pkt, uint64_t len);

/**
 * @brief Stop server, force drop all screens, and clear allocations.
 */
void wbs_stop(void);

/**
 * @brief  Spawns an asynchronous worker thread to actively push gateway telemetry status to web clients.
 * @param  interval_ms  [in] Telemetry collection and broadcast period in milliseconds.
 * @return int 0 on successful thread initialization, non-zero system error code on failure.
 * @note   Non-blocking runner. Actively streams JSON metrics over the active WebSocket channel.
 */
int wbs_notify_thread(int interval_ms);

#endif