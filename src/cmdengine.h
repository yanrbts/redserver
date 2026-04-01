/*
 * Copyright (c) 2026-2026, CLI
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __CMD_ENGINE_H__
#define __CMD_ENGINE_H__

#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>

/**
 * @brief Initializes the command table and launches the management server thread.
 * @return pthread_t The thread ID of the management server on success, 
 * or 0 if the table registration or thread creation fails.
 */
pthread_t cmd_start_core(void);
/**
 * @brief Checks if xdp raw packet logging is currently enabled.
 * @return true if logging is enabled, false otherwise.
 */
bool cmd_islogpkt_enabled(void);

/**
 * @brief Increments the reassembly statistics counters in a thread-safe manner.
 * This function can be called from the XDP packet parser to update the engine's
 * internal metrics related to IP fragment reassembly.
 * @param completed Number of successfully reassembled datagrams to add.
 * @param timeout Number of reassembly attempts that timed out to add.
 * @param error Number of reassembly errors to add.
 * @param overlap Number of overlapping fragments detected to add.
 */
void cmd_reass_stats_add(uint64_t completed, uint64_t timeout, uint64_t error, uint64_t overlap);

#endif