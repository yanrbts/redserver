/*
 * Copyright (c) 2026-2026, CLI
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdatomic.h>
#include "log.h"
#include "cmd.h"
#include "cmdengine.h"

typedef struct cmd_engine_s {
    atomic_int interval;       /* Atomic integer for scan interval */
    atomic_bool islogptk;      /* Atomic boolean for packet logging */

    struct {
        atomic_uint_least64_t completed; /* Successfully reassembled datagrams */
        atomic_uint_least64_t timeout;   /* Reassembly attempts that timed out */
        atomic_uint_least64_t error;     /* Reassembly errors (e.g., missing fragments) */
        atomic_uint_least64_t overlap;   /* Overlapping fragments detected */
    } reass_stats;
} cmd_engine_t;

static cmd_engine_t cmdengine = {
    .interval = ATOMIC_VAR_INIT(1000),  /* Default 1000ms */
    .islogptk = ATOMIC_VAR_INIT(false), /* Default disabled */
    .reass_stats = {
        .completed = ATOMIC_VAR_INIT(0),
        .timeout = ATOMIC_VAR_INIT(0),
        .error = ATOMIC_VAR_INIT(0),
        .overlap = ATOMIC_VAR_INIT(0)
    }
};

static int cmd_set_islogptk(void *ctx, int argc, char **argv, cmd_resp_t *resp);
static int cmd_get_reass_stats(void *ctx, int argc, char **argv, cmd_resp_t *resp);
static int cmd_get_config(void *ctx, int argc, char **argv, cmd_resp_t *resp);
static int cmd_handle_set(void *ctx, int argc, char **argv, cmd_resp_t *resp);
static int cmd_handle_get(void *ctx, int argc, char **argv, cmd_resp_t *resp);

static const cmd_entry_t cmd_table[] = {
    /* --- Root Level Commands (group is NULL) --- */
    {NULL,  "STATUS", "show server status",               "",            1, NULL},
    {NULL,  "SET",    "set parameters",                   "<key> <val>", 1, cmd_handle_set},
    {NULL,  "GET",    "get parameters",                   "<key>",       1, cmd_handle_get},
    {NULL,  "HELP",   "command help",                     "[command]",   1, cmd_handle_help},
    {NULL,  "EXIT",   "exit the CLI",                     "",            1, NULL},
    /* --- SET Group Sub-commands --- */
    {"SET", "interval", "Scan interval (ms)",              "<val>",      3, NULL},
    {"SET", "logpkt",   "print raw XDP packet info",       "<1|0>",      3, cmd_set_islogptk},
    /* --- GET Group Sub-commands --- */
    {"GET", "pktstats", "get packet statistics",           "",           2, cmd_get_reass_stats},
    {"GET", "config",   "get configuration",               "",           2, cmd_get_config},

    {NULL, NULL, NULL, NULL, 0, NULL}
};

/**
 * @brief Professional Handler for 'SET logpkt' using C11 Atomic Operations.
 * This implementation achieves lock-free updates, ensuring maximum performance 
 * for the data plane while maintaining strict thread safety and visibility.
 */
static int cmd_set_islogptk(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    /* 1. Context Recovery: Ensure the engine context is valid */
    cmd_engine_t *engine = (cmd_engine_t *)ctx;
    if (!engine) {
        cmd_resp_red(resp, "ERR: System internal error: context is NULL.");
        return -1;
    }

    /* 2. Argument Integrity Check: 
     * Ensures argv[2] exists before access to prevent segmentation faults.
     */
    if (argc < 3 || argv[2] == NULL) {
        cmd_resp_red(resp, "ERR: Missing parameter. Usage: SET logpkt <1|0|on|off>");
        return 0;
    }

    const char *val_str = argv[2];
    bool enable;

    /* 3. Strict Value Validation:
     * Mapping CLI string inputs to logical boolean values.
     */
    if (strcmp(val_str, "1") == 0 || 
        strcasecmp(val_str, "on") == 0 || 
        strcasecmp(val_str, "true") == 0) {
        enable = true;
    } else if (strcmp(val_str, "0") == 0 || 
               strcasecmp(val_str, "off") == 0 || 
               strcasecmp(val_str, "false") == 0) {
        enable = false;
    } else {
        cmd_resp_red(resp, "ERR: Invalid value '%s'. Expected: 1, 0, on, off, true, or false.", val_str);
        return 0; 
    }

    /* 4. Atomic State Comparison:
     * atomic_load ensures we read the most current value across CPU caches.
     * If the state is already the same, we avoid redundant store and logging.
     */
    if (atomic_load(&engine->islogptk) == enable) {
        cmd_resp_green(resp, "OK: Raw packet logging is already %s.", enable ? "ENABLED" : "DISABLED");
        return 0;
    }

    /* 5. Atomic Thread-Safe Update:
     * atomic_store provides a lock-free way to update the variable.
     * memory_order_seq_cst (default) ensures the strongest consistency.
     */
    atomic_store(&engine->islogptk, enable);

    /* 6. Response and Audit Trail:
     * Feedback is given to the CLI user and a persistent log is generated for the admin.
     */
    cmd_resp_green(resp, "OK: Raw packet logging changed to %s.", enable ? "ENABLED" : "DISABLED");
    log_info("[MGMT] Configuration updated: islogptk set to %d by administrator.", (int)enable);

    return 0;
}

/**
 * @brief Sub-dispatcher for the "SET" group.
 */
static int cmd_handle_set(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    /* 1. Check if sub-command (key) is provided.
     * If just "SET" is typed, show all keys in the SET group.
     */
    if (argc < 2) {
        cmd_group_help("SET", resp);
        return 0;
    }

    const char *sub_cmd = argv[1];

    /* 2. Search ONLY within the "SET" group */
    for (int i = 0; cmd_table[i].name != NULL; i++) {
        /* Only consider entries belonging to the "SET" group */
        if (cmd_table[i].group != NULL && strcasecmp(cmd_table[i].group, "SET") == 0) {
            
            if (strcasecmp(sub_cmd, cmd_table[i].name) == 0) {
                /* Guard against uninitialized handlers in the static table */
                if (cmd_table[i].handler == NULL) {
                    cmd_resp_red(resp, "ERR: SET %s logic is not implemented.", sub_cmd);
                    return 0;
                }

                /* Validate arguments for this specific sub-command */
                if (argc < cmd_table[i].min_argc) {
                    cmd_resp_red(resp, "ERR: Usage: SET %s %s", 
                                   cmd_table[i].name, cmd_table[i].usage);
                    return 0;
                }
                /* Execute the targeted handler */
                return cmd_table[i].handler(ctx, argc, argv, resp);
            }
        }
    }

    /* 3. Fallback: Key not found in this group */
    cmd_resp_red(resp, "ERR: Unknown SET key '%s'. Use 'HELP SET' to see options.", sub_cmd);
    return -1;
}

/**
 * @brief Sub-dispatcher for the "GET" command group.
 * This function handles the second-level routing for all configuration retrieval requests.
 * It ensures that the user has provided a valid key and that the internal state 
 * can be accessed safely via the registered handler.
 * @param ctx      Opaque pointer to the application engine context (cmd_engine_t).
 * @param argc     Number of arguments in the command line (e.g., "GET logpkt" -> argc=2).
 * @param argv     Array of strings containing the command and arguments.
 * @param resp     Pointer to the response buffer context for outputting results.
 * @return int     0 on successful dispatch or handled user error, -1 on internal system failure.
 */
static int cmd_handle_get(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    /* 1. Preliminary Validation: Defensive checks for mandatory pointers */
    if (!ctx || !resp) {
        /* This should theoretically never happen if the framework is sound */
        return -1; 
    }

    /* 2. Argument Presence Check:
     * If the user sends "GET" without any keys, provide an interactive discovery
     * list of all available keys within this specific group.
     */
    if (argc < 2) {
        cmd_group_help("GET", resp);
        return 0;
    }

    /* Extract the sub-command (key) after the "GET" verb */
    const char *target_key = argv[1];

    /* 3. Static Table Lookup:
     * Linearly scan the command table for entries matching the "GET" group.
     * Note: strcasecmp is used to allow "get logpkt" or "GET LOGPKT".
     */
    for (int i = 0; cmd_table[i].name != NULL; i++) {
        /* Filter entries that belong to the "GET" group */
        if (cmd_table[i].group != NULL && strcasecmp(cmd_table[i].group, "GET") == 0) {
            
            /* Match the specific sub-command name */
            if (strcasecmp(target_key, cmd_table[i].name) == 0) {
                
                /* Guard against uninitialized handlers in the static table */
                if (cmd_table[i].handler == NULL) {
                    cmd_resp_red(resp, "ERR: GET %s logic is not implemented.", target_key);
                    return 0;
                }

                /* Validation: Ensure the caller provided enough arguments for the leaf handler */
                if (argc < cmd_table[i].min_argc) {
                    cmd_resp_red(resp, "ERR: Usage: GET %s %s", 
                                   cmd_table[i].name, 
                                   cmd_table[i].usage ? cmd_table[i].usage : "");
                    return 0;
                }

                /* Execute the leaf handler. Leaf handlers for GET must use atomic_load 
                 * internally for thread-safe access to the engine context. */
                return cmd_table[i].handler(ctx, argc, argv, resp);
            }
        }
    }

    /* 4. Fallback: No matching key found in the GET group */
    cmd_resp_red(resp, "ERR: Unknown GET key '%s'. Use 'HELP GET' to list valid keys.", target_key);
    
    return -1;
}

/**
 * @brief Professional Handler to retrieve IP reassembly statistics.
 * * This implementation ensures context validity, utilizes atomic loads for 
 * thread-safety without blocking the XDP data path, and provides formatted 
 * tabular output for better CLI readability.
 */
static int cmd_get_reass_stats(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    (void)argv;

    /* 1. Context and Parameter Validation */
    cmd_engine_t *engine = (cmd_engine_t *)ctx;
    
    if (!engine || !resp) {
        /* Technical error: Should be caught during integration */
        return -1; 
    }

    /* Argument Check: 
     * Since this is a leaf node (e.g., "GET reass"), we expect argc to be exactly 2.
     * If there are extra arguments, we flag it as an invalid usage.
     */
    if (argc != 2) {
        cmd_resp_red(resp, "ERR: Unexpected arguments. Usage: GET reass");
        return 0;
    }

    /* 2. Snapshot Atomic Data
     * We load values into local variables to ensure a consistent point-in-time 
     * view of the statistics for this specific report.
     */
    uint64_t completed = atomic_load(&engine->reass_stats.completed);
    uint64_t timeout   = atomic_load(&engine->reass_stats.timeout);
    uint64_t error     = atomic_load(&engine->reass_stats.error);
    uint64_t overlap   = atomic_load(&engine->reass_stats.overlap);

    /* 3. Professional Formatted Output 
     * Using headers and aligned columns makes the CLI output parseable by 
     * humans and simple scripts.
     */
    cmd_resp_printf(resp, "\n%s%-20s%s : %s%lu%s\n", C_GREEN, "Reass-Completed", C_RESET, C_YELLOW, completed, C_RESET);
    cmd_resp_printf(resp, "%s%-20s%s : %s%lu%s\n", C_GREEN, "Reass-Timeout", C_RESET, C_YELLOW, timeout, C_RESET);
    cmd_resp_printf(resp, "%s%-20s%s : %s%lu%s\n", C_GREEN, "Reass-Error", C_RESET, C_YELLOW, error, C_RESET);
    cmd_resp_printf(resp, "%s%-20s%s : %s%lu%s\n", C_GREEN, "Reass-Overlap", C_RESET, C_YELLOW, overlap, C_RESET);

    return 0;
}

static int cmd_get_config(void *ctx, int argc, char **argv, cmd_resp_t *resp) {
    (void)argv;

    cmd_engine_t *engine = (cmd_engine_t *)ctx;
    if (!engine || !resp) {
        return -1;
    }

    if (argc != 2) {
        cmd_resp_red(resp, "ERR: Unexpected arguments. Usage: GET config");
        return 0;
    }

    int interval = atomic_load(&engine->interval);
    bool islogptk = atomic_load(&engine->islogptk);

    cmd_resp_printf(resp, "\n  %s%-20s%s : %s%d%s %sms%s\n", 
                    C_GREEN, "interval", C_RESET, 
                    C_YELLOW, interval, C_RESET, 
                    C_GRAY, C_RESET);

    cmd_resp_printf(resp, "  %s%-20s%s : %s%s%s\n", 
                    C_GREEN, "logpkt", C_RESET, 
                    C_YELLOW, islogptk ? "yes" : "no",
                    C_RESET);

    return 0;
}

/**
 * @brief Initializes the command table and launches the management server thread.
 * @return pthread_t The thread ID of the management server on success, 
 * or 0 if the table registration or thread creation fails.
 */
pthread_t cmd_start_core(void) {
    /* 1. Register the business command table */
    cmd_register_table(cmd_table);

    /* 2. Start the management server thread */
    pthread_t tid = cmd_server_start(&cmdengine);

    /* 3. Validation and Error Logging */
    if (tid == 0) {
        log_error("[CORE] Fatal: Failed to start management server thread.\n");
        return 0; 
    }

    log_info("[CORE] Management plane initialized successfully. Thread ID: %lu\n", (unsigned long)tid);
    
    return tid;
}

bool cmd_islogpkt_enabled(void) {
    return atomic_load(&cmdengine.islogptk);
}

/**
 * @brief Updates IP reassembly metrics using atomic increments.
 * Optimized name: cmd_reass_stats_add
 */
void cmd_reass_stats_add(uint64_t completed, uint64_t timeout, uint64_t error, uint64_t overlap) {
    /* Direct atomic additions - Lock-free and XDP friendly */
    if (completed) atomic_fetch_add(&cmdengine.reass_stats.completed, completed);
    if (timeout)   atomic_fetch_add(&cmdengine.reass_stats.timeout, timeout);
    if (error)     atomic_fetch_add(&cmdengine.reass_stats.error, error);
    if (overlap)   atomic_fetch_add(&cmdengine.reass_stats.overlap, overlap);
}
