/**
 * Copyright (c) 2026-2026, Red LRM.
 * Author: yanruibing
 * All rights reserved.
 *
 * @file ljb.h
 * @brief Industrial Protocol Stack Header according to LJB 408-202X.
 *        Supports dual-role runtime dynamic architecture (CPU / IPMC).
 */

#ifndef LJB408_H
#define LJB408_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SLIP Protocol Special Control Characters (Section 5.2) */
enum ljb_slip_char {
    SLIP_END     = 0xC0,
    SLIP_ESC     = 0xDB,
    SLIP_ESC_END = 0xDC,
    SLIP_ESC_ESC = 0xDD
};

/* Protocol Network Node Address Identifiers (Section 5.3.1) */
typedef enum {
    NODE_IPMC = 0x01,
    NODE_CPU  = 0x02
} ljb_node_t;

/* Message Type Codes (Section 5.3.1) */
typedef enum {
    TYPE_HB_REQ          = 0x01,
    TYPE_HB_RSP          = 0x02,
    TYPE_SW_REQ          = 0x03,
    TYPE_SW_RSP          = 0x04,
    TYPE_HW_REQ          = 0x05,
    TYPE_HW_RSP          = 0x06,
    TYPE_SN_REQ          = 0x07,
    TYPE_SN_RSP          = 0x08,
    TYPE_TIME_REQ        = 0x09,
    TYPE_TIME_RSP        = 0x0A,
    TYPE_UPGRADE_REQ     = 0x0B,
    TYPE_UPGRADE_RSP     = 0x0C,
    TYPE_RACK_REQ        = 0x0D,
    TYPE_RACK_RSP        = 0x0E,
    TYPE_BOARD_TYPE_REQ  = 0x0F,
    TYPE_BOARD_TYPE_RSP  = 0x10,
    TYPE_ALARM           = 0xA0
} ljb_msg_type_t;

/* Buffer Limits */
enum ljb_buf_limit {
    LJB_MAX_RAW_FRAME  = 64,
    LJB_MAX_SLIP_FRAME = 128
};

/* Universal Function Return Codes */
typedef enum {
    LJB_OK              =  0,
    LJB_ERR_INVALID_ARG = -1,
    LJB_ERR_UART_OPEN   = -2,
    LJB_ERR_UART_CFG    = -3,
    LJB_ERR_THREAD      = -4,
    LJB_ERR_IO          = -5,
    LJB_ERR_TIMEOUT     = -6,
    LJB_ERR_ROLE        = -7
} ljb_err_t;

/* Software / Hardware Version Structure (Appendix H) */
typedef struct {
    uint8_t  major;
    uint8_t  minor;
    uint8_t  revision;
    uint8_t  build;
    uint32_t ymd; /* Date format: YYYYMMDD (4 Bytes Big-Endian) */
} ljb_version_t;

/* Rack Location Specification */
typedef struct {
    uint8_t rack_id;
    uint8_t slot_id;
} ljb_rack_t;

/* Local Hardware/Software Entity Context */
typedef struct {
    ljb_version_t sw_ver;
    ljb_version_t hw_ver;
    uint8_t       sn[8];
    uint64_t      total_half_hours;
    uint8_t       rack_id;
    uint8_t       slot_id;
} ljb_dev_info_t;

/* Alarm Callback Handler */
typedef void (*ljb_alarm_handler_t)(uint8_t alarm_code, void *user_data);

/* Internal Synchronization Frame Store */
typedef struct {
    uint8_t       expected_type;
    volatile bool is_ready;
    uint8_t       result_code;
    ljb_version_t sw_ver;
    ljb_version_t hw_ver;
    uint8_t       sn[8];
    uint8_t       total[8];
    uint8_t       uptime[8];
    ljb_rack_t    rack_info;
} ljb_rx_sync_store_t;

/* Protocol Control Block Context Structure */
typedef struct ljb_context {
    int                 uart_fd;
    pthread_t           rx_thread;
    pthread_mutex_t     lock;
    pthread_cond_t      cond;
    volatile bool       is_running;
    
    ljb_node_t          role;       /* Local Node Identification */
    ljb_node_t          peer_node;  /* Destination Peer Identification */
    char               *dev;
    const char         *cfile;      
    uint8_t             seq_num;    /* Frame Sequence Number */
    uint32_t            timeout_ms;

    struct timespec     start_ts;
    ljb_dev_info_t      local_info; /* Local Asset Cache */

    ljb_alarm_handler_t alarm_cb;   /* Async Event Observer */
    void               *user_data;  /* Opaque Context pointer */

    ljb_rx_sync_store_t sync_store; /* Blocking Sync Barrier Container */
} ljb_ctx_t;

/* Lifecycle APIs */
ljb_err_t ljb_init(ljb_ctx_t *ctx, const char *cfile, ljb_node_t role);
void ljb_deinit(ljb_ctx_t *ctx);
ljb_err_t ljb_set_device_info(ljb_ctx_t *ctx, const ljb_dev_info_t *info);
ljb_err_t ljb_register_alarm_handler(ljb_ctx_t *ctx, ljb_alarm_handler_t handler, void *user_data);
/* CPU Domain Action APIs */
ljb_err_t ljb_cpu_get_rack_info_sync(ljb_ctx_t *ctx, ljb_rack_t *out_rack);
ljb_err_t ljb_cpu_request_upgrade_sync(ljb_ctx_t *ctx, uint8_t *out_result);
/* IPMC Domain Action APIs */
ljb_err_t ljb_ipmc_send_heartbeat_sync(ljb_ctx_t *ctx);
ljb_err_t ljb_ipmc_get_sw_version_sync(ljb_ctx_t *ctx, ljb_version_t *out_ver);
ljb_err_t ljb_ipmc_get_hw_version_sync(ljb_ctx_t *ctx, ljb_version_t *out_ver);
ljb_err_t ljb_ipmc_get_sn_sync(ljb_ctx_t *ctx, uint8_t outsn[8]);
ljb_err_t ljb_ipmc_get_time_sync(ljb_ctx_t *ctx, uint8_t total[8], uint8_t uptime[8]);
ljb_err_t ljb_ipmc_trigger_alarm(ljb_ctx_t *ctx, uint8_t alarm_code);

static inline const char *ljb_strerror(ljb_err_t err) {
    switch (err) {
        case LJB_OK:                return "Success (LJB_OK)";
        case LJB_ERR_INVALID_ARG:   return "Invalid argument (LJB_ERR_INVALID_ARG)";
        case LJB_ERR_UART_OPEN:     return "Failed to open UART device (LJB_ERR_UART_OPEN)";
        case LJB_ERR_UART_CFG:      return "Failed to configure UART (LJB_ERR_UART_CFG)";
        case LJB_ERR_THREAD:        return "Thread creation or execution error (LJB_ERR_THREAD)";
        case LJB_ERR_IO:            return "I/O operation error (LJB_ERR_IO)";
        case LJB_ERR_TIMEOUT:       return "Operation timed out (LJB_ERR_TIMEOUT)";
        case LJB_ERR_ROLE:          return "Invalid role or permission denied (LJB_ERR_ROLE)";
        default:                    return "Unknown error code";
    }
}

#ifdef __cplusplus
}
#endif

#endif /* LJB408_H */