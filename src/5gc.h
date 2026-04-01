/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __5GC_H__
#define __5GC_H__

#include <stdint.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <pthread.h>
#include "hdr.h"
#include "udp.h"

#define GC_RETRY_THRESHOLD          3       // consecutive failure threshold
#define GC_FIND_INTERVAL            10      // in seconds
#define GC_REGISTER_INTERVAL        3       // in seconds
#define GC_HEARBEAT_INTERVAL        3       // in seconds
#define GC_DEFAULT_BROADCAST_PORT   50001
#define GC_BROADCAST_IP             "255.255.255.255"

typedef struct gc_manager gc_manager_t;
typedef struct gc_ctx gc_ctx_t;

typedef enum gc_porttype {
    GC_MGR_BLACK = 0,
    GC_MGR_SWITCH = 1
} gc_porttype_e;

enum RespCode {
    GC_NO_ERROR     = 0,    // success
    GC_PARAM_ERROR  = 1,    // param error
    GC_OUT_OF_RES   = 2,    // Insufficient resources to perform the operation.
    GC_MOUDLE_ERROR = 3,    // Related module error or failure
    GC_SYS_BUSY     = 4,    // system busy  
    GC_TASK_BUSY    = 5,    // task busy
    GC_SERVICE_EXIST = 6,   /* 5G is already present, and during a rapid restart, the 
                             * IP switch fails to detect that the 5G link has gone down. */
};

enum MsgType {
    GC_FIND = 0x01,         // find or search
    GC_REGISTER = 0x02,     // register
    GC_HEARBEAT = 0x03      // hearbeat
};

enum SubType {
    GC_SUB_REQ  = 0x01,     // Request
    GC_SUB_RESP = 0x02      // Response
};

enum IpType {
    GC_IPV4 = 0x00,
    GC_IPV6 = 0x01
};

enum Role {
    GC_B_5GC = 0x01,    // 基础网络 默认
    GC_L_5GC = 0x02,    // 陆军 5GC
    GC_H_5GC = 0x03,    // 海军 5GC
    GC_K_5GC = 0x04,    // 空军 5GC
    GC_J_5GC = 0x05     // 火箭军 5GC
};

typedef struct {
    hdr_t hdr;                // AUTH
    uint8_t ether_header[14]; // MAC 0x857
    uint8_t symbol[2];      // 协议标识
    uint8_t version;        // 版本号
    uint8_t cls;            // 消息类型
    uint8_t type;           // 子消息类型
    uint8_t empty;          // 分片标记 0表示最后一包，非0表示存在后续数据包
    uint16_t msgno;         // 消息序号
} __attribute__((packed)) gc_header_t;

typedef struct {
    gc_header_t head;
    uint8_t iptype;
    struct in_addr svipv4;
    uint16_t port;
} __attribute__((packed)) gc_req_find_t;

typedef struct {
    gc_header_t head;
    uint8_t devid[6];       // 设备标识号
    uint8_t iptype;         // ip 地址类型
    struct in_addr ipv4;    // 交换机ip
} __attribute__((packed)) gc_resp_find_t;

typedef struct {
    gc_header_t head;
    uint8_t svrid[6];       // 唯一标识
    uint8_t iptype;         // 0: ipv4,1:ipv6
    uint8_t svrip[4];       // 如果 是ipv4 则4字节，如果ipv6 16字节
    uint8_t svrrole;        // 1 基础网络5GC,2/3/4/5
} __attribute__((packed)) gc_req_register_t;

typedef struct {
    gc_header_t head;
    uint8_t result;         // 0-成功，非0注册失败错误码
} __attribute__((packed)) gc_resp_register_t;

typedef struct {
    gc_header_t head;
    uint8_t tm[4];
} __attribute__((packed)) gc_hearbeat_t;

/* State definitions for the internal worker thread */
typedef enum {
    GC_STATE_DISCOVERY = 0,  /* Searching for remote server via broadcast */
    GC_STATE_REGISTER,       /* Attempting to register identity to the server */
    GC_STATE_HEARTBEAT,      /* Active session: sending keep-alive packets */
} gc_state_e;


typedef void (*gc_handler_t)(gc_ctx_t *ctx, const void *payload, size_t len, struct sockaddr_in *from);

/* Main context structure for the 5GC service */
typedef struct gc_ctx {
    /* Network Connection - Fixed port during lifecycle */
    udp_conn_t *conn;

    /* Protocol Data */
    gc_resp_find_t node;
    // gc_resp_find_t black_node;

    /* Status & Control */
    gc_state_e state;           /* Current FSM state */
    int fail_count;             /* Consecutive failure counter */
    uint16_t target_port;       /* Target destination port */
    uint16_t src_port;          /* Local source port */
    uint16_t last_query_msgno;
    bool is_running;            /* Thread execution flag */
    gc_porttype_e porttype;     /* Mode: true for black-zone, false for switch */

    /* Threading */
    pthread_t worker_tid;
    pthread_rwlock_t lock;

    gc_handler_t on_find_req;     
    gc_handler_t on_register_req; 
    gc_handler_t on_heartbeat_req;
    /* Callbacks */
    void (*on_state_change)(struct gc_ctx *ctx, gc_state_e new_state);
    gc_manager_t *mgr;           /* Parent manager, if any */
} gc_ctx_t;

/**
 * @brief Allocates and initializes a new 5GC service context.
 * @param src_port The local source UDP port. if 0, OS assigns ephemeral port.
 * @param target_port The target UDP port.
 * @param is_black Operational mode selection.
 * @return Pointer to the new context, or NULL on failure.
 * @warning if src_port is 0, OS assigns ephemeral port. The returned context must be freed using gc_service_destroy().
 */
gc_ctx_t* gc_service_create(uint16_t src_port, uint16_t target_port, gc_porttype_e porttype);

/**
 * @brief Stops the background thread and frees all associated memory.
 * @param ctx Pointer to the context to be destroyed.
 */
void gc_service_destroy(gc_ctx_t *ctx);

/**
 * @brief Launches the background maintenance thread for the 5GC service.
 *
 * This function is the entry point for the service's autonomous behavior. 
 * It performs the following critical actions:
 * 1. Thread Creation: Spawns a POSIX thread (pthread) that runs 'gc_worker_thread'.
 * 2. Lifecycle Ignition: Sets the 'is_running' flag to true, enabling the 
 * Internal State Machine (FSM) to start the Discovery -> Register -> Heartbeat cycle.
 * 3. Resource Management: Once started, the thread runs in the background, 
 * isolated from the caller's main execution path, preventing network 
 * timeouts from blocking the UI or main logic.
 *
 * @param ctx Pointer to the service context initialized by gc_service_create.
 * @return int 0 on success; -1 if the thread could not be created or ctx is invalid.
 */
int gc_service_start(gc_ctx_t *ctx);

/**
 * @brief Signals the background thread to stop.
 */
void gc_service_stop(gc_ctx_t *ctx);

/**
 * @brief Registers user-defined callback functions for different protocol message classes.
 * This function allows the application to override the default behavior for Find, 
 * Register, and Heartbeat requests by providing custom handler functions. 
 * If a handler is passed as NULL, the system will typically fall back to 
 * its internal default implementation.
 *
 * @param ctx   Pointer to the 5GC context structure (state and configuration).
 * @param find  Callback function invoked when a Service Discovery (FIND) request is received.
 * @param reg   Callback function invoked when an Identity Registration (REGISTER) request is received.
 * @param hb    Callback function invoked when a Keep-alive (HEARTBEAT) request is received.
 */
void gc_set_handlers(gc_ctx_t *ctx, gc_handler_t find, gc_handler_t reg, gc_handler_t hb);

/**
 * @brief Retrieves the unique device identifier (MAC address) of the local machine.
 *
 * This function fetches the MAC address of the primary network interface 
 * and copies it into the provided output buffer. The MAC address serves 
 * as a unique device identifier in various network protocols.
 *
 * @param out_devid A pointer to a buffer where the 6-byte MAC address will be stored.
 *                  The buffer must be at least 6 bytes in size.
 * @return int 0 on success; -1 if the MAC address could not be retrieved.
 */
int gc_get_device_id(gc_ctx_t *ctx, uint8_t out_devid[6]);

/**
 * @brief Retrieves the IP address of the connected server.
 *
 * This function extracts the IP address of the server that the 
 * 5GC service is currently connected to and copies it into the 
 * provided output variable in network byte order.
 *
 * @param out_ip A pointer to a uint32_t variable where the server's IP address will be stored.
 *               The IP address is represented in network byte order.
 * @return int 0 on success; -1 if the server IP could not be retrieved.
 */
int gc_get_server_ip(gc_ctx_t *ctx, uint32_t *out_ip);

/**
 * @brief Generates the next unique message number for protocol messages.
 *
 * This function maintains an internal counter to ensure that each 
 * outgoing message has a distinct identifier. The message number 
 * is used for tracking requests and matching responses in the protocol.
 *
 * @return uint16_t The next unique message number.
 */
uint16_t get_next_msgno();

/**
 * @brief Constructs a protocol header for outgoing messages.
 *
 * This utility function initializes a gc_header_t structure with the 
 * specified message class, type, and message number. It also sets the 
 * protocol symbol and version fields to their default values.
 *
 * @param head   Pointer to the gc_header_t structure to be initialized.
 * @param cls    Message class (e.g., GC_FIND, GC_REGISTER, GC_HEARBEAT).
 * @param type   Sub-message type (e.g., GC_SUB_REQ, GC_SUB_RESP).
 * @param msgno  Unique message number for tracking requests/responses.
 */
void gc_build_header(gc_header_t *head, uint8_t cls, uint8_t type, uint16_t msgno);

#endif
