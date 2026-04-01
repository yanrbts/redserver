/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __GC_PROBE_H__
#define __GC_PROBE_H__

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <netinet/in.h>
#include "udp.h"
#include "hdr.h"

#define MAX_QUEUE_SIZE      128
#define MAX_PAYLOAD_SIZE    2048
#define GC_RETRY_THRESHOLD  3
#define GC_BROADCAST_IP     "192.168.211.255"

typedef enum gc_porttype {
    GC_MGR_BLACK = 0,
    GC_MGR_SWITCH = 1
} gc_porttype_e;

typedef struct gc_mgr_port {
    uint16_t        port;             /* remote probe port */
    gc_porttype_e   type;             /* port type: black-zone or switch */
} gc_probe_port_t;

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

typedef enum {
    GC_STATE_DISCOVERY = 0,
    GC_STATE_REGISTER,
    GC_STATE_HEARTBEAT
} gc_fsm_state_e;

typedef struct {
    uint8_t  data[MAX_PAYLOAD_SIZE];
    size_t   len;
    struct   sockaddr_in peer;
} gc_probe_task_t;

typedef struct {
    uint32_t ip;
    uint16_t port;
    gc_fsm_state_e state;
    gc_porttype_e type;
    uint32_t fail_count;
    uint64_t last_send_ms;
    uint16_t last_msgno;
    uint8_t  devid[6];
} gc_node_context_t;

typedef struct gc_probe_processor {
    gc_probe_task_t *queue;
    _Atomic size_t head;
    _Atomic size_t tail;
    pthread_t worker_tid;
    sem_t sem;
    volatile bool running;
    pthread_rwlock_t  lock;

    gc_node_context_t *nodes;
    int node_count;

    udp_conn_t *conn;
    void (*on_state_change)(uint32_t ip, int new_state);
} gc_probe_processor_t;

/**
 * @brief Initializes and starts the probe processor instance.
 * Allocates memory for the processor context, initializes the node states,
 * sets up the UDP broadcast socket, and spawns the background worker thread.
 * @param ports      Pointer to an array of port configurations to monitor.
 * @param port_count Number of elements in the ports array.
 * @return gc_probe_processor_t* Pointer to the created processor, or NULL on failure.
 */
gc_probe_processor_t* gc_probe_proc_create(const gc_probe_port_t *ports, size_t port_count);

/**
 * @brief Enqueues a received packet for asynchronous processing.
 * Thread-safe function that copies the raw packet data and peer information 
 * into the internal ring buffer (queue) and signals the worker thread.
 * @param proc Pointer to the active probe processor.
 * @param data Pointer to the raw packet data (including Ethernet/IP/UDP headers if applicable).
 * @param len  Length of the data in bytes.
 * @param peer Pointer to the source address and port of the sender.
 * @return true if the packet was successfully enqueued; false if the queue is full.
 */
bool gc_probe_proc_enqueue(gc_probe_processor_t *proc, const uint8_t *data, size_t len, const struct sockaddr_in *peer);

/**
 * @brief Stops and cleans up the probe processor instance.
 * Signals the worker thread to exit, joins the thread, closes the network 
 * connections, and deallocates all associated memory.
 * @param proc Pointer to the probe processor instance to be destroyed.
 */
void gc_probe_proc_destroy(gc_probe_processor_t *proc);

/**
 * @brief Retrieves the IPv4 address of a node based on its port type.
 * Searches the active node list for the first node matching the specified 
 * hardware/service type. It prioritizes nodes that have completed discovery.
 * @param proc     Pointer to the probe processor instance.
 * @param porttype The specific port type to search for (e.g., GC_MGR_BLACK).
 * @param out_ip   Pointer to store the discovered IP (network byte order).
 * @return true if a matching node was found; false otherwise.
 */
bool gc_probe_get_ip_by_type(gc_probe_processor_t *proc, gc_porttype_e porttype, uint32_t *out_ip);

/**
 * @brief Retrieves the MAC address of a node based on its port type.
 * Searches the node list for the first node matching the specified type.
 * Returns the device ID (MAC address) if the node has been discovered.
 * @param proc     Pointer to the probe processor instance.
 * @param porttype The port type to search for.
 * @param out_mac  Pointer to a buffer (min 6 bytes) to store the MAC address.
 * @return true if a matching node was found; false otherwise.
 */
bool gc_probe_get_mac_by_type(gc_probe_processor_t *proc, gc_porttype_e porttype, uint8_t *out_mac);

#endif /* __GC_PROBE_H__ */