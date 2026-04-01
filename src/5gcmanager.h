/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#ifndef __5GC_MANAGER_H__
#define __5GC_MANAGER_H__

#include <stdint.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <pthread.h>
#include "udp.h"
#include "5gc.h"

#define CG_DEFAULT_SRC_PORT         8888
#define GC_DEFAULT_BROADCAST_PORT   50001
#define GC_BROADCAST_IP             "255.255.255.255"

typedef struct gc_mgr_port {
    uint16_t        port;             /* remote probe port */
    gc_porttype_e   type;             /* port type: black-zone or switch */
} gc_mgr_port_t;

struct gc_manager;
typedef void (*gc_manager_handler_t)(struct gc_manager *mgr, const void *payload, size_t len, struct sockaddr_in *from);
typedef void (*gc_manager_new_target_cb_t)(struct gc_manager *mgr, gc_resp_find_t *new_node, uint16_t probe_port);

/* Manager for multiple 5GC contexts with multi-port probing */
typedef struct gc_manager {
    udp_conn_t         *broadcast_conn;     /* Dedicated for broadcast discovery */
    uint16_t            src_port;           /* Shared local source port */
    bool                is_running;

    pthread_t           broadcast_tid;
    pthread_rwlock_t    lock;               /* Protects child list & probe ports */

    gc_ctx_t          **child_ctxs;
    size_t              num_childs;
    size_t              child_capacity;

    /* Multi-port probing configuration */
    struct probe_port {
        uint16_t        port;               /* remote probe port */
        uint16_t        last_msgno;         /* last sent msgno for this port */
        uint64_t        last_send_ms;       /* last send timestamp */
        gc_porttype_e   type;
        bool            active;
    } *probe_ports;
    size_t              num_probe_ports;
    size_t              probe_capacity;

    /* Callbacks */
    gc_manager_handler_t        on_find_req;          /* FIND request received on broadcast */
    gc_manager_handler_t        on_register_req;      /* REGISTER request received on broadcast */
    gc_manager_handler_t        on_heartbeat_req;     /* HEARTBEAT request received on broadcast */
    gc_manager_new_target_cb_t  on_new_target;        /* new target discovered, includes probe port */
    void                       (*on_child_state_change)(gc_ctx_t *child, gc_state_e new_state);
} gc_manager_t;

/**
 * @brief Create a new 5GC manager instance.
 * @param src_port The local source UDP port for all child contexts. If 0, OS assigns ephemeral port.
 * @param target_ports Array of target UDP ports to probe. If NULL, defaults to GC_DEFAULT_BROADCAST_PORT.
 * @param num_ports Number of ports in the target_ports array.
 * @return Pointer to the new gc_manager_t instance, or NULL on failure.
 */
gc_manager_t* gc_mgr_create(
    uint16_t src_port,
    const gc_mgr_port_t *target_ports,   /* array of ports to probe */
    size_t num_ports
);

/**
 * @brief Destroy a 5GC manager instance and free all associated resources.
 * @param mgr Pointer to the gc_manager_t instance to destroy.
 */
void gc_mgr_destroy(gc_manager_t *mgr);

/**
 * @brief Start the 5GC manager's background broadcast thread.
 * @param mgr Pointer to the gc_manager_t instance.
 * @return 0 on success, -1 on failure.
 */
int gc_mgr_start(gc_manager_t *mgr);

/**
 * @brief Stop the 5GC manager's background broadcast thread and all child services.
 * @param mgr Pointer to the gc_manager_t instance.
 */
void gc_mgr_stop(gc_manager_t *mgr);

/**
 * @brief Set the handler for incoming FIND requests on the broadcast socket.
 * @param mgr Pointer to the gc_manager_t instance.
 * @param handler Function pointer to the FIND request handler.
 */
void gc_mgr_set_find_handler(gc_manager_t *mgr, gc_manager_handler_t handler);

/**
 * @brief Set the callback for new target discovery events.
 * @param mgr Pointer to the gc_manager_t instance.
 * @param cb Function pointer to the new target callback.
 */
void gc_mgr_set_new_target_cb(gc_manager_t *mgr, gc_manager_new_target_cb_t cb);

/**
 * @brief Set the callback for child state change events.
 * @param mgr Pointer to the gc_manager_t instance.
 * @param cb Function pointer to the child state change callback.
 */
void gc_mgr_set_child_state_cb(gc_manager_t *mgr, void (*cb)(gc_ctx_t*, gc_state_e));

/**
 * @brief Dynamically add a probe port to the manager.
 * @param mgr Pointer to the gc_manager_t instance.
 * @param port The UDP port to add for probing.
 * @return 0 on success, -1 on failure (e.g., port already exists or manager is not running).
 */
int gc_mgr_add_probe_port(gc_manager_t *mgr, uint16_t port);

/**
 * @brief Get the number of child contexts managed by this manager.
 * @param mgr Pointer to the gc_manager_t instance.
 * @return Number of child contexts.
 */
size_t gc_mgr_get_child_count(gc_manager_t *mgr);

/**
 * @brief Get a child context by its index.
 * @param mgr Pointer to the gc_manager_t instance.
 * @param index Index of the child context to retrieve.
 * @return Pointer to the gc_ctx_t instance, or NULL if index is out of bounds
 */
gc_ctx_t* gc_mgr_get_child(gc_manager_t *mgr, size_t index);

/**
 * @brief Find a child context by its target IP and port.
 * @param mgr Pointer to the gc_manager_t instance.
 * @param ip Target IPv4 address in network byte order.
 * @param port Target UDP port.
 * @return Pointer to the gc_ctx_t instance if found, or NULL if not found.
 */
gc_ctx_t* gc_mgr_find_child(gc_manager_t *mgr, uint32_t ip, uint16_t port);

/**
 * @brief Resume probing on a specific port.
 * @param mgr Pointer to the gc_manager_t instance.
 * @param port The UDP port to resume probing.
 */
void gc_mgr_resume_probe_port(gc_manager_t *mgr, uint16_t port);

/**
 * @brief Remove and destroy a child context from the manager.
 * @param mgr Pointer to the gc_manager_t instance.
 * @param child Pointer to the gc_ctx_t instance to remove.
 * @warning This will stop and destroy the child context. child must not be used after this call.
 */
void gc_mgr_remove_child(gc_manager_t *mgr, gc_ctx_t *child);

/**
 * @brief Get the server IP address for a given port type from the managed children.
 * @param mgr Pointer to the gc_manager_t instance.
 * @param porttype The port type to search for (GC_MGR_BLACK or GC_MGR_SWITCH).
 * @param out_ip Pointer to a uint32_t variable to receive the server IP in network byte order.
 * @return 0 on success, -1 if no matching child found or on error.
 * @warning out_ip must not be NULL. out_ip is network byte order. 
 */
int gc_mgr_get_ip_by_type(gc_manager_t *mgr, gc_porttype_e porttype, uint32_t *out_ip);

/**
 * @brief Get the device MAC address for a given port type from the managed children.
 * @param mgr Pointer to the gc_manager_t instance.
 * @param porttype The port type to search for (GC_MGR_BLACK or GC_MGR_SWITCH).
 * @param out_mac Pointer to a 6-byte array to receive the MAC address.
 * @return 0 on success, -1 if no matching child found or on error.
 * @warning out_mac must not be NULL. out_mac is 6 bytes.
 */
int gc_mgr_get_mac_by_type(gc_manager_t *mgr, gc_porttype_e porttype, uint8_t out_mac[6]);


#endif