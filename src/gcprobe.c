/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <string.h>
#include <arpa/inet.h>
#include "log.h"
#include "hdr.h"
#include "auth.h"
#include "util.h"
#include "gcprobe.h"

/* Time Configuration (Milliseconds) */
#define INTERVAL_DISCOVERY_MS   10000  /* Discovery period: 10 seconds */
#define INTERVAL_REGISTER_MS    3000   /* Registration retry interval: 3 seconds */
#define INTERVAL_HEARTBEAT_MS   3000   /* Heartbeat cycle: 3 seconds */

/* Threshold Configuration */
#define REGISTER_RETRY_MAX      2      /* Max registration attempts (Initial + Retries) */
#define HEARTBEAT_RETRY_MAX     3      /* Heartbeat failure threshold before timeout */

static uint16_t get_next_msgno() {
    static _Atomic uint16_t global_msgno = 0;
    return atomic_fetch_add(&global_msgno, 1);
}

void gc_xdp_build_header(gc_header_t *head, uint8_t cls, uint8_t type, uint16_t msgno) {
    memcpy(head->symbol, "5G", 2);
    head->version = 0x01;   /* Protocol Version 1 */
    head->cls = cls;     /* Message Class */
    head->type = type;   /* Message Type */
    head->msgno = htons(msgno);
    head->empty = 0;     /* No fragmentation support currently */
    memset(head->ether_header, 0, sizeof(head->ether_header)); /* Clear MAC header */
    head->ether_header[12] = 0x08;
    head->ether_header[13] = 0x57;
}

static void gc_default_find_handler(gc_probe_processor_t *proc, const void *data, size_t len, struct sockaddr_in *from) {
    if (len < sizeof(gc_header_t)) return;

    gc_header_t *req_h = (gc_header_t *)data;
    gc_resp_find_t resp = {0};
    memset(&resp, 0, sizeof(resp));
    
    memcpy(resp.head.symbol, "5G", 2);
    resp.head = *req_h;
    resp.head.type = GC_SUB_RESP;

    uint8_t temp_mac[6];
    uint32_t temp_ip;

    if (get_interface_binary_info(temp_mac, &temp_ip) == 0) {
        memcpy(resp.devid, temp_mac, 6);
        resp.ipv4.s_addr = temp_ip;
    }

    hdr_build((unsigned char*)&resp.head.hdr, AUTH_DATA, sizeof(resp), auth_get_static_value());
    
    udp_send_raw(proc->conn, inet_ntoa(from->sin_addr), ntohs(from->sin_port), &resp, sizeof(resp));
}

static void gc_default_register_handler(gc_probe_processor_t *proc, const void *data, size_t len, struct sockaddr_in *from) {
    if (len < sizeof(gc_header_t)) return;

    gc_header_t *req_h = (gc_header_t *)data;
    gc_resp_register_t resp;
    memset(&resp, 0, sizeof(resp));
    
    resp.head = *req_h;
    resp.head.type = GC_SUB_RESP;
    resp.result = GC_NO_ERROR;

    hdr_build((unsigned char*)&resp.head.hdr, AUTH_DATA, sizeof(resp), auth_get_static_value());
    
    udp_send_raw(proc->conn, inet_ntoa(from->sin_addr), ntohs(from->sin_port), &resp, sizeof(resp));
}

/**
 * @brief Default handler for incoming Heartbeat requests.
 * Automatically acknowledges heartbeat packets by echoing the sequence number (MsgNo)
 * back to the sender. This ensures the remote peer knows this service is still alive.
 */
static void gc_default_heartbeat_handler(gc_probe_processor_t *proc, const void *data, size_t len, struct sockaddr_in *from) {
    if (len < sizeof(gc_header_t)) return;

    gc_header_t *req_h = (gc_header_t *)data;
    gc_hearbeat_t resp;
    memset(&resp, 0, sizeof(resp));
    
    /* Mirror the header and flip the SubType to RESPONSE */
    resp.head = *req_h;
    resp.head.type = GC_SUB_RESP;

    uint32_t now = (uint32_t)time(NULL);
    uint32_t net_now = htonl(now);
    memcpy(resp.tm, &net_now, 4);

    hdr_build((unsigned char*)&resp.head.hdr, AUTH_DATA, sizeof(resp), auth_get_static_value());

    char client_ip[INET_ADDRSTRLEN];
    ip_ntop(from->sin_addr.s_addr, client_ip, sizeof(client_ip));
    
    /* Send Unicast Response to the requester's source port */
    udp_send_raw(proc->conn, client_ip, ntohs(from->sin_port), &resp, sizeof(resp));
}

static void do_node_discovery(gc_probe_processor_t *proc, gc_node_context_t *node) {
    gc_req_find_t req;
    uint16_t msgno = get_next_msgno();
    node->last_msgno = msgno;
    gc_xdp_build_header(&req.head, GC_FIND, GC_SUB_REQ, msgno);
    req.iptype = GC_IPV4;
    
    /*
     * This warning is triggered by GCC's security check mechanism. When you use 
     * `__attribute__((packed))` to pack a struct, member variables 
     * (such as `req.svipv4.s_addr`) may no longer be aligned to a 4-byte boundary in memory.
     * Dereferencing a pointer to such a potentially misaligned member and 
     * casting it to `uint32_t*` may cause a program crash (Alignment Fault) 
     * on certain architectures, like ARM, while it could degrade access performance on x86.
     */
    uint8_t dummy_mac[6];
    uint32_t temp_ip = 0;
    if (get_interface_binary_info(dummy_mac, &temp_ip) == 0) {
        req.svipv4.s_addr = temp_ip; 
    }

    req.port = node->port; 
    hdr_build((unsigned char*)&req.head.hdr, AUTH_DATA, sizeof(req), auth_get_static_value());

    udp_send_raw(proc->conn, GC_BROADCAST_IP, node->port, &req, sizeof(req));
    node->last_send_ms = get_now_ms();

    log_debug("GC_PROBE: Discovery broadcast on port %u", node->port);
}

static void do_node_register(gc_probe_processor_t *proc, gc_node_context_t *node) {
    gc_req_register_t req;
    uint16_t msgno = get_next_msgno();
    node->last_msgno = msgno;

    memset(&req, 0, sizeof(req));
    gc_xdp_build_header(&req.head, GC_REGISTER, GC_SUB_REQ, msgno);

    uint8_t src_mac[6];
    uint32_t src_ip;
    get_interface_binary_info(src_mac, &src_ip);
    
    memcpy(req.svrid, src_mac, 6);
    req.iptype = GC_IPV4;
    req.svrrole = GC_B_5GC;
    memcpy(req.svrip, &src_ip, sizeof(req.svrip));

    hdr_build((unsigned char*)&req.head.hdr, AUTH_DATA, sizeof(req), auth_get_static_value());
    
    udp_send_raw(proc->conn, inet_ntoa(*(struct in_addr*)&node->ip), node->port, &req, sizeof(req));

    node->last_send_ms = get_now_ms();
    node->fail_count++; 
    log_debug(">>> Register Sent to %s", inet_ntoa(*(struct in_addr*)&node->ip));
}

static void do_node_heartbeat(gc_probe_processor_t *proc, gc_node_context_t *node) {
    gc_hearbeat_t hb;
    uint16_t msgno = get_next_msgno();
    node->last_msgno = msgno;

    memset(&hb, 0, sizeof(hb));
    gc_xdp_build_header(&hb.head, GC_HEARBEAT, GC_SUB_REQ, msgno);
    
    uint32_t net_now = htonl((uint32_t)time(NULL));
    memcpy(hb.tm, &net_now, 4);

    hdr_build((unsigned char*)&hb.head.hdr, AUTH_DATA, sizeof(hb), auth_get_static_value());

    udp_send_raw(proc->conn, inet_ntoa(*(struct in_addr*)&node->ip), node->port, &hb, sizeof(hb));

    node->last_send_ms = get_now_ms();
    node->fail_count++;
    log_debug(">>> Heartbeat Sent to %s", inet_ntoa(*(struct in_addr*)&node->ip));
}

static void process_timers(gc_probe_processor_t *proc) {
    uint64_t now = get_now_ms();
    for (int i = 0; i < proc->node_count; i++) {
        gc_node_context_t *node = &proc->nodes[i];

        if (node->state == GC_STATE_DISCOVERY) {
            if (now - node->last_send_ms >= INTERVAL_DISCOVERY_MS) {
                do_node_discovery(proc, node);
            }
        } else if (node->state == GC_STATE_REGISTER) {
            if (node->fail_count >= REGISTER_RETRY_MAX) {
                log_warn("GC_PROBE: Port %u Register fail twice, revert to DISCOVERY", node->port);
                node->state = GC_STATE_DISCOVERY;
                node->fail_count = 0;
                node->last_send_ms = 0; // Immediately trigger the next probe
            } else if (now - node->last_send_ms >= INTERVAL_REGISTER_MS) {
                do_node_register(proc, node);
            }
        } else if (node->state == GC_STATE_HEARTBEAT) {
            if (node->fail_count >= GC_RETRY_THRESHOLD) {
                char ipstr[16] = {0};
                ip_ntop(node->ip, ipstr, sizeof(ipstr));
                log_warn("GC_PROBE: Node (%s) Heartbeat lost, revert to DISCOVERY", ipstr);
                node->state = GC_STATE_DISCOVERY;
                node->fail_count = 0;
                node->last_send_ms = 0; // Immediately trigger the next probe
            } else if (now - node->last_send_ms >= INTERVAL_HEARTBEAT_MS) {
                do_node_heartbeat(proc, node);
            }
        }
    }
}

static void internal_business_logic(gc_probe_processor_t *proc, gc_probe_task_t *task) {
    if (!hdr_verify_crc(task->data, task->len)) return;
    gc_header_t *head = (gc_header_t *)task->data;
    if (memcmp(head->symbol, "5G", 2) != 0) {
        log_error("symbol != '5G'");
        return;
    }

    uint16_t peer_port = ntohs(task->peer.sin_port);
    uint32_t peer_ip = task->peer.sin_addr.s_addr;
    gc_node_context_t *node = NULL;

    for(int i = 0; i < proc->node_count; i++) {
        if(proc->nodes[i].port == peer_port
            && (proc->nodes[i].state == GC_STATE_DISCOVERY || proc->nodes[i].ip == peer_ip)) {
            node = &proc->nodes[i];
            break;
        }
    }

    if (!node) {
        log_error("Not find node");
        return;
    }

    if (head->type == GC_SUB_RESP) {
        if (ntohs(head->msgno) != node->last_msgno) {
            log_error("msgno is match %u:%u", ntohs(head->msgno), node->last_msgno);
            return;
        }

        switch (head->cls) {
            case GC_FIND: {
                gc_resp_find_t *resp = (gc_resp_find_t *)task->data;

                pthread_rwlock_wrlock(&proc->lock);
                node->state = GC_STATE_REGISTER;
                node->fail_count = 0;
                node->ip = resp->ipv4.s_addr;
                memcpy(node->devid, resp->devid, sizeof(node->devid));
                pthread_rwlock_unlock(&proc->lock);

                char ipstr[16] = {0};
                ip_ntop(resp->ipv4.s_addr, ipstr, sizeof(ipstr));
                log_info("GC_PROBE: Node (%s) online.", ipstr);
                break;
            }
            case GC_REGISTER: {
                char ipstr[16] = {0};
                ip_ntop(node->ip, ipstr, sizeof(ipstr));

                gc_resp_register_t *resp = (gc_resp_register_t *)task->data;
                if (resp->result == GC_NO_ERROR) {
                    node->state = GC_STATE_HEARTBEAT;
                    node->fail_count = 0;
                    log_info("GC_PROBE: Node (%s) register successfully.", ipstr);
                } else {
                    node->state = GC_STATE_DISCOVERY;
                    log_error("GC_PROBE: Node (%s) register NAK.", ipstr);
                }
                break;
            }
            case GC_HEARBEAT:
                node->fail_count = 0;
                break;
        }
    } else if (head->type == GC_SUB_REQ) {
        switch (head->cls) {
            case GC_FIND:
                log_info("<<< Recv Find Message!");
                gc_default_find_handler(proc, task->data, task->len, &task->peer);
                break;
            case GC_REGISTER:
                log_info("<<< Recv Register Message!");
                gc_default_register_handler(proc, task->data, task->len, &task->peer);
                break;
            case GC_HEARBEAT:
                log_info("<<< Recv Heartbeat Message!");
                gc_default_heartbeat_handler(proc, task->data, task->len, &task->peer);
                break;
            default:
                return;
        }
        return;
    }
}

/**
 * @brief Background worker thread for processing the packet queue and timers.
 * This thread runs in a continuous loop while the processor is active. It uses 
 * a timed semaphore wait to balance two main responsibilities:
 * 1. Immediate processing of incoming packets enqueued by the receiver.
 * 2. Periodic execution of state machine timers (Discovery, Registration, Heartbeats).
 * @param arg Pointer to the gc_probe_processor_t instance.
 * @return void* Always returns NULL upon thread termination.
 */
static void* probe_worker_thread(void *arg) {
    gc_probe_processor_t *proc = (gc_probe_processor_t *)arg;
    struct timespec ts;

    while (proc->running) {
        /* Use timed wait to handle both "queue-triggered" events and "timer-triggered" logic */
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 100 * 1000000; // 100ms timeout
        if (ts.tv_nsec >= 1000000000) { 
            ts.tv_sec++; 
            ts.tv_nsec -= 1000000000; 
        }

        /* Wait for a packet signal or a 100ms timeout */
        sem_timedwait(&proc->sem, &ts);
        
        /* 1. Drain the packet queue */
        size_t h = atomic_load(&proc->head);
        size_t t = atomic_load(&proc->tail);
        while (h != t) {
            internal_business_logic(proc, &proc->queue[h % MAX_QUEUE_SIZE]);
            h++;
            /* Atomic update of head to allow producer to reuse slots */
            atomic_store(&proc->head, h);
            t = atomic_load(&proc->tail);
        }

        /* 2. Execute periodic state machine tasks (Discovery/Retries/Heartbeats) */
        process_timers(proc);
    }
    return NULL;
}

gc_probe_processor_t* gc_probe_proc_create(const gc_probe_port_t *ports, size_t port_count) {
    if (!ports || port_count == 0) return NULL;

    gc_probe_processor_t *proc = calloc(1, sizeof(gc_probe_processor_t));
    if (!proc) return NULL;

    if (pthread_rwlock_init(&proc->lock, NULL) != 0) {
        log_error("Failed to initialize mutex");
        free(proc);
        return NULL;
    }

    proc->nodes = calloc(port_count, sizeof(gc_node_context_t));
    if (!proc->nodes) { 
        free(proc); 
        return NULL; 
    }

    for (size_t i = 0; i < port_count; i++) {
        proc->nodes[i].port = ports[i].port;
        proc->nodes[i].type = ports[i].type;
        proc->nodes[i].state = GC_STATE_DISCOVERY;
        proc->nodes[i].last_send_ms = 0; 
    }
    proc->node_count = (int)port_count;

    proc->queue = malloc(sizeof(gc_probe_task_t) * MAX_QUEUE_SIZE);
    sem_init(&proc->sem, 0, 0);
    proc->running = true;

    proc->conn = udp_init_listener(0, 1);
    udp_set_broadcast(proc->conn, 1);

    pthread_create(&proc->worker_tid, NULL, probe_worker_thread, proc);
    return proc;
}

void gc_probe_proc_destroy(gc_probe_processor_t *proc) {
    
    if (!proc) return;

    proc->running = false;
    sem_post(&proc->sem);
    pthread_join(proc->worker_tid, NULL);
    pthread_rwlock_destroy(&proc->lock);
    sem_destroy(&proc->sem);
    if (proc->nodes) free(proc->nodes);
    if (proc->queue) free(proc->queue);
    if (proc->conn) udp_close(proc->conn);
    free(proc);

    log_info("Destroy gc probe");
}

bool gc_probe_proc_enqueue(gc_probe_processor_t *proc, const uint8_t *data, size_t len, const struct sockaddr_in *peer) {
    size_t t = atomic_load(&proc->tail);
    size_t h = atomic_load(&proc->head);
    if (t - h >= MAX_QUEUE_SIZE) return false;

    gc_probe_task_t *task = &proc->queue[t % MAX_QUEUE_SIZE];
    task->len = len > MAX_PAYLOAD_SIZE ? MAX_PAYLOAD_SIZE : len;
    memcpy(task->data, data, task->len);
    task->peer = *peer;

    atomic_store(&proc->tail, t + 1);
    sem_post(&proc->sem);
    return true;
}

/**
 * @brief Retrieves the IPv4 address of a node based on its port type.
 * * Searches the active node list for the first node matching the specified 
 * hardware/service type. It prioritizes nodes that have completed discovery.
 * @param proc     Pointer to the probe processor instance.
 * @param porttype The specific port type to search for (e.g., GC_MGR_BLACK).
 * @param out_ip   Pointer to store the discovered IP (network byte order).
 * @return true if a matching node was found; false otherwise.
 */
bool gc_probe_get_ip_by_type(gc_probe_processor_t *proc, gc_porttype_e porttype, uint32_t *out_ip) {
    if (!proc || !out_ip) return false;

    for (int i = 0; i < proc->node_count; i++) {
        gc_node_context_t *node = &proc->nodes[i];
        
        /* * Match by type and ensure the node has a valid IP 
         * (i.e., it has moved past the DISCOVERY state) 
         */
        if (node->type == porttype && node->state != GC_STATE_DISCOVERY) {
            *out_ip = node->ip;
            return true;
        }
    }

    return false;
}

/**
 * @brief Retrieves the MAC address of a node based on its port type.
 * * Searches the node list for the first node matching the specified type.
 * Returns the device ID (MAC address) if the node has been discovered.
 * @param proc     Pointer to the probe processor instance.
 * @param porttype The port type to search for.
 * @param out_mac  Pointer to a buffer (min 6 bytes) to store the MAC address.
 * @return true if a matching node was found; false otherwise.
 */
bool gc_probe_get_mac_by_type(gc_probe_processor_t *proc, gc_porttype_e porttype, uint8_t *out_mac) {
    if (!proc || !out_mac) return false;

    pthread_rwlock_rdlock(&proc->lock);
    for (int i = 0; i < proc->node_count; i++) {
        gc_node_context_t *node = &proc->nodes[i];
        
        /* Ensure the node type matches and it has been identified (device ID is valid) */
        if (node->type == porttype && node->state != GC_STATE_DISCOVERY) {
            memcpy(out_mac, node->devid, 6);
            return true;
        }
    }
    pthread_rwlock_unlock(&proc->lock);

    return false;
}