/*
 * Copyright (c) 2026-2026, Red LRM.
 * Author: [yanruibing]
 * All rights reserved.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/select.h>
#include <time.h>
#include "log.h"
#include "util.h"
#include "udp.h"
#include "auth.h"
#include "5gcmanager.h"


static void gc_manager_default_find_handler(gc_manager_t *mgr, const void *data, size_t len, struct sockaddr_in *from) {
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
    
    udp_send_raw(mgr->broadcast_conn, inet_ntoa(from->sin_addr), ntohs(from->sin_port), &resp, sizeof(resp));
}

static void gc_manager_default_register_handler(gc_manager_t *mgr, const void *data, size_t len, struct sockaddr_in *from) {
    if (len < sizeof(gc_header_t)) return;

    gc_header_t *req_h = (gc_header_t *)data;
    gc_resp_register_t resp;
    memset(&resp, 0, sizeof(resp));
    
    resp.head = *req_h;
    resp.head.type = GC_SUB_RESP;
    resp.result = GC_NO_ERROR; // 默认成功

    hdr_build((unsigned char*)&resp.head.hdr, AUTH_DATA, sizeof(resp), auth_get_static_value());
    
    udp_send_raw(mgr->broadcast_conn, inet_ntoa(from->sin_addr), ntohs(from->sin_port), &resp, sizeof(resp));
}

/**
 * @brief Default handler for incoming Heartbeat requests.
 * Automatically acknowledges heartbeat packets by echoing the sequence number (MsgNo)
 * back to the sender. This ensures the remote peer knows this service is still alive.
 */
static void gc_manager_default_heartbeat_handler(gc_manager_t *mgr, const void *data, size_t len, struct sockaddr_in *from) {
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
    udp_send_raw(mgr->broadcast_conn, client_ip, ntohs(from->sin_port), &resp, sizeof(resp));
}

/**
 * @brief Sends a FIND request via broadcast on the specified port.
 * @param mgr  Pointer to the gc_manager_t structure.
 * @param port Target destination port for the FIND request.
 * @return uint16_t The message number (msgno) used in the request, or 0 on failure.
 */
static int gc_manager_send_find(gc_manager_t *mgr, uint16_t port) {
    uint16_t msgno = get_next_msgno();

    log_info("Broadcast FIND on port %u (MsgNo: %u)", port, msgno);

    gc_req_find_t req = {0};
    gc_build_header(&req.head, GC_FIND, GC_SUB_REQ, msgno);
    req.iptype = GC_IPV4;
    req.port   = htons(port);

    hdr_build((unsigned char*)&req.head.hdr, AUTH_DATA, sizeof(req), auth_get_static_value());

    int ret = udp_send_raw(mgr->broadcast_conn, GC_BROADCAST_IP, port, &req, sizeof(req));
    if (ret <= 0) {
        log_error("Broadcast to port %u failed", port);
        return 0;
    }

    return msgno;
}

static void gc_mgr_broadcast_all(gc_manager_t *mgr, uint64_t now_ms) {
    pthread_rwlock_wrlock(&mgr->lock);

    for (size_t i = 0; i < mgr->num_probe_ports; i++) {
        struct probe_port *p = &mgr->probe_ports[i];

        if (!p->active) continue;
        if (now_ms - p->last_send_ms < GC_FIND_INTERVAL * 1000ULL) {
            continue;
        }

        uint16_t sent_msgno = gc_manager_send_find(mgr, p->port);
        if (sent_msgno != 0) {
            p->last_msgno = sent_msgno;
            p->last_send_ms = now_ms;
        }
    }

    pthread_rwlock_unlock(&mgr->lock);
}

static gc_ctx_t* gc_mgr_create_child(gc_manager_t *mgr, gc_resp_find_t *resp, uint16_t probe_port, gc_porttype_e porttype) {
    gc_ctx_t *child = gc_service_create(mgr->src_port, probe_port, porttype);
    if (!child) return NULL;
    
    /**
     * Initialize the child's protocol data with the discovered server information.
     * This includes the server's device ID and IP address.
     */
    memcpy(&child->node, resp, sizeof(*resp));

    // log_info("Creating child context for target %s:%u iptype:%d (PortType: %s)", 
    //          inet_ntoa(child->node.ipv4), child->target_port, child->node.iptype,
    //          porttype == GC_MGR_BLACK ? "BLACK" : "SWITCH");

    char ip_str[INET_ADDRSTRLEN];
    ip_ntop(resp->ipv4.s_addr, ip_str, sizeof(ip_str));

    /**
     * Connect the child's UDP connection to the discovered server IP and probe port.
     * This enables direct communication for registration and heartbeat messages.
     * If the connection fails, clean up and return NULL.
     */
    if (udp_set_connect(child->conn, resp->ipv4.s_addr, probe_port) < 0) {
        log_error("Failed to connect child to %s:%u", ip_str, probe_port);
        gc_service_destroy(child);
        return NULL;
    }

    log_info("Child created & connected to %s:%u", ip_str, probe_port);

    child->state = GC_STATE_REGISTER;
    child->fail_count = 0;
    child->mgr = mgr;

    if (mgr->on_child_state_change) {
        child->on_state_change = mgr->on_child_state_change;
    }

    return child;
}

/**
 * @brief Reallocates the child_ctxs array to accommodate more child contexts.
 * @param mgr Pointer to the gc_manager_t structure.
 * @return int 0 on success, -1 on failure.
 */
static int gc_mgr_realloc_childs(gc_manager_t *mgr) {
    if (mgr->num_childs < mgr->child_capacity) {
        return 0;
    }

    size_t new_cap = mgr->child_capacity ? mgr->child_capacity * 2 : 8;
    gc_ctx_t **new_arr = (gc_ctx_t **)realloc(mgr->child_ctxs, new_cap * sizeof(gc_ctx_t*));
    
    if (!new_arr) {
        log_error("OOM: Failed to expand child_ctxs to %zu", new_cap);
        return -1;
    }

    mgr->child_ctxs = new_arr;
    mgr->child_capacity = new_cap;
    return 0;
}

static void gc_manager_dispatch(gc_manager_t *mgr, void *buf, ssize_t n, struct sockaddr_in *from) {
    if (!hdr_verify_crc(buf, n)) {
        log_error("GC manager message dispatcher CRC verification failed");
        return;
    }

    if (n < (ssize_t)sizeof(gc_header_t)) return;

    gc_header_t *h = (gc_header_t*)buf;
    if (memcmp(h->symbol, "5G", 2) != 0) return;

    uint16_t msgno = ntohs(h->msgno);

    if (h->type == GC_SUB_REQ) {
        switch (h->cls) {
            case GC_FIND:
                log_info("<<< Recv Find Message!");
                mgr->on_find_req ? mgr->on_find_req(mgr, buf, n, from) : gc_manager_default_find_handler(mgr, buf, n, from);
                break;
            case GC_REGISTER:
                log_info("<<< Recv Register Message!");
                mgr->on_register_req ? mgr->on_register_req(mgr, buf, n, from) : gc_manager_default_register_handler(mgr, buf, n, from);
                break;
            case GC_HEARBEAT:
                log_info("<<< Recv Heartbeat Message!");
                mgr->on_heartbeat_req ? mgr->on_heartbeat_req(mgr, buf, n, from) : gc_manager_default_heartbeat_handler(mgr, buf, n, from);
                break;
            default:
                return;
        }
        return;
    }

    if (h->type == GC_SUB_RESP && h->cls == GC_FIND) {
        if (n < (ssize_t)sizeof(gc_resp_find_t)) return;

        // Match msgno to probe ports
        uint16_t matched_port = 0;
        gc_porttype_e porttype = GC_MGR_BLACK; // Default value
        pthread_rwlock_rdlock(&mgr->lock);
        for (size_t i = 0; i < mgr->num_probe_ports; i++) {
            if (mgr->probe_ports[i].last_msgno == msgno) {
                matched_port = mgr->probe_ports[i].port;
                porttype = mgr->probe_ports[i].type;
                break;
            } 
        }
        pthread_rwlock_unlock(&mgr->lock);

        if (matched_port == 0) {
            log_debug("FIND response MsgNo %u not matched to any probe", msgno);
            return;
        }

        gc_resp_find_t *resp = (gc_resp_find_t *)buf;

        /**
         * Check if a child context already exists for this target IP and port.
         * If so, ignore this response to avoid duplicate child services.
         */
        if (gc_mgr_find_child(mgr, resp->ipv4.s_addr, matched_port)) {
            log_debug("Target %s:%u already has a child service, skipping.", 
                    inet_ntoa(resp->ipv4), matched_port);
            return;
        }

        log_warn(">>> New target discovered at %s:%u (MsgNo: %u)", 
                 inet_ntoa(resp->ipv4), matched_port, msgno);

        gc_ctx_t *child = gc_mgr_create_child(mgr, resp, matched_port, porttype);
        if (!child) return;

        if (gc_service_start(child) != 0) {
            log_error("Failed to start service for %s:%u", inet_ntoa(resp->ipv4), matched_port);
            gc_service_destroy(child);
            return;
        }

        pthread_rwlock_wrlock(&mgr->lock);
        
        if (gc_mgr_realloc_childs(mgr) != 0) {
            pthread_rwlock_unlock(&mgr->lock);
            log_error("OOM: Failed to expand child array");
            gc_service_stop(child);
            gc_service_destroy(child);
            return;
        }
        mgr->child_ctxs[mgr->num_childs++] = child;

        for (size_t i = 0; i < mgr->num_probe_ports; i++) {
            if (mgr->probe_ports[i].port == matched_port) {
                mgr->probe_ports[i].active = false;
                break;
            }
        }
        pthread_rwlock_unlock(&mgr->lock);

        if (mgr->on_new_target) {
            mgr->on_new_target(mgr, resp, matched_port);
        }
    }
}

static void gc_mgr_reap_children(gc_manager_t *mgr) {
    pthread_rwlock_wrlock(&mgr->lock);

    for (size_t i = 0; i < mgr->num_childs; ) {
        gc_ctx_t *child = mgr->child_ctxs[i];
        
        if (!child->is_running) {
            log_info("Reaping stopped child service at index %zu", i);
            
            gc_service_destroy(child);

            mgr->child_ctxs[i] = mgr->child_ctxs[mgr->num_childs - 1];
            mgr->child_ctxs[mgr->num_childs - 1] = NULL;
            mgr->num_childs--;
            
            continue; 
        }

        i++;
    }

    pthread_rwlock_unlock(&mgr->lock);
}

static void* gc_mgr_broadcast_thread(void *arg) {
    gc_manager_t *mgr = (gc_manager_t*)arg;
    char buf[2048];
    struct sockaddr_in from;
    fd_set fds;

    while (mgr->is_running) {
        uint64_t now = get_now_ms();

        /**
         * Broadcast FIND requests on all active probe ports as per their schedule.
         * This keeps the discovery process ongoing and allows new targets to be found.
         */
        gc_mgr_broadcast_all(mgr, now);

        /**
         * Clean up any child services that have stopped running.
         * This helps free resources and maintain an accurate list of active children.
         */
        gc_mgr_reap_children(mgr);

        FD_ZERO(&fds);
        FD_SET(mgr->broadcast_conn->fd, &fds);

        struct timeval tv = {0, 80000};  // 80 ms

        int r = select(mgr->broadcast_conn->fd + 1, &fds, NULL, NULL, &tv);
        if (r > 0) {
            if (FD_ISSET(mgr->broadcast_conn->fd, &fds)) {
                ssize_t n = udp_recv_raw(mgr->broadcast_conn, buf, sizeof(buf), &from, 0);
                if (n > 0) {
                    /**
                     * Dispatch the received UDP packet to the appropriate handler based on its type.
                     * This includes handling FIND responses and other message types.
                     */
                    gc_manager_dispatch(mgr, buf, n, &from);
                } else if (n < 0) {
                    log_debug("+++UDP recv error: %s+++", strerror(errno));
                }
            }
        } else if (r < 0) {
            if (errno == EINTR) continue;
            log_error("+++Select crash: %s+++", strerror(errno));
            break;
        }
    }
    return NULL;
}

gc_manager_t* gc_mgr_create(uint16_t src_port, const gc_mgr_port_t *target_ports, size_t num_ports) {
    gc_manager_t *mgr = calloc(1, sizeof(gc_manager_t));
    if (!mgr) return NULL;

    mgr->src_port = src_port ? src_port : CG_DEFAULT_SRC_PORT;

    mgr->broadcast_conn = udp_init_listener(mgr->src_port, 1);
    if (!mgr->broadcast_conn) {
        goto cleanup;
    }
    /**
     * Enable broadcast capability on the UDP socket.
     * This is essential for sending FIND requests to the broadcast address.
     * Failure to set this option will result in broadcast packets being dropped
     * by the operating system.
     */
    if (udp_set_broadcast(mgr->broadcast_conn, 1) != 0) {
        log_error("Failed to enable broadcast on UDP socket");
        goto cleanup;
    }

    pthread_rwlock_init(&mgr->lock, NULL);

    mgr->probe_capacity = num_ports > 0 ? num_ports * 2 : 4;
    mgr->probe_ports = calloc(mgr->probe_capacity, sizeof(*mgr->probe_ports));
    if (!mgr->probe_ports) goto cleanup;

    if (num_ports == 0) {
        mgr->probe_ports[0].port = GC_DEFAULT_BROADCAST_PORT;
        mgr->probe_ports[0].type = GC_MGR_BLACK;
        mgr->probe_ports[0].active = true;
        mgr->num_probe_ports = 1;
    } else {
        for (size_t i = 0; i < num_ports; i++) {
            mgr->probe_ports[i].port = target_ports[i].port;
            mgr->probe_ports[i].type = target_ports[i].type;
            mgr->probe_ports[i].active = true;
        }
        mgr->num_probe_ports = num_ports;
    }

    mgr->child_capacity = 4;
    mgr->child_ctxs = (gc_ctx_t**)calloc(mgr->child_capacity, sizeof(gc_ctx_t*));
    if (!mgr->child_ctxs) goto cleanup;

    return mgr;

cleanup:
    if (mgr->broadcast_conn) udp_close(mgr->broadcast_conn);
    if (mgr->probe_ports) free(mgr->probe_ports);
    free(mgr);
    return NULL;
}

void gc_mgr_destroy(gc_manager_t *mgr) {
    if (!mgr) return;

    gc_mgr_stop(mgr);

    if (mgr->broadcast_conn) {
        udp_close(mgr->broadcast_conn);
    }

    pthread_rwlock_wrlock(&mgr->lock);
    for (size_t i = 0; i < mgr->num_childs; i++) {
        gc_service_stop(mgr->child_ctxs[i]);
        gc_service_destroy(mgr->child_ctxs[i]);
    }
    free(mgr->child_ctxs);
    free(mgr->probe_ports);
    pthread_rwlock_unlock(&mgr->lock);

    pthread_rwlock_destroy(&mgr->lock);
    free(mgr);
}

int gc_mgr_start(gc_manager_t *mgr) {
    if (!mgr || mgr->is_running) return -1;

    mgr->is_running = true;

    if (pthread_create(&mgr->broadcast_tid, NULL, gc_mgr_broadcast_thread, mgr) != 0) {
        mgr->is_running = false;
        return -1;
    }

    return 0;
}

void gc_mgr_stop(gc_manager_t *mgr) {
    if (!mgr || !mgr->is_running) return;

    mgr->is_running = false;
    pthread_join(mgr->broadcast_tid, NULL);

    pthread_rwlock_wrlock(&mgr->lock);

    for (size_t i = 0; i < mgr->num_childs; i++) {
        gc_service_stop(mgr->child_ctxs[i]);
    }

    pthread_rwlock_unlock(&mgr->lock);
}

void gc_mgr_set_find_handler(gc_manager_t *mgr, gc_manager_handler_t find) {
    if (mgr) mgr->on_find_req = find;
}

void gc_mgr_set_new_target_cb(gc_manager_t *mgr, gc_manager_new_target_cb_t cb) {
    if (mgr) mgr->on_new_target = cb;
}

void gc_mgr_set_child_state_cb(gc_manager_t *mgr, void (*cb)(gc_ctx_t*, gc_state_e)) {
    if (mgr) mgr->on_child_state_change = cb;
}

int gc_mgr_add_probe_port(gc_manager_t *mgr, uint16_t port) {
    if (!mgr) return -1;

    pthread_rwlock_wrlock(&mgr->lock);

    if (mgr->num_probe_ports >= mgr->probe_capacity) {
        size_t new_cap = mgr->probe_capacity * 2;
        struct probe_port *new_arr = realloc(mgr->probe_ports, new_cap * sizeof(*mgr->probe_ports));
        if (!new_arr) {
            pthread_rwlock_unlock(&mgr->lock);
            return -1;
        }
        mgr->probe_ports = new_arr;
        mgr->probe_capacity = new_cap;
    }
    mgr->probe_ports[mgr->num_probe_ports].port = port;
    mgr->probe_ports[mgr->num_probe_ports].last_msgno = 0;
    mgr->probe_ports[mgr->num_probe_ports].last_send_ms = 0;
    mgr->num_probe_ports++;

    pthread_rwlock_unlock(&mgr->lock);

    return 0;
}

size_t gc_mgr_get_child_count(gc_manager_t *mgr) {
    if (!mgr) return 0;

    size_t cnt;
    pthread_rwlock_rdlock(&mgr->lock);

    cnt = mgr->num_childs;

    pthread_rwlock_unlock(&mgr->lock);

    return cnt;
}

gc_ctx_t* gc_mgr_get_child(gc_manager_t *mgr, size_t index) {
    if (!mgr || !mgr->child_ctxs) return NULL;

    gc_ctx_t *c = NULL;

    pthread_rwlock_rdlock(&mgr->lock);

    if (index < mgr->num_childs) 
        c = mgr->child_ctxs[index];

    pthread_rwlock_unlock(&mgr->lock);

    return c;
}

gc_ctx_t* gc_mgr_find_child(gc_manager_t *mgr, uint32_t ip, uint16_t port) {
    if (!mgr) return NULL;

    gc_ctx_t *found = NULL;

    pthread_rwlock_rdlock(&mgr->lock);

    for (size_t i = 0; i < mgr->num_childs; i++) {
        gc_ctx_t *c = mgr->child_ctxs[i];
        if (c->node.ipv4.s_addr == ip && c->target_port == port) {
            found = c;
            break;
        }
    }
    
    pthread_rwlock_unlock(&mgr->lock);

    return found;
}

void gc_mgr_resume_probe_port(gc_manager_t *mgr, uint16_t port) {
    if (!mgr) return;
    
    pthread_rwlock_wrlock(&mgr->lock);

    for (size_t i = 0; i < mgr->num_probe_ports; i++) {
        if (mgr->probe_ports[i].port == port) {
            mgr->probe_ports[i].active = true;
            mgr->probe_ports[i].last_send_ms = 0;  // 立即触发下一次广播
            break;
        }
    }

    pthread_rwlock_unlock(&mgr->lock);
}

void gc_mgr_remove_child(gc_manager_t *mgr, gc_ctx_t *child) {
    pthread_rwlock_wrlock(&mgr->lock);

    for (size_t i = 0; i < mgr->num_childs; i++) {
        if (mgr->child_ctxs[i] == child) {
            gc_service_stop(child);
            gc_service_destroy(child);

            for (size_t j = i; j < mgr->num_childs - 1; j++) {
                mgr->child_ctxs[j] = mgr->child_ctxs[j+1];
            }
            mgr->num_childs--;

            break;
        }
    }

    pthread_rwlock_unlock(&mgr->lock);
}


int gc_mgr_get_ip_by_type(gc_manager_t *mgr, gc_porttype_e porttype, uint32_t *out_ip) {
    if (!mgr || !out_ip) return -1;

    pthread_rwlock_rdlock(&mgr->lock);

    for (size_t i = 0; i < mgr->num_childs; i++) {
        gc_ctx_t *c = mgr->child_ctxs[i];
        if (c->porttype == porttype) {
            if (gc_get_server_ip(c, out_ip) == 0) {
                pthread_rwlock_unlock(&mgr->lock);
                return 0;
            }
        }
    }

    pthread_rwlock_unlock(&mgr->lock);
    return -1;
}

int gc_mgr_get_mac_by_type(gc_manager_t *mgr, gc_porttype_e porttype, uint8_t out_mac[6]) {
    if (!mgr || !out_mac) return -1;

    pthread_rwlock_rdlock(&mgr->lock);

    for (size_t i = 0; i < mgr->num_childs; i++) {
        gc_ctx_t *c = mgr->child_ctxs[i];
        if (c->porttype == porttype) {
            if (gc_get_device_id(c, out_mac) == 0) {
                pthread_rwlock_unlock(&mgr->lock);
                return 0;
            }
        }
    }

    pthread_rwlock_unlock(&mgr->lock);
    return -1;
}