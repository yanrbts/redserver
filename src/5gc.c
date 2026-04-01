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
#include "log.h"
#include "udp.h"
#include "auth.h"
#include "util.h"
#include "5gc.h" 
#include "5gcmanager.h"

uint16_t get_next_msgno() {
    /* Used to differentiate consecutive messages. 
     * Responder must echo this value back in the response. */
    static uint16_t global_msgno = 0;
    /**
     * __sync_fetch_and_add is a GCC built-in atomic intrinsic.
     * It performs an atomic "fetch-and-add" operation on the variable.
     * 1. Read: It retrieves the current value of 'global_msgno'.
     * 2. Add:  It increments 'global_msgno' by 1.
     * 3. Atomicity: These steps are performed as a single, indivisible operation
     * at the CPU hardware level (using bus locking or LL/SC instructions).
     * This prevents "Race Conditions" where two threads might otherwise read 
     * the same value simultaneously, ensuring each discovery request gets a 
     * unique 'current_msgno' even when red-zone and black-zone discovery 
     * run in parallel.
     */
    return __sync_fetch_and_add(&global_msgno, 1);
}

void gc_build_header(gc_header_t *head, uint8_t cls, uint8_t type, uint16_t msgno) {
    memcpy(head->symbol, "5G", 2);
    head->version = 1;   /* Protocol Version 1 */
    head->cls = cls;     /* Message Class */
    head->type = type;   /* Message Type */
    head->msgno = htons(msgno);
    head->empty = 0;     /* No fragmentation support currently */
    memset(head->ether_header, 0, sizeof(head->ether_header)); /* Clear MAC header */
    head->ether_header[12] = 0x08;
    head->ether_header[13] = 0x57;
}

/**
 * @brief Handles registration response codes and logs corresponding status.
 * @param code  The result code returned by the server.
 * @param msgno The sequence number associated with the request.
 * @return int  Returns 0 on success, or -1 for any server-side failure.
 */
static int gc_register_error(uint8_t code, uint16_t msgno) {
    switch (code) {
        case GC_NO_ERROR:
            log_info("+++ Register Success (MsgNo: %u) +++", msgno);
            return 0;
        case GC_PARAM_ERROR:
            log_error("+++ Register failed: Parameter error (MsgNo: %u) +++", msgno);
            break;
        case GC_OUT_OF_RES:
            log_error("+++ Register failed: Insufficient server resources +++");
            break;
        case GC_MOUDLE_ERROR:
            log_error("+++ Register failed: Internal module error +++");
            break;
        case GC_SYS_BUSY:
            log_error("+++ Register failed: System busy +++");
            break;
        case GC_TASK_BUSY:
            log_error("+++ Register failed: Task queue full/busy +++");
            break;
        case GC_SERVICE_EXIST:
            log_error("+++ Register conflict: Service already exists. "
                      "IP switch may have stale link state +++");
            break;
        default:
            log_error("+++ Register failed: Unknown error code (0x%02X) +++", code);
            return -1;
    }
    /* All error cases above (except success/default) return -1 */
    return -1;
}

/**
 * @brief Performs service registration to a discovered host via UDP.
 * This function retrieves local MAC/IP, constructs a registration request, 
 * and waits for a server response using a temporary UDP connection.
 * @param ctx     Pointer to the context containing discovered server info.
 * @param port The target destination port for discovery (e.g., 50001).
 * @param porttype The port type (BLACK or SWITCH).
 * @return int    Returns send data length. or faile -1
 */
static int gc_register_service(gc_ctx_t *ctx, uint16_t port, gc_porttype_e porttype) {
    if (!ctx) return -1;

    uint8_t src_mac[6];
    uint32_t src_ip;

    uint16_t target_port = port ? port : GC_DEFAULT_BROADCAST_PORT; 
    uint16_t current_msgno = get_next_msgno();
    ctx->last_query_msgno = current_msgno;

    gc_resp_find_t *found_host = &ctx->node; //isblack ? &ctx->black_node : &ctx->switch_node;
    
    if (found_host->ipv4.s_addr == 0) {
        log_error("Register aborted: Target server IP is 0.0.0.0 (Scan first!)");
        return -1;
    }

    char server_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &found_host->ipv4, server_ip, sizeof(server_ip));

    /* Build Request Packet */
    gc_req_register_t req;
    memset(&req, 0, sizeof(req));
    gc_build_header(&req.head, GC_REGISTER, GC_SUB_REQ, current_msgno);

    /* Fetch local machine identity (MAC and IP) */
    if (get_interface_binary_info(src_mac, &src_ip) != 0) {
        log_error("Failed to retrieve local interface info for registration");
        return -1;
    }
    
    memcpy(req.svrid, src_mac, 6);
    req.iptype = GC_IPV4;
    req.svrrole = GC_B_5GC; /* Default role: 5GC Base Node */
    memcpy(req.svrip, &src_ip, sizeof(req.svrip));

    hdr_build((unsigned char*)&req.head.hdr, AUTH_DATA, sizeof(req), auth_get_static_value());

    log_info(">>> Sending registration request to %s server (%s:%u)...", 
             porttype == GC_MGR_BLACK ? "BLACK" : "SWITCH", server_ip, target_port);
    
    return udp_send_raw(ctx->conn, server_ip, target_port, &req, sizeof(req));
}

/**
 * @brief Sends a heartbeat packet to the discovered server and waits for a response.
 *
 * This function retrieves the server address from the context, constructs a heartbeat 
 * request containing the current system timestamp, and verifies the server's response.
 * It is used to maintain the active session state on the 5GC server.
 *
 * @param ctx     Pointer to the context containing discovered server information.
 * @param port    The destination port (if 0, use GC_DEFAULT_BROADCAST_PORT).
 * @param porttype The port type (BLACK or SWITCH).
 * @return int    Returns send data length. or faile -1
 */
static int gc_hearbeat(gc_ctx_t *ctx, uint16_t port, gc_porttype_e porttype) {
    (void)porttype;

    if (!ctx) return -1;

    /* 1. Select the target host based on the zone flag */
    gc_resp_find_t *target_node = &ctx->node;
    if (target_node->ipv4.s_addr == 0) {
        log_error("Heartbeat failed: Target server IP is not initialized.");
        return -1;
    }

    uint16_t current_msgno = get_next_msgno();
    ctx->last_query_msgno = current_msgno;
    uint16_t target_port = port ? port : GC_DEFAULT_BROADCAST_PORT;

    char server_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &target_node->ipv4, server_ip, sizeof(server_ip));

    /* 3. Construct Heartbeat Request (GC_HEARBEAT) */
    gc_hearbeat_t hb;
    memset(&hb, 0, sizeof(hb));
    gc_build_header(&hb.head, GC_HEARBEAT, GC_SUB_REQ, current_msgno);
    /* Get local system time and convert to Network Byte Order */
    uint32_t now = (uint32_t)time(NULL);
    uint32_t net_now = htonl(now);
    memcpy(hb.tm, &net_now, 4);

    hdr_build((unsigned char*)&hb.head.hdr, AUTH_DATA, sizeof(hb), auth_get_static_value());

    log_debug("Sending heartbeat to %s:%u (MsgNo: %u)...", server_ip, target_port, current_msgno);

    return udp_send_raw(ctx->conn, server_ip, target_port, &hb, sizeof(hb));
}

/**
 * @brief Message Dispatcher / Router
 * * This function acts as the central hub for incoming UDP packets. It distinguishes 
 * between inbound requests (where we act as a Server) and inbound responses 
 * (where we act as a Client).
 * @param ctx   Pointer to the service context.
 * @param buf   Raw buffer containing the received packet.
 * @param n     Length of the data received.
 * @param from  Source address info of the sender.
 * @return int 
 * 0: Packet was a Request (REQ) and has been handled internally by a handler.
 * 1: Packet is a Response (RESP), should be passed back to the client-side logic.
 * -1: Malformed packet, invalid header, or protocol mismatch.
 */
static int gc_message_dispatcher(gc_ctx_t *ctx, void *buf, ssize_t n, struct sockaddr_in *from) {
    /*
     * Packet Validation: Verify CRC and basic header sanity before processing.
     * This prevents malformed or malicious packets from causing undefined behavior
     * in the handlers. The 'hdr_verify_crc' function checks the integrity of the
     * packet using the CRC32 value in the header. If the CRC check fails, 
     * we log an error and discard the packet immediately. This is crucial for security and stability, 
     */
    if (!hdr_verify_crc(buf, n)) {
        log_error("GC message dispatcher CRC verification failed");
        return -1;
    }
    /* Validation: Ensure packet size is at least large enough to contain the protocol header */
    if (n < (ssize_t)sizeof(gc_header_t)) {
        log_error("(n)%d < (head)%d", n, (ssize_t)sizeof(gc_header_t));
        return -1;
    }
    
    gc_header_t *head = (gc_header_t *)buf;
    /* Protocol Sanity Check: Verify the "5G" magic symbol */
    if (memcmp(head->symbol, "5G", 2) != 0) {
        log_error("symbol error");
        return -1;
    }

    if (head->type == GC_SUB_RESP) {
        /* CASE 2: Inbound Response (We are acting as the CLIENT) 
         * Hand the packet back to the waiting Discovery/Register/Heartbeat loop. */
        if (ntohs(head->msgno) != ctx->last_query_msgno) {
            log_debug("Ignored irrelevant RESP (MsgNo mismatch)");
            return -1;
        }

        switch (head->cls) {
            case GC_REGISTER:
                if (n < (ssize_t)sizeof(gc_resp_register_t)) return -1;

                if (n >= (ssize_t)sizeof(gc_resp_register_t)) {
                    gc_resp_register_t *resp = (gc_resp_register_t *)buf;

                    if (resp->result == GC_NO_ERROR) {
                        ctx->state = GC_STATE_HEARTBEAT;
                        ctx->fail_count = 0;
                        if (ctx->on_state_change) ctx->on_state_change(ctx, ctx->state);
                    } else {
                        gc_register_error(resp->result, head->msgno);
                    }
                }
                break;
            case GC_HEARBEAT:
                ctx->fail_count = 0; 
                log_debug("%s:%u Heartbeat ACK received...", inet_ntoa(from->sin_addr), ntohs(from->sin_port));
                break;
            default:
                return -1;
        }
        return 0;
    } else {
        log_error("Head Type error, please check data header!");
    }
    /* Invalid SubType */
    return -1;
}

/**
 * @brief Internal Worker Thread: Drives the Discovery -> Register -> Heartbeat cycle.
 * * This thread manages the full lifecycle of the connection. If heartbeats fail 
 * 3 times consecutively, it automatically falls back to the Discovery state 
 * to re-establish the link.
 */
static void* gc_worker_thread(void* arg) {
    gc_ctx_t *ctx = (gc_ctx_t*)arg;
    fd_set readfds;
    struct timeval tv;
    char recv_buf[1024];
    struct sockaddr_in from_addr;
    uint64_t last_send_time = 0;

    while (ctx->is_running) {
        FD_ZERO(&readfds);
        FD_SET(ctx->conn->fd, &readfds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;    // 100ms

        int ret = select(ctx->conn->fd + 1, &readfds, NULL, NULL, &tv);

        if (ret > 0) {
            ssize_t n = udp_recv_raw(ctx->conn, recv_buf, sizeof(recv_buf), &from_addr, 0);
            if (n > 0) {
                gc_message_dispatcher(ctx, recv_buf, n, &from_addr);
            }
        } else if (ret < 0) {
            /**
             * Error Handling: If select() is interrupted by a signal (EINTR),
             * we simply continue the loop. For other errors, we break out of the loop.
             * This ensures robust operation even in the presence of system signals.
             */
            if (errno == EINTR) continue;
            break;
        }

        uint64_t now_ms = get_now_ms();

        uint64_t interval_ms = (ctx->state == GC_STATE_REGISTER)
                             ? GC_REGISTER_INTERVAL * 1000ULL
                             : GC_HEARBEAT_INTERVAL * 1000ULL;

        if (now_ms - last_send_time >= interval_ms) {

            switch (ctx->state) {
                case GC_STATE_REGISTER:  gc_register_service(ctx, ctx->target_port, ctx->porttype); break;
                case GC_STATE_HEARTBEAT: gc_hearbeat(ctx, ctx->target_port, ctx->porttype); break;
                default: break;
            }
            
            /* --- Transmission Logic & Failure Management ---
             * Every time a request (Discovery, Registration, or Heartbeat) is sent, 
             * we optimistically increment the failure counter.
             * Logic Flow:
             * 1. Send Request: We assume the packet might be lost in the network.
             * 2. Wait for Dispatcher: If the server replies, the 'gc_message_dispatcher' 
             * function will catch the RESPONSE and reset 'ctx->fail_count' to 0.
             * 3. Threshold Check: If 'ctx->fail_count' reaches the threshold (e.g., 3), 
             * it means no valid responses were received for the last 3 attempts.
             */
            ctx->fail_count++;

            /* Check if the retry threshold has been exceeded.
             * If the server is unreachable or the network link is broken, 
             * revert the Finite State Machine (FSM) to the initial Discovery phase.
             */
            if (ctx->fail_count >= GC_RETRY_THRESHOLD) {
                ctx->state = GC_STATE_DISCOVERY;
                // ctx->fail_count = 0;

                if (ctx->mgr) {
                    /**
                     * Notify the manager to resume probing on this port,
                     * allowing manager free ctx of this port.
                     */
                    gc_mgr_resume_probe_port(ctx->mgr, ctx->target_port);
                }

                if (ctx->on_state_change) {
                    ctx->on_state_change(ctx, ctx->state);
                }
                ctx->is_running = false; // Stop the thread
                break;
            }
            last_send_time = now_ms;
        }
    }

    log_info("5GC HearBeat worker thread exiting.");

    return NULL;
}

gc_ctx_t* gc_service_create(uint16_t src_port, uint16_t target_port, gc_porttype_e porttype) {
    gc_ctx_t *ctx = (gc_ctx_t*)malloc(sizeof(gc_ctx_t));
    if (!ctx) {
        log_error("Memory allocation failed for 5GC context.");
        return NULL;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->target_port = target_port;
    ctx->src_port = src_port;
    ctx->porttype = porttype;
    ctx->state = GC_STATE_REGISTER;
    ctx->is_running = false;
    ctx->fail_count = 0;

    /* Initialize the persistent UDP connection once */
    /* Using 0 for local port to let OS assign an ephemeral port, 
       but it stays FIXED for this ctx */
    ctx->conn = udp_init_listener(ctx->src_port, 1);
    if (!ctx->conn) {
        log_error("Failed to initialize UDP socket.");
        free(ctx);
        return NULL;
    }
    pthread_rwlock_init(&ctx->lock, NULL);

    return ctx;
}

void gc_service_destroy(gc_ctx_t *ctx) {
    if (!ctx) return;
    /* Ensure the thread is terminated before freeing */
    gc_service_stop(ctx);

    if (ctx->conn) {
        udp_close(ctx->conn);
    }

    pthread_rwlock_destroy(&ctx->lock);
    free(ctx);

    log_info("5GC context destroyed.");
}

int gc_service_start(gc_ctx_t *ctx) {
    /* Step 1: Safety Validation
     * Ensure the context exists and is not already running to prevent 
     * multiple threads from conflicting over the same network resources. */
    if (!ctx || ctx->is_running) return -1;
    
    /* Step 2: Set the Execution Flag
     * This boolean is the "Main Switch" for the worker thread's while loop. */
    ctx->is_running = true;

    /* Step 3: Launch the Worker Thread
     * - &ctx->worker_tid: Stores the unique ID of the new thread.
     * - NULL: Use default thread attributes (stack size, priority).
     * - gc_worker_thread: The function containing the FSM logic.
     * - ctx: Pass the context pointer as the argument to the thread function. */
    if (pthread_create(&ctx->worker_tid, NULL, gc_worker_thread, ctx) != 0) {
        ctx->is_running = false;
        log_error("Failed to launch 5GC background thread.");
        return -1;
    }
    return 0;
}

void gc_service_stop(gc_ctx_t *ctx) {
    if (!ctx || !ctx->is_running) return;
    
    ctx->is_running = false;
    pthread_join(ctx->worker_tid, NULL);
}

void gc_set_handlers(gc_ctx_t *ctx, gc_handler_t find, gc_handler_t reg, gc_handler_t hb) {
    if (!ctx) return;

    ctx->on_find_req = find;
    ctx->on_register_req = reg;
    ctx->on_heartbeat_req = hb;
}

/**
 * @brief Retrieves the unique device identifier (MAC address) of the local machine.
 *
 * This function fetches the MAC address of the primary network interface 
 * and copies it into the provided output buffer. The MAC address serves 
 * as a unique device identifier in various network protocols. 
 */
static const uint8_t ZERO_MAC[6] = {0, 0, 0, 0, 0, 0};
int gc_get_device_id(gc_ctx_t *ctx, uint8_t out_devid[6]) {
    if (!ctx || !out_devid) return -1;

    pthread_rwlock_rdlock(&ctx->lock);

    if (ctx->state != GC_STATE_HEARTBEAT) {
        pthread_rwlock_unlock(&ctx->lock);
        return -1;
    }

    if (memcmp(ctx->node.devid, ZERO_MAC, 6) != 0) {
        memcpy(out_devid, ctx->node.devid, 6);
        return 0;
    }

    pthread_rwlock_unlock(&ctx->lock);

    return -1;
}

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
int gc_get_server_ip(gc_ctx_t *ctx, uint32_t *out_ip) {
    if (!ctx || !out_ip) return -1;

    pthread_rwlock_rdlock(&ctx->lock);

    if (ctx->state != GC_STATE_HEARTBEAT) {
        pthread_rwlock_unlock(&ctx->lock);
        return -1;
    }

    if (ctx->node.ipv4.s_addr == 0) {
        pthread_rwlock_unlock(&ctx->lock);
        return -1;
    }
    *out_ip = ctx->node.ipv4.s_addr;
    pthread_rwlock_unlock(&ctx->lock);

    return 0;
}