/**
 * Copyright (c) 2026-2026, Red LRM.
 * Author: yanruibing
 * All rights reserved.
 *
 * @file ljb.c
 * @brief Industrial Protocol Engine Implementation for LJB 408-202X Standard.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include <inttypes.h>

#include "ljb.h"
#include "log.h"

#define LJB_TIMEOUT 2000

static void ljb_load_config_file(ljb_ctx_t *ctx, ljb_node_t role);
static bool ljb_save_uptime(ljb_ctx_t *ctx);

/**
 * @brief Converts a single hex character to its 4-bit nibble value.
 */
static inline int8_t hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/**
 * @brief Safely parses a hex string into a binary byte buffer.
 *
 * @param[in]  str      Null-terminated hex string (e.g., "010200A10064").
 * @param[out] buf      Destination byte buffer.
 * @param[in]  buf_size Maximum capacity of the destination buffer.
 * @return true   Parsed successfully (or safely truncated to fit buf_size).
 * @return false  Null pointer, empty string, or invalid hex character found.
 */
static bool hex2bin(const char *str, uint8_t *buf, size_t buf_size) {
    if (!str || !buf || buf_size == 0) return false;

    memset(buf, 0, buf_size);

    size_t str_len = strlen(str);
    if (str_len == 0) return false;

    size_t idx = 0;
    size_t i = 0;

    while (i < str_len && idx < buf_size) {
        int8_t hi = hex_val(str[i]);
        if (hi < 0) {
            memset(buf, 0, buf_size);
            return false;
        }

        if (i + 1 < str_len) {
            int8_t lo = hex_val(str[i + 1]);
            if (lo < 0) {
                memset(buf, 0, buf_size);
                return false;
            }
            buf[idx++] = (uint8_t)((hi << 4) | lo);
            i += 2;
        } else {
            /* Odd length: pad low nibble with 0 */
            buf[idx++] = (uint8_t)(hi << 4);
            i += 1;
        }
    }

    return true;
}

static char *zstrdup(const char *s) {
    size_t l = strlen(s)+1;
    char *p = malloc(l);

    memcpy(p,s,l);
    return p;
}

/**
 * @brief Get the continuous uptime of the current process/node in seconds.
 *
 * @param[in] start_ts Pointer to the timespec recorded when the program started.
 * @return uint64_t    Seconds elapsed since process startup.
 */
static uint64_t get_uptime_sec(const struct timespec *start_ts) {
    if (!start_ts || start_ts->tv_sec == 0) return 0;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    if (now.tv_sec < start_ts->tv_sec) return 0; // Safeguard

    return (uint64_t)(now.tv_sec - start_ts->tv_sec);
}

/**
 * @brief Computes modular two's complement checksum per Standard Appendix A.2.
 */
static uint8_t ljb_checksum(const uint8_t *buffer, size_t length) {
    uint8_t sum = 0;
    for (size_t i = 0; i < length; ++i) {
        sum = (uint8_t)((sum + buffer[i]) & 0xFF);
    }
    return (uint8_t)(-sum);
}

static const char *get_frame_type_name(uint8_t type) {
    switch (type) {
        case TYPE_HB_REQ:      return "HB_REQ";
        case TYPE_HB_RSP:      return "HB_RSP";
        case TYPE_SW_REQ:      return "SW_REQ";
        case TYPE_SW_RSP:      return "SW_RSP";
        case TYPE_HW_REQ:      return "HW_REQ";
        case TYPE_HW_RSP:      return "HW_RSP";
        case TYPE_SN_REQ:      return "SN_REQ";
        case TYPE_SN_RSP:      return "SN_RSP";
        case TYPE_TIME_REQ:    return "TIME_REQ";
        case TYPE_TIME_RSP:    return "TIME_RSP";
        case TYPE_RACK_REQ:    return "RACK_REQ";
        case TYPE_RACK_RSP:    return "RACK_RSP";
        case TYPE_UPGRADE_REQ: return "UPGRADE_REQ";
        case TYPE_UPGRADE_RSP: return "UPGRADE_RSP";
        case TYPE_ALARM:       return "ALARM";
        default:               return "UNKNOWN";
    }
}

static void log_frame_bytes(ljb_ctx_t *ctx, const uint8_t *frame, uint8_t len, const char *flag) {
    (void)ctx;

    if (!frame || len < 6) {
        log_warn("%s INVALID Received null or truncated frame (len=%u)", 
                 flag ? flag : "TRACE", len);
        return;
    }

    uint8_t src_node = frame[0];
    uint8_t dst_node = frame[1];
    uint8_t type     = frame[2];
    uint8_t seq      = frame[3];

    /* 1. Extract Result Code according to protocol specification */
    uint8_t res_code = 0;
    bool has_rc = false;

    if (type == TYPE_RACK_RSP) { 
        /* TYPE_RACK_RSP: Result Code is at Byte 8 (frame[7]) */
        if (len >= 8) {
            res_code = frame[7];
            has_rc = true;
        }
    } else { 
        /* Standard Responses: Result Code is at Byte 6 (frame[5]) */
        switch (type) {
            case TYPE_HB_RSP:
            case TYPE_SW_RSP:
            case TYPE_HW_RSP:
            case TYPE_SN_RSP:
            case TYPE_TIME_RSP:
            case TYPE_UPGRADE_RSP:
                if (len >= 6) {
                    res_code = frame[5];
                    has_rc = true;
                }
                break;
            default:
                /* Request frames (REQ) or unknown types do not have a result code */
                has_rc = false;
                break;
        }
    }

    /* 2. Format Result Code text representation for consistent log alignment */
    char rc_str[8] = {0};
    if (has_rc) {
        snprintf(rc_str, sizeof(rc_str), "0x%02X", res_code);
    } else {
        snprintf(rc_str, sizeof(rc_str), " -- ");
    }

    /* 3. Extract Checksum from the last byte (frame[len - 1]) */
    uint8_t chk_code = frame[len - 1];

    /* 4. Format full raw frame in Hex */
    char full_hex[LJB_MAX_RAW_FRAME * 3 + 1];
    size_t full_off = 0;

    for (uint8_t i = 0; i < len; ++i) {
        int written = snprintf(full_hex + full_off, sizeof(full_hex) - full_off, "%02X ", frame[i]);
        if (written > 0 && (size_t)written < sizeof(full_hex) - full_off) {
            full_off += (size_t)written;
        } else {
            break; /* Prevent buffer overflow */
        }
    }
    full_hex[full_off] = '\0';

    log_info("[%s %-11s] | %02u->%02u | SEQ:%03u | LEN:%02u | RC:%-4s | CHK:0x%02X | RAW:[ %-72s ]",
             flag ? flag : "TRACE",
             get_frame_type_name(type),
             src_node, dst_node,
             seq, len,
             rc_str,
             chk_code,
             full_hex);
}

/**
 * @brief Encodes raw byte payload into SLIP-framed stream.
 */
static size_t slip_encode_stream(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_capacity) {
    size_t out_idx = 0;

    if (out_idx < dst_capacity) {
        dst[out_idx++] = SLIP_END;
    }

    for (size_t i = 0; i < src_len; ++i) {
        if (src[i] == SLIP_END) {
            if (out_idx + 2 > dst_capacity) return 0;
            dst[out_idx++] = SLIP_ESC;
            dst[out_idx++] = SLIP_ESC_END;
        } else if (src[i] == SLIP_ESC) {
            if (out_idx + 2 > dst_capacity) return 0;
            dst[out_idx++] = SLIP_ESC;
            dst[out_idx++] = SLIP_ESC_ESC;
        } else {
            if (out_idx + 1 > dst_capacity) return 0;
            dst[out_idx++] = src[i];
        }
    }

    if (out_idx < dst_capacity) {
        dst[out_idx++] = SLIP_END;
    }

    return out_idx;
}

/**
 * @brief Configures Linux POSIX UART termios interface.
 */
static int configure_uart_termios(int fd, int baudrate) {
    struct termios options;
    if (tcgetattr(fd, &options) != 0) {
        return -1;
    }

    speed_t speed = B115200;
    if (baudrate == 9600) {
        speed = B9600;
    }

    cfsetispeed(&options, speed);
    cfsetospeed(&options, speed);

    /* Control mode flags: Enable receiver and local line; 
     * set 8N1 (8 data bits, no parity, 1 stop bit, 
     * no hardware flow control) */
    options.c_cflag |= (CLOCAL | CREAD);
    options.c_cflag &= ~(PARENB | CSTOPB | CSIZE | CRTSCTS);
    options.c_cflag |= CS8;

    /* Local mode flags: Enable raw input mode 
     * by disabling canonical mode, echo, and signal handling */
    options.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);

    /* Input mode flags: Disable software flow 
     * control (XON/XOFF) and CR/LF translation */
    options.c_iflag &= ~(IXON | IXOFF | IXANY | ICRNL | INLCR | IGNCR);

    /* Output mode flags: Disable post-processing for raw output */
    options.c_oflag &= ~OPOST;

    /* Non-blocking read with 100ms timeout per byte */
    options.c_cc[VMIN]  = 0;
    options.c_cc[VTIME] = 1;

    /* Flush unread input buffer and apply settings immediately */
    tcflush(fd, TCIFLUSH);
    return tcsetattr(fd, TCSANOW, &options);
}

static ljb_err_t send_raw_frame_unlocked(ljb_ctx_t *ctx, uint8_t dest_node, 
                                        uint8_t type, const uint8_t *payload, 
                                        uint8_t payload_len) {
    uint8_t raw[LJB_MAX_RAW_FRAME];
    uint8_t slip[LJB_MAX_SLIP_FRAME];

    uint8_t total_len = (uint8_t)(5 + payload_len + 1);
    if (total_len > LJB_MAX_RAW_FRAME) {
        return LJB_ERR_INVALID_ARG;
    }

    raw[0] = (uint8_t)ctx->role;
    raw[1] = dest_node;
    raw[2] = type;
    raw[3] = ctx->seq_num++;
    raw[4] = total_len;

    if (payload_len > 0 && payload != NULL) {
        memcpy(&raw[5], payload, payload_len);
    }

    /* Checksum covers header + payload (excludes checksum byte itself) */
    raw[total_len - 1] = ljb_checksum(raw, total_len - 1);

    log_frame_bytes(ctx, raw, total_len, "OUT");

    size_t slip_len = slip_encode_stream(raw, total_len, slip, sizeof(slip));
    if (slip_len == 0) {
        log_info("SLIP encode failed");
        return LJB_ERR_INVALID_ARG;
    }

    ssize_t written = write(ctx->uart_fd, slip, slip_len);
    return (written == (ssize_t)slip_len) ? LJB_OK : LJB_ERR_IO;
}

static ljb_err_t send_raw_frame(ljb_ctx_t *ctx, uint8_t dest_node, 
                                uint8_t type, const uint8_t *payload, 
                                uint8_t payload_len) {
    pthread_mutex_lock(&ctx->lock);
    ljb_err_t ret = send_raw_frame_unlocked(ctx, dest_node, type, payload, payload_len);
    pthread_mutex_unlock(&ctx->lock);
    return ret;
}

static void dispatch_received_frame(ljb_ctx_t *ctx, const uint8_t *frame, uint8_t len) {
    if (ctx == NULL || frame == NULL || len < 6) return;

    uint8_t src_node = frame[0];
    uint8_t dst_node = frame[1];
    uint8_t type     = frame[2];
    uint8_t msg_len  = frame[4];

    log_frame_bytes(ctx, frame, len, "IN ");

    /* Basic frame validation */
    if (dst_node != (uint8_t)ctx->role || msg_len != len) return;
    if (ljb_checksum(frame, len - 1) != frame[len - 1]) return;

    pthread_mutex_lock(&ctx->lock);
    /* Phase 1: Signal matching blocked synchronous query threads */
    if (!ctx->sync_store.is_ready && type == ctx->sync_store.expected_type) {
        switch (type) {
            case TYPE_HB_RSP:
            case TYPE_UPGRADE_RSP:
                if (len == 7) {
                    ctx->sync_store.result_code = frame[5];
                    ctx->sync_store.is_ready = true;
                }
                break;

            case TYPE_SW_RSP:
            case TYPE_HW_RSP:
                if (len == 15) {
                    ljb_version_t *v = (type == TYPE_SW_RSP) ? 
                        &ctx->sync_store.sw_ver : &ctx->sync_store.hw_ver;
                    
                    ctx->sync_store.result_code = frame[5];
                    v->major    = frame[6];
                    v->minor    = frame[7];
                    v->revision = frame[8];
                    v->build    = frame[9];
                    v->ymd      = ((uint32_t)frame[10] << 24) | 
                                  ((uint32_t)frame[11] << 16) |
                                  ((uint32_t)frame[12] << 8)  | 
                                   (uint32_t)frame[13];
                    ctx->sync_store.is_ready = true;
                }
                break;

            case TYPE_SN_RSP:
                if (len == 15) {
                    ctx->sync_store.result_code = frame[5];
                    memcpy(ctx->sync_store.sn, &frame[6], 8);
                    ctx->sync_store.is_ready = true;
                }
                break;
            
            case TYPE_TIME_RSP:
                if (len == 23) {
                    ctx->sync_store.result_code = frame[5];
                    memcpy(ctx->sync_store.total, &frame[6], sizeof(ctx->sync_store.total));
                    memcpy(ctx->sync_store.uptime, &frame[14], sizeof(ctx->sync_store.uptime));
                    ctx->sync_store.is_ready = true;
                }
                break;

            case TYPE_RACK_RSP:
                if (len == 9) {
                    ctx->sync_store.rack_info.rack_id = frame[5];
                    ctx->sync_store.rack_info.slot_id = frame[6];
                    ctx->sync_store.result_code       = frame[7];
                    ctx->sync_store.is_ready = true;
                }
                break;

            default:
                break;
        }

        if (ctx->sync_store.is_ready) {
            pthread_cond_broadcast(&ctx->cond);
            pthread_mutex_unlock(&ctx->lock);
            return;
        }
    }
    pthread_mutex_unlock(&ctx->lock);

    /* Phase 2: Automatic Passive Requests Protocol Handling */
    switch (type) {
        case TYPE_HB_REQ: {
            if (len != 6) break;
            uint8_t rsp[1] = { 0x00 };
            send_raw_frame(ctx, src_node, TYPE_HB_RSP, rsp, sizeof(rsp));
            break;
        }

        case TYPE_SW_REQ:
        case TYPE_HW_REQ: {
            if (len != 6) break;
            uint8_t rsp[9];
            const ljb_version_t *ver = NULL;

            ver = (type == TYPE_SW_REQ) ? &ctx->local_info.sw_ver : &ctx->local_info.hw_ver;
            rsp[0] = 0x00;
            rsp[1] = ver->major;
            rsp[2] = ver->minor;
            rsp[3] = ver->revision;
            rsp[4] = ver->build;
            rsp[5] = (uint8_t)((ver->ymd >> 24) & 0xFF);
            rsp[6] = (uint8_t)((ver->ymd >> 16) & 0xFF);
            rsp[7] = (uint8_t)((ver->ymd >> 8) & 0xFF);
            rsp[8] = (uint8_t)(ver->ymd & 0xFF);

            send_raw_frame(ctx, src_node, 
                           (type == TYPE_SW_REQ) ? TYPE_SW_RSP : TYPE_HW_RSP, 
                           rsp, sizeof(rsp));
            break;
        }

        case TYPE_SN_REQ: {
            if (len != 6) break;
            uint8_t rsp[9];
            rsp[0] = 0x00;

            memcpy(&rsp[1], ctx->local_info.sn, 8);
            send_raw_frame(ctx, src_node, TYPE_SN_RSP, rsp, sizeof(rsp));
            break;
        }

        case TYPE_TIME_REQ: {
            if (len != 6) break;
            uint8_t rsp[17];
            rsp[0] = 0x00;

            uint64_t cur_sec = get_uptime_sec(&ctx->start_ts);
            uint64_t total = ctx->local_info.total_half_hours;
            /* Convert current session seconds to half-hours (1 half-hour = 1800 seconds) */
            uint64_t total_half_hours = total + (cur_sec / 1800);

            for (size_t i = 0; i < 8; ++i) {
                // rsp[1 + i] = (uint8_t)((total_half_hours >> (56 - i * 8)) & 0xFF);
                // rsp[9 + i] = (uint8_t)((cur_sec >> (56 - i * 8)) & 0xFF);

                rsp[1 + i] = (uint8_t)((total_half_hours >> (i * 8)) & 0xFF);
                rsp[9 + i] = (uint8_t)((cur_sec >> (i * 8)) & 0xFF);
            }
            send_raw_frame(ctx, src_node, TYPE_TIME_RSP, rsp, sizeof(rsp));
            break;
        }

        case TYPE_RACK_REQ: {
            if (len != 6) break;
            if (ctx->role == NODE_IPMC) {
                uint8_t rsp[3];
                // pthread_mutex_lock(&ctx->lock);
                rsp[0] = ctx->local_info.rack_id;
                rsp[1] = ctx->local_info.slot_id;
                rsp[2] = 0x00; /* Status Code: OK */
                // pthread_mutex_unlock(&ctx->lock);

                send_raw_frame(ctx, src_node, TYPE_RACK_RSP, rsp, sizeof(rsp));
            }
            break;
        }

        case TYPE_UPGRADE_REQ: {
            if (len != 6) break;
            if (ctx->role == NODE_IPMC) {
                uint8_t rsp[1] = { 0x00 };
                send_raw_frame(ctx, src_node, TYPE_UPGRADE_RSP, rsp, sizeof(rsp));
            }
            break;
        }

        case TYPE_ALARM: {
            if (len != 7) break;
            if (ctx->role == NODE_CPU) {
                uint8_t alarm_code = frame[5];

                pthread_mutex_lock(&ctx->lock);
                ljb_alarm_handler_t cb = ctx->alarm_cb;
                void *ud = ctx->user_data;
                pthread_mutex_unlock(&ctx->lock);

                if (cb != NULL) {
                    cb(alarm_code, ud);
                }
            }
            break;
        }

        default:
            break;
    }
}

static void *rx_worker_thread(void *arg) {
    ljb_ctx_t *ctx = (ljb_ctx_t *)arg;
    uint8_t rx_byte;
    uint8_t frame_buf[LJB_MAX_RAW_FRAME];
    size_t frame_idx = 0;
    bool in_escape = false;

    while (ctx->is_running) {
        ssize_t read_bytes = read(ctx->uart_fd, &rx_byte, 1);
        if (read_bytes <= 0) {
            if (read_bytes < 0 && (errno == EINTR || errno == EAGAIN)) {
                usleep(1000);
                continue;
            }
            usleep(2000);
            continue;
        }

        if (rx_byte == SLIP_END) {
            if (frame_idx > 0) {
                dispatch_received_frame(ctx, frame_buf, (uint8_t)frame_idx);
                frame_idx = 0;
            }
            in_escape = false;
        } else if (in_escape) {
            if (rx_byte == SLIP_ESC_END) {
                if (frame_idx < sizeof(frame_buf)) frame_buf[frame_idx++] = SLIP_END;
            } else if (rx_byte == SLIP_ESC_ESC) {
                if (frame_idx < sizeof(frame_buf)) frame_buf[frame_idx++] = SLIP_ESC;
            } else {
                frame_idx = 0; /* Invalid SLIP sequence -> Reset Frame Buffer */
            }
            in_escape = false;
        } else if (rx_byte == SLIP_ESC) {
            in_escape = true;
        } else {
            if (frame_idx < sizeof(frame_buf)) {
                frame_buf[frame_idx++] = rx_byte;
            } else {
                frame_idx = 0; /* Buffer Overflow Guard -> Drop frame */
            }
        }
    }
    return NULL;
}

static ljb_err_t ljb_sync_exec(ljb_ctx_t *ctx, uint8_t req_type, 
                                uint8_t expected_rsp_type, 
                                const uint8_t *payload, 
                                uint8_t payload_len) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec  += ctx->timeout_ms / 1000;
    ts.tv_nsec += (ctx->timeout_ms % 1000) * 1000000;
    if (ts.tv_nsec >= 1000000000) {
        ts.tv_sec  += 1;
        ts.tv_nsec -= 1000000000;
    }

    ctx->sync_store.is_ready = false;
    ctx->sync_store.expected_type = expected_rsp_type;

    if (send_raw_frame_unlocked(ctx, ctx->peer_node, req_type, payload, payload_len) != LJB_OK) {
        log_error("Failed to send raw frame (req_type=0x%02X, peer_node=0x%02X)", req_type, ctx->peer_node);
        return LJB_ERR_IO;
    }

    int rc = 0;
    while (!ctx->sync_store.is_ready) {
        rc = pthread_cond_timedwait(&ctx->cond, &ctx->lock, &ts);
        if (rc != 0) {
            log_error("Time sync response timeout: %s (rc=%d)", strerror(rc), rc);
            return LJB_ERR_TIMEOUT;
        }
    }
    return LJB_OK;
}

ljb_err_t ljb_init(ljb_ctx_t *ctx, const char *cfile, ljb_node_t role) {
    if (ctx == NULL) return LJB_ERR_INVALID_ARG;

    memset(ctx, 0, sizeof(*ctx));
    ctx->role      = role;
    ctx->peer_node = (role == NODE_CPU) ? NODE_IPMC : NODE_CPU;
    ctx->cfile     = cfile;

    ljb_load_config_file(ctx, role);

    log_info("Initializing UART device: %s (role=%d)", ctx->dev, role);

    ctx->uart_fd = open(ctx->dev, O_RDWR | O_NOCTTY | O_NDELAY);
    if (ctx->uart_fd < 0) {
        log_error("Failed to open UART device %s: %s (fd=%d)", 
                  ctx->dev, strerror(errno), ctx->uart_fd);
        return LJB_ERR_UART_OPEN;
    }

    if (configure_uart_termios(ctx->uart_fd, 115200) != 0) {
        log_error("Failed to configure termios for UART device %s (baudrate=115200)", ctx->dev);
        close(ctx->uart_fd);
        return LJB_ERR_UART_CFG;
    }

    pthread_mutex_init(&ctx->lock, NULL);
    pthread_cond_init(&ctx->cond, NULL);

    if (clock_gettime(CLOCK_MONOTONIC, &ctx->start_ts) != 0) {
        log_error("Failed to get monotonic clock start timestamp: %s", strerror(errno));
        return LJB_ERR_UART_CFG;
    }

    ctx->timeout_ms = LJB_TIMEOUT;
    ctx->is_running = true;
    if (pthread_create(&ctx->rx_thread, NULL, rx_worker_thread, ctx) != 0) {
        log_error("Failed to create RX worker thread: %s", strerror(errno));
        ctx->is_running = false;
        pthread_mutex_destroy(&ctx->lock);
        pthread_cond_destroy(&ctx->cond);
        close(ctx->uart_fd);
        return LJB_ERR_THREAD;
    }

    log_info("Initialization successful for UART device %s", ctx->dev);
    return LJB_OK;
}

void ljb_deinit(ljb_ctx_t *ctx) {
    if (ctx == NULL || !ctx->is_running) return;

    ctx->is_running = false;
    pthread_join(ctx->rx_thread, NULL);

    if (ctx->role == NODE_CPU) {
        if (ljb_save_uptime(ctx)) {
            log_info("Total uptime saved to configuration file successfully");
        } else {
            log_error("Failed to save total uptime to configuration file");
        }
    }
    
    pthread_mutex_destroy(&ctx->lock);
    pthread_cond_destroy(&ctx->cond);

    if (ctx->dev) free(ctx->dev);
    if (ctx->uart_fd >= 0) {
        close(ctx->uart_fd);
        ctx->uart_fd = -1;
    }
    log_info("Deinitialization completed successfully");
}

ljb_err_t ljb_set_device_info(ljb_ctx_t *ctx, const ljb_dev_info_t *info) {
    if (ctx == NULL || info == NULL) return LJB_ERR_INVALID_ARG;
    pthread_mutex_lock(&ctx->lock);
    memcpy(&ctx->local_info, info, sizeof(ljb_dev_info_t));
    pthread_mutex_unlock(&ctx->lock);
    return LJB_OK;
}

ljb_err_t ljb_register_alarm_handler(ljb_ctx_t *ctx, ljb_alarm_handler_t handler, void *user_data) {
    if (ctx == NULL) return LJB_ERR_INVALID_ARG;

    pthread_mutex_lock(&ctx->lock);
    ctx->alarm_cb  = handler;
    ctx->user_data = user_data;
    pthread_mutex_unlock(&ctx->lock);

    return LJB_OK;
}

ljb_err_t ljb_cpu_get_rack_info_sync(ljb_ctx_t *ctx, ljb_rack_t *out_rack) {
    if (ctx == NULL || out_rack == NULL) return LJB_ERR_INVALID_ARG;
    if (ctx->role != NODE_CPU) return LJB_ERR_ROLE;

    pthread_mutex_lock(&ctx->lock);
    ljb_err_t err = ljb_sync_exec(ctx, TYPE_RACK_REQ, TYPE_RACK_RSP, NULL, 0);
    if (err == LJB_OK) {
        memcpy(out_rack, &ctx->sync_store.rack_info, sizeof(ljb_rack_t));
    }
    pthread_mutex_unlock(&ctx->lock);

    return err;
}

ljb_err_t ljb_cpu_request_upgrade_sync(ljb_ctx_t *ctx, uint8_t *out_result) {
    if (ctx == NULL) return LJB_ERR_INVALID_ARG;
    if (ctx->role != NODE_CPU) return LJB_ERR_ROLE;

    pthread_mutex_lock(&ctx->lock);
    ljb_err_t err = ljb_sync_exec(ctx, TYPE_UPGRADE_REQ, TYPE_UPGRADE_RSP, NULL, 0);
    if (err == LJB_OK && out_result != NULL) {
        *out_result = ctx->sync_store.result_code;
    }
    pthread_mutex_unlock(&ctx->lock);

    return err;
}

ljb_err_t ljb_ipmc_send_heartbeat_sync(ljb_ctx_t *ctx) {
    if (ctx == NULL) return LJB_ERR_INVALID_ARG;
    if (ctx->role != NODE_IPMC) return LJB_ERR_ROLE;

    pthread_mutex_lock(&ctx->lock);
    ljb_err_t err = ljb_sync_exec(ctx, TYPE_HB_REQ, TYPE_HB_RSP, NULL, 0);
    pthread_mutex_unlock(&ctx->lock);

    return err;
}

ljb_err_t ljb_ipmc_get_sw_version_sync(ljb_ctx_t *ctx, ljb_version_t *out_ver) {
    if (ctx == NULL || out_ver == NULL) return LJB_ERR_INVALID_ARG;
    if (ctx->role != NODE_IPMC) return LJB_ERR_ROLE;

    pthread_mutex_lock(&ctx->lock);
    ljb_err_t err = ljb_sync_exec(ctx, TYPE_SW_REQ, TYPE_SW_RSP, NULL, 0);
    if (err == LJB_OK) {
        memcpy(out_ver, &ctx->sync_store.sw_ver, sizeof(ljb_version_t));
    }
    pthread_mutex_unlock(&ctx->lock);

    return err;
}

ljb_err_t ljb_ipmc_get_hw_version_sync(ljb_ctx_t *ctx, ljb_version_t *out_ver) {
    if (ctx == NULL || out_ver == NULL) return LJB_ERR_INVALID_ARG;
    if (ctx->role != NODE_IPMC) return LJB_ERR_ROLE;

    pthread_mutex_lock(&ctx->lock);
    ljb_err_t err = ljb_sync_exec(ctx, TYPE_HW_REQ, TYPE_HW_RSP, NULL, 0);
    if (err == LJB_OK) {
        memcpy(out_ver, &ctx->sync_store.hw_ver, sizeof(ljb_version_t));
    }
    pthread_mutex_unlock(&ctx->lock);

    return err;
}

ljb_err_t ljb_ipmc_get_sn_sync(ljb_ctx_t *ctx, uint8_t outsn[8]) {
    if (ctx == NULL || outsn == NULL) return LJB_ERR_INVALID_ARG;
    if (ctx->role != NODE_IPMC) return LJB_ERR_ROLE;

    pthread_mutex_lock(&ctx->lock);
    ljb_err_t err = ljb_sync_exec(ctx, TYPE_SN_REQ, TYPE_SN_RSP, NULL, 0);
    if (err == LJB_OK) {
        memcpy(outsn, ctx->sync_store.sn, sizeof(ctx->sync_store.sn));
    }
    pthread_mutex_unlock(&ctx->lock);

    return err;
}

ljb_err_t ljb_ipmc_get_time_sync(ljb_ctx_t *ctx, uint8_t total[8], uint8_t uptime[8]) {
    if (ctx == NULL || total == NULL || uptime == NULL)
        return LJB_ERR_INVALID_ARG;
    if (ctx->role != NODE_IPMC)
        return LJB_ERR_ROLE;

    pthread_mutex_lock(&ctx->lock);
    ljb_err_t err = ljb_sync_exec(ctx, TYPE_TIME_REQ, TYPE_TIME_RSP, NULL, 0);
    if (err == LJB_OK) {
        memcpy(total, ctx->sync_store.total, sizeof(ctx->sync_store.total));
        memcpy(uptime, ctx->sync_store.uptime, sizeof(ctx->sync_store.uptime));
    }
    pthread_mutex_unlock(&ctx->lock);

    return err;
}

ljb_err_t ljb_ipmc_trigger_alarm(ljb_ctx_t *ctx, uint8_t alarm_code) {
    if (ctx == NULL) return LJB_ERR_INVALID_ARG;
    if (ctx->role != NODE_IPMC) return LJB_ERR_ROLE;

    return send_raw_frame(ctx, NODE_CPU, TYPE_ALARM, &alarm_code, 1);
}

static void ljb_load_config_file(ljb_ctx_t *ctx, ljb_node_t role) {
    FILE *fp;
    char *err = NULL;
    char tmp[256] = {0};
    char buf[1024];

    fp = fopen(ctx->cfile, "r");
    if (fp == NULL) {
        log_error("Error opening config file: %s\n", ctx->cfile);
        exit(1);
    }

    while (fgets(buf, sizeof(buf), fp) != NULL) {
        char *p = buf;
        /* Remove whitespace characters at the beginning of the line */
        while (isspace(*p))
            p++;
        /* Skip lines starting with # or empty */
        if (*p == '#' || *p == '\0')
            continue;
        
        /* Remove newlines at the end of lines */
        p[strcspn(p, "\r\n")] = '\0';

        char *first = p;
        char *second = NULL;

        while (*p && !isspace(*p))
            p++;
        if (*p) {
            *p = '\0';
            second = p + 1;
        }

        while (second && isspace(*second))
            second++;

        if (!first || !second || *second == '\0') {
            log_error("Error: Invalid config line or missing parameter.\n");
            continue;
        }

        if (!strcasecmp(first, "cpudev") && role == NODE_CPU) {
            ctx->dev = zstrdup(second);
        } else if (!strcasecmp(first, "ipmcdev") && role == NODE_IPMC) {
            ctx->dev = zstrdup(second);
        } else if (!strcasecmp(first, "rackid")) {
            ctx->local_info.rack_id = (uint8_t)strtoul(second, NULL, 0);
        } else if (!strcasecmp(first, "slotid")) {
            ctx->local_info.slot_id = (uint8_t)strtoul(second, NULL, 0);
        } else if (!strcasecmp(first, "devicesn")) {
            if (!hex2bin(second, ctx->local_info.sn, sizeof(ctx->local_info.sn))) {
                snprintf(tmp, sizeof(tmp), "Invalid SN: %s", second);
                err = tmp;
                goto loaderr;
            }
        } else if (!strcasecmp(first, "sw_major")) {
            ctx->local_info.sw_ver.major = (uint8_t)atoi(second);
        } else if (!strcasecmp(first, "sw_minor")) {
            ctx->local_info.sw_ver.minor = (uint8_t)atoi(second);
        } else if (!strcasecmp(first, "sw_revision")) {
            ctx->local_info.sw_ver.revision = (uint8_t)atoi(second);
        } else if (!strcasecmp(first, "sw_build")) {
            ctx->local_info.sw_ver.build = (uint8_t)atoi(second);
        } else if (!strcasecmp(first, "sw_ymd")) {
            ctx->local_info.sw_ver.ymd = (uint32_t)strtoul(second, NULL, 10);
        } else if (!strcasecmp(first, "hw_major")) {
            ctx->local_info.hw_ver.major = (uint8_t)atoi(second);
        } else if (!strcasecmp(first, "hw_minor")) {
            ctx->local_info.hw_ver.minor = (uint8_t)atoi(second);
        } else if (!strcasecmp(first, "hw_revision")) {
            ctx->local_info.hw_ver.revision = (uint8_t)atoi(second);
        } else if (!strcasecmp(first, "hw_build")) {
            ctx->local_info.hw_ver.build = (uint8_t)atoi(second);
        } else if (!strcasecmp(first, "hw_ymd")) {
            ctx->local_info.hw_ver.ymd = (uint32_t)strtoul(second, NULL, 10);
        } else if (!strcasecmp(first, "total_uptime")) {
            ctx->local_info.total_half_hours = (uint64_t)strtoul(second, NULL, 10);
        }
    }
    fclose(fp);
    return;

loaderr:
    log_error("Config Error: %s\n", err);
    exit(1);
}

/**
 * @brief Saves accumulated uptime to the config file on thread/process exit.
 * 
 * Safely updates only 'total_uptime' while preserving comments and other fields.
 * Uses atomic file replacement to prevent corruptions during sudden power loss.
 *
 * @param[in,out] ctx         Pointer to application context.
 * @param[in]     cfg_path    Path to the configuration file.
 * @return true   Update succeeded.
 * @return false  Invalid parameters or I/O failure.
 */
static bool ljb_save_uptime(ljb_ctx_t *ctx) {
    if (!ctx || !ctx->cfile) return false;

    /* 1. Calculate session increment in half-hours (1800 seconds) */
    uint64_t session_sec = get_uptime_sec(&ctx->start_ts);
    uint64_t add_half_hours = session_sec / 1800;

    /* 2. Thread-safe update of memory baseline */
    pthread_mutex_lock(&ctx->lock);
    ctx->local_info.total_half_hours += add_half_hours;
    uint64_t new_total = ctx->local_info.total_half_hours;
    pthread_mutex_unlock(&ctx->lock);

    /* 3. Open original config file */
    FILE *src = fopen(ctx->cfile, "r");
    if (!src) {
        log_error("Failed to open config file for reading: %s", ctx->cfile);
        return false;
    }

    /* 4. Prepare temporary file path for atomic write */
    char tmp_path[512];
    if (snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", ctx->cfile) >= (int)sizeof(tmp_path)) {
        log_error("Temporary file path too long for config file: %s", ctx->cfile);
        fclose(src);
        return false;
    }

    FILE *dst = fopen(tmp_path, "w");
    if (!dst) {
        log_error("Failed to open temporary config file for writing: %s", tmp_path);
        fclose(src);
        return false;
    }

    char line[512];
    bool key_found = false;

    /* 5. Stream processing: preserve comments, whitespace, and other key-value pairs */
    while (fgets(line, sizeof(line), src)) {
        char key[64] = {0};

        /* Parse first non-space token for lines that are not comments */
        if (line[0] != '#' && sscanf(line, "%63s", key) == 1) {
            if (strcmp(key, "total_uptime") == 0) {
                /* Replace only total_uptime line with formatted output */
                fprintf(dst, "total_uptime    %" PRIu64 "\n", new_total);
                key_found = true;
                continue;
            }
        }
        /* Copy unchanged line */
        fputs(line, dst);
    }

    /* Append key if missing from original config */
    if (!key_found) {
        fprintf(dst, "total_uptime    %" PRIu64 "\n", new_total);
    }

    /* 6. Flush buffers to disk before replacement */
    fflush(dst);
    fclose(src);
    fclose(dst);

    /* 7. Atomic rename: guarantees file integrity even on power failures */
    if (rename(tmp_path, ctx->cfile) != 0) {
        log_error("Failed to rename temporary config file to original: %s -> %s, error: %s", 
                  tmp_path, ctx->cfile, strerror(errno));
        unlink(tmp_path);
        return false;
    }

    return true;
}