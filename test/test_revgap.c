#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

#define BIND_PORT 9999
#define REASM_BUF_SIZE (64 * 1024)

/* 按照你打印出的真实偏移量进行硬编码 */
#define OFF_INNER_DATA_LEN 46
#define OFF_NUM            48
#define OFF_TOTAL          49
#define OFF_RCPID          51
#define OFF_METHOD         52
#define OFF_URL            58
#define OFF_JSON_PAYLOAD   186

// volatile sig_atomic_t server_running = 1;
// struct server {
//     int dummy;
// } redserver;
/* 计算分片步长： 
 * 发送端使用的 GAP_MAX_FRAGMENT (假设1300) 减去 内部头的长度。
 * 内部头长度 = OFF_JSON_PAYLOAD - OFF_INNER_DATA_LEN = 186 - 46 = 140 字节
 * 所以步长 = 1300 - 140 = 1160 字节
 */
#define INNER_HDR_SIZE     (OFF_JSON_PAYLOAD - OFF_INNER_DATA_LEN)
#define MAX_JSON_PER_FRAG  (1300 - INNER_HDR_SIZE) 

typedef struct {
    uint8_t *data;
    int received_count;
    uint16_t expected_total;
    uint8_t current_rcpId;
} ReassemblySession;

void handle_packet(uint8_t *pkt, ssize_t size, ReassemblySession *sess) {
    if (size < OFF_JSON_PAYLOAD) return;

    /* 1. 严格按照字节偏移解析 */
    uint16_t data_len;
    memcpy(&data_len, pkt + OFF_INNER_DATA_LEN, 2);
    data_len = ntohs(data_len);

    uint8_t  num = *(pkt + OFF_NUM);

    uint16_t total;
    memcpy(&total, pkt + OFF_TOTAL, 2);
    total = ntohs(total);

    uint8_t  rcp_id = *(pkt + OFF_RCPID);
    
    char method[7] = {0};
    memcpy(method, pkt + OFF_METHOD, 6);

    /* 打印调试信息 */
    printf("[Recv] RCPID: 0x%02X, Method: %s, Frag: %d/%d, Len: %u\n", 
           rcp_id, method, num, total, data_len);

    /* 2. 重组逻辑 */
    if (sess->received_count == 0) {
        sess->expected_total = total;
        sess->current_rcpId = rcp_id;
        memset(sess->data, 0, REASM_BUF_SIZE);
    }

    /* 确保是同一组消息 */
    if (rcp_id != sess->current_rcpId) return;

    /* 计算写入位置 */
    size_t write_pos = (num - 1) * MAX_JSON_PER_FRAG;
    
    if (write_pos + data_len <= REASM_BUF_SIZE) {
        memcpy(sess->data + write_pos, pkt + OFF_JSON_PAYLOAD, data_len);
        sess->received_count++;
    }

    /* 3. 完成输出 */
    if (sess->received_count == sess->expected_total) {
        printf("\n>>> JSON REASSEMBLED SUCCESS (%d fragments) <<<\n", sess->received_count);
        printf("%s\n", (char *)sess->data);
        printf("----------------------------------------------\n\n");
        sess->received_count = 0; 
    }
}

int main() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(BIND_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    ReassemblySession sess;
    sess.data = malloc(REASM_BUF_SIZE);
    sess.received_count = 0;

    printf("Standalone Receiver started. Using verified offsets.\n");
    printf("Expected Data Start: Byte %d\n", OFF_JSON_PAYLOAD);

    uint8_t buf[2048];
    while (1) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n > 0) handle_packet(buf, n, &sess);
    }
    return 0;
}