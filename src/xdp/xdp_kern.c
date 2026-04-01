#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <stdbool.h>

#define MAX_PACKET_DATA 2048
#define TARGET_UDP_DST_PORT 52719

struct packet_event {
    __u32 pkt_len;
    __u8  data[MAX_PACKET_DATA];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); 
} pkt_ringbuf SEC(".maps");

SEC("xdp")
int xdp_packet_capture(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return XDP_PASS;

    // 1. 提取分片信息
    __u16 frag_off = bpf_ntohs(ip->frag_off);
    bool is_fragment = (frag_off & 0x3FFF) != 0; // MF位或Offset不为0

    // 2. 如果不是 UDP 且也不是分片，直接放行
    if (ip->protocol != IPPROTO_UDP && !is_fragment) {
        return XDP_PASS;
    }

    // 3. 端口检查逻辑（仅针对非分片包，或者分片的首片）
    if (!is_fragment || (is_fragment && (frag_off & 0x1FFF) == 0)) {
        __u32 ip_hdr_len = ip->ihl * 4;
        if ((void *)ip + ip_hdr_len + sizeof(struct udphdr) > data_end) {
            // 如果是首片但长度不够看 UDP 头，可能包坏了，如果是普通包则放行
            if (!is_fragment) return XDP_PASS;
        } else {
            struct udphdr *udp = (void *)ip + ip_hdr_len;
            // 如果端口不匹配，且不是分片，才放行
            if (bpf_ntohs(udp->dest) != TARGET_UDP_DST_PORT && !is_fragment) {
                return XDP_PASS;
            }
        }
    }

    // 4. 只要是分片包，或者匹配端口的 UDP 包，全部送往 RingBuffer
    __u32 pkt_len = (__u32)(data_end - data);
    struct packet_event *event = bpf_ringbuf_reserve(&pkt_ringbuf, sizeof(struct packet_event), 0);
    if (!event) return XDP_PASS;

    if (pkt_len > MAX_PACKET_DATA) pkt_len = MAX_PACKET_DATA;
    event->pkt_len = pkt_len;
    
    // 使用简单的拷贝
    bpf_probe_read_kernel(event->data, MAX_PACKET_DATA, data);
    bpf_ringbuf_submit(event, 0);

    return XDP_DROP;
}
char _license[] SEC("license") = "GPL";