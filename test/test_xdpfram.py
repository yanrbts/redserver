from scapy.all import *
import struct
import json
import time
import argparse

# --- 协议定义 (必须与 C 代码对齐) ---
GAP_METHOD_LEN = 6
GAP_URL_LEN    = 128

def build_gap_header(data_len, rcp_id):
    """构造 tunnel_inner_payload_t 头部"""
    header_fmt = f"!H B H B {GAP_METHOD_LEN}s {GAP_URL_LEN}s"
    return struct.pack(
        header_fmt,
        data_len,
        1,  # num (单包测试设为1)
        1,  # total
        rcp_id,
        b"POST".ljust(GAP_METHOD_LEN, b'\x00'),
        b"/test/xdp".ljust(GAP_URL_LEN, b'\x00')
    )

def stress_test(target_ip, target_port, rcp_id, total_size, frag_size, count, interval):
    print(f"[*] Starting Stress Test to {target_ip}:{target_port}")
    print(f"[*] Total Data Size: {total_size}, Fragment Size: {frag_size}")

    # 1. 生成大 JSON 数据
    payload_data = json.dumps({
        "test": "stress",
        "timestamp": time.time(),
        "content": "A" * (total_size - 50) # 填充到指定大小
    }).encode('utf-8')

    # 2. 组合业务头和数据
    gap_header = build_gap_header(len(payload_data), rcp_id)
    full_payload = gap_header + payload_data

    # 3. 构造基础 UDP 包
    # 注意：我们手动处理分片，所以这里先建立一个大的 UDP 对象
    base_pkt = IP(dst=target_ip)/UDP(sport=RandShort(), dport=target_port)/Raw(load=full_payload)

    # 4. 循环压测
    sent_pkts = 0
    try:
        while count == 0 or sent_pkts < count:
            # 使用 Scapy 的 fragment 功能进行 IP 层切割
            # 这会产生多个带有相同 IP ID 但不同 Offset 的包
            frags = fragment(base_pkt, fragsize=frag_size)
            
            # 发送这一组分片
            send(frags, verbose=False)
            
            sent_pkts += 1
            if sent_pkts % 10 == 0:
                print(f"[+] Sent {sent_pkts} full datagrams (each fragmented into {len(frags)} units)")
            
            if interval > 0:
                time.sleep(interval)
                
    except KeyboardInterrupt:
        print("\n[*] Stopped by user.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XDP Reassembly Stress Tester (Scapy)")
    parser.add_argument("--ip", required=True, help="Target Server IP")
    parser.add_argument("--port", type=int, default=52719, help="Target UDP Port")
    parser.add_argument("--size", type=int, default=4000, help="Total JSON size (will trigger fragmentation)")
    parser.add_argument("--frag", type=int, default=1200, help="IP fragment size (MTU approx)")
    parser.add_argument("--count", type=int, default=1, help="How many times to send (0 for infinite)")
    parser.add_argument("--interval", type=float, default=0.1, help="Interval between datagrams")
    parser.add_argument("--rcp", type=int, default=101, help="Report ID")

    args = parser.parse_args()
    stress_test(args.ip, args.port, args.rcp, args.size, args.frag, args.count, args.interval)