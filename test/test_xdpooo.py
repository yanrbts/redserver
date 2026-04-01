from scapy.all import *
import struct
import json
import random
import argparse
import time

# --- 协议常量 ---
GAP_METHOD_LEN = 6
GAP_URL_LEN    = 128

def get_gap_header(data_len, rcp_id):
    """构造 C 结构体头部"""
    header_fmt = f"!H B H B {GAP_METHOD_LEN}s {GAP_URL_LEN}s"
    return struct.pack(
        header_fmt,
        data_len, 1, 1, rcp_id,
        b"REORDER".ljust(GAP_METHOD_LEN, b'\x00'),
        b"/ooo_test".ljust(GAP_URL_LEN, b'\x00')
    )

def send_ooo_frags(target_ip, target_port, rcp_id, total_size, frag_size):
    # 1. 构造完整载荷 (Header + JSON)
    payload_data = json.dumps({
        "desc": "Out-of-order stress test",
        "data": "X" * (total_size - 100),
        "ts": time.time()
    }).encode('utf-8')
    
    gap_header = get_gap_header(len(payload_data), rcp_id)
    full_payload = gap_header + payload_data
    
    # 2. 构造原始大包 (IP ID 必须固定，以便服务端识别为同一 Session)
    ip_id = random.randint(1000, 60000)
    base_pkt = IP(dst=target_ip, id=ip_id)/UDP(sport=54321, dport=target_port)/Raw(load=full_payload)
    
    # 3. 使用 Scapy 的 fragment 函数进行切片
    print(f"[*] Original size: {len(full_payload)} bytes. Fragmenting into {frag_size} byte chunks...")
    frags = fragment(base_pkt, fragsize=frag_size)
    
    # 4. 关键步骤：随机打乱分片顺序
    random.shuffle(frags)
    
    print(f"[*] Sending {len(frags)} fragments in RANDOM order (IP ID: {ip_id})...")
    
    # 逐个发送被打乱的分片
    for i, f in enumerate(frags):
        # 打印当前发送分片的 Offset (单位: 8字节)
        print(f"  [->] Sending part {i+1}: Offset={f.frag * 8}, Flags={f.flags}")
        send(f, verbose=False)
        time.sleep(0.01) # 微小延迟确保顺序确实被打乱

    print("[+] All fragments sent. Check XDP statistics.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XDP Out-of-Order Fragment Tester")
    parser.add_argument("--ip", required=True, help="Target Server IP")
    parser.add_argument("--port", type=int, default=52719, help="Target UDP Port")
    parser.add_argument("--size", type=int, default=4000, help="Total JSON size")
    parser.add_argument("--frag", type=int, default=1000, help="Fragment size")
    parser.add_argument("--rcp", type=int, default=101)

    args = parser.parse_args()
    send_ooo_frags(args.ip, args.port, args.rcp, args.size, args.frag)