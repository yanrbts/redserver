from scapy.all import *
import struct
import argparse

# --- 协议定义 (与 C 代码对齐) ---
GAP_METHOD_LEN = 6
GAP_URL_LEN    = 128

def get_gap_header(data_len, rcp_id):
    header_fmt = f"!H B H B {GAP_METHOD_LEN}s {GAP_URL_LEN}s"
    return struct.pack(
        header_fmt,
        data_len, 1, 1, rcp_id,
        b"ATTACK".ljust(GAP_METHOD_LEN, b'\x00'),
        b"/overlap_test".ljust(GAP_URL_LEN, b'\x00')
    )

def send_overlap_attack(target_ip, target_port, rcp_id):
    print(f"[*] Sending Overlap Attack to {target_ip}:{target_port}...")
    
    # 唯一标识符，确保服务端认为是同一个 Session
    ip_id = 0x1337 
    
    # 1. 第一个分片 (Offset = 0, MF = 1)
    # 载荷包含：GAP Header (140字节) + 一些数据
    header = get_gap_header(200, rcp_id)
    payload1 = header + b"A" * 60  # 总共 200 字节
    
    p1 = IP(dst=target_ip, id=ip_id, frag=0, flags="MF") / \
         UDP(sport=12345, dport=target_port) / \
         Raw(load=payload1)

    # 2. 第二个分片 (畸形重叠分片)
    # 正常情况下，第二个分片的 Offset 应该是 (p1的长度 / 8)
    # 我们故意设置一个极小的 Offset，让它盖在 p1 的数据上
    payload2 = b"B" * 100
    
    # frag 单位是 8 字节。设置 frag=2 意味着从第 16 字节开始覆盖。
    # 这绝对会覆盖掉第一个包里的 GAP Header 内部数据！
    p2 = IP(dst=target_ip, id=ip_id, frag=2, flags=0) / \
         Raw(load=payload2)

    # 发送包
    send([p1, p2], verbose=True)
    print("[+] Attack packets sent. Check XDP logs for 'reasm_overlap_drops'.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XDP Overlap Attack Tester")
    parser.add_argument("--ip", required=True)
    parser.add_argument("--port", type=int, default=52719)
    parser.add_argument("--rcp", type=int, default=101)
    args = parser.parse_args()

    send_overlap_attack(args.ip, args.port, args.rcp)