#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import struct
import sys
from datetime import datetime

# ============================================================
# 适配嵌套结构体 lrm_health_payload_t
# 布局: Magic(I) + Rack(B) + Slot(B) + Status(H) + Uptime(I) 
#      + V_Maj(H) + V_Min(H) + Mem(I) + CPU(H) + Err(H)
# ============================================================
# > 表示大端 (网络字节序)
PAYLOAD_FORMAT = ">I BBH I HH I HH" 
PAYLOAD_SIZE = struct.calcsize(PAYLOAD_FORMAT)

def start_monitor():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        print(f"[*] Monitoring Red LRM Telemetry | Expected: {PAYLOAD_SIZE} bytes")
        print("-" * 75)
    except PermissionError:
        print("[!] Error: Must run as root (sudo).")
        sys.exit(1)

    while True:
        try:
            raw_data, addr = sock.recvfrom(2048)
            ip_header_len = (raw_data[0] & 0xF) * 4
            payload_start = ip_header_len + 8
            payload_raw = raw_data[payload_start:]

            if len(payload_raw) >= PAYLOAD_SIZE:
                # 解析字段
                (magic, rack, slot, status, uptime, 
                 v_major, v_minor, mem_kb, cpu_load, custom_err) = \
                 struct.unpack(PAYLOAD_FORMAT, payload_raw[:PAYLOAD_SIZE])
                
                # 验证 Magic 'HLTH'
                if magic == 0x484C5448:
                    status_str = "NORMAL" if status == 0x0000 else f"ERR(0x{status:04X})"
                    color = "\033[92m" if status == 0x0000 else "\033[91m"
                    reset = "\033[0m"

                    time_str = datetime.now().strftime('%H:%M:%S')
                    mem_mb = mem_kb / 1024.0
                    
                    # 严格按照你要求的原始打印格式
                    print(f"[{time_str}] FROM: {addr[0]}")
                    print(f"    ID     : Rack {rack:02d} / Slot {slot:02d} | Version: v{v_major}.{v_minor}")
                    print(f"    Health : {color}{status_str}{reset} | Uptime: {uptime}s")
                    # 这里 CPU 和 Memory 就能精准读到各自的 uint16 和 uint32 区域了
                    print(f"    System : CPU: {cpu_load}% | Memory: {mem_mb:.2f} MB ({mem_kb} KB)")
                    print(f"    Extra  : CustomError: 0x{custom_err:04X}")
                    print("-" * 75)

        except struct.error:
            continue

if __name__ == "__main__":
    try:
        start_monitor()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
        sys.exit(0)