import socket
import struct
import argparse
import time
import sys

# --- 协议定义 (严格匹配你的 C 结构体: Sym, Ver, Cls, Type, Empty, MsgNo) ---
HEADER_FORMAT = "!2s B B B B H"
H_LEN = struct.calcsize(HEADER_FORMAT)

# 业务类型常量
GC_SYMBOL = b'5G'
GC_VERSION = 1
GC_FIND, GC_REGISTER, GC_HEARTBEAT = 0x01, 0x02, 0x03
GC_SUB_REQ, GC_SUB_RESP = 0x01, 0x02

def start_test(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(2.5)

    # 1. 发起探测 (FIND_REQ)
    msgno = 1001
    # 按照你的 C 结构体顺序打包
    header = struct.pack(HEADER_FORMAT, GC_SYMBOL, GC_VERSION, GC_FIND, GC_SUB_REQ, 0, msgno)
    body = struct.pack("!H", port)
    
    print(f"[*] Probing 5GC Server on port: {port}")
    sock.sendto(header + body, ('255.255.255.255', port))

    try:
        # 2. 接收 FIND 响应
        data, addr = sock.recvfrom(1024)
        
        # --- 精准解析 Body ---
        # 针对你提到的 0.192.168.211 错误：说明 IP 前面有冗余。
        # 既然 IP 永远是最后 4 字节，我们直接从末尾截取
        ip_bin = data[-4:] 
        # MAC 紧跟在 Header 后面（前 6 字节）
        mac_bin = data[H_LEN : H_LEN+6]
        
        ip_str = socket.inet_ntoa(ip_bin)
        mac_str = mac_bin.hex(':').upper()

        print("-" * 45)
        print(f"[SUCCESS] Server Found at {addr[0]}")
        print(f"  MAC Address : {mac_str}")
        print(f"  IPv4 Address: {ip_str}")
        print("-" * 45)

        # 3. 发送注册 (REGISTER_REQ)
        time.sleep(0.5)
        msgno += 1
        reg_header = struct.pack(HEADER_FORMAT, GC_SYMBOL, GC_VERSION, GC_REGISTER, GC_SUB_REQ, 0, msgno)
        print(f"[*] Sending Register Request (MsgNo: {msgno})...")
        sock.sendto(reg_header, addr)
        
        reg_resp, _ = sock.recvfrom(1024)
        print("[SUCCESS] Registration Confirmed by Server.")

        # 4. 进入心跳循环 (HEARTBEAT)
        print("\n[*] Starting Heartbeat Loop (Press Ctrl+C to stop)")
        while True:
            time.sleep(3)
            msgno += 1
            hb_header = struct.pack(HEADER_FORMAT, GC_SYMBOL, GC_VERSION, GC_HEARTBEAT, GC_SUB_REQ, 0, msgno)
            sock.sendto(hb_header, addr)
            
            try:
                sock.recvfrom(1024)
                print(f"  > Heartbeat ACK received (MsgNo: {msgno})", end='\r')
            except socket.timeout:
                print(f"\n[!] Heartbeat Timeout! Server may have kicked us.")
                break

    except socket.timeout:
        print("\n[ERROR] No response from server. Check port or C dispatcher logic.")
    except KeyboardInterrupt:
        print("\n[!] Test stopped by user.")
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    # 保留你的传参功能
    parser = argparse.ArgumentParser(description="5GC Protocol Active Client")
    parser.add_argument("-p", "--port", type=int, required=True, help="Target UDP port of the C server")
    
    # 自动处理不带参数直接运行的情况
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
        
    args = parser.parse_args()
    start_test(args.port)