import socket
import struct
import time
import psutil
import sys
import argparse

# --- Constant Definitions ---
SYMBOL = b'5G'

# Protocol Types
GC_FIND      = 0x01
GC_REGISTER  = 0x02
GC_HEARBEAT  = 0x03

# Sub Types
GC_REQ       = 0x01
GC_RESP      = 0x02

# --- Format Strings ---
H_FMT = "!2sBBBBH"
FIND_RESP_FMT = H_FMT + "6sB4s"
REG_RESP_FMT = H_FMT + "B"
HB_RESP_FMT = H_FMT + "4s"

def get_interface_info(interface_name=None):
    """获取指定网卡的IP和MAC地址"""
    interfaces = psutil.net_if_addrs()
    
    # 如果指定了网卡名称
    if interface_name:
        if interface_name not in interfaces:
            print(f"[!] 警告: 网卡 '{interface_name}' 不存在")
            print(f"[!] 可用网卡: {', '.join(interfaces.keys())}")
            return None, None
        
        snics = interfaces[interface_name]
        ip, mac = None, None
        
        for snic in snics:
            if snic.family == socket.AF_INET: 
                ip = snic.address
            elif snic.family == psutil.AF_LINK:
                # 兼容 Windows (-) 和 Linux (:) 的 MAC 格式
                mac_str = snic.address.replace('-', ':')
                mac = bytes([int(x, 16) for x in mac_str.split(':')])
        
        if ip and mac:
            return ip, mac
        else:
            print(f"[!] 警告: 网卡 '{interface_name}' 没有有效的IPv4地址或MAC地址")
            return None, None
    
    # 如果没有指定网卡，使用原来的逻辑获取第一个非回环网卡
    for interface, snics in interfaces.items():
        if interface == 'lo' or 'loopback' in interface.lower(): 
            continue
        ip, mac = None, None
        for snic in snics:
            if snic.family == socket.AF_INET: 
                ip = snic.address
            elif snic.family == psutil.AF_LINK:
                # 兼容 Windows (-) 和 Linux (:) 的 MAC 格式
                mac_str = snic.address.replace('-', ':')
                mac = bytes([int(x, 16) for x in mac_str.split(':')])
        if ip and mac: 
            return ip, mac
    
    print("[!] 警告: 没有找到有效的非回环网卡")
    return "127.0.0.1", b'\x00'*6

def start_server(port, interface=None):
    # 获取指定网卡的信息，用于响应报文
    server_ip, server_mac = get_interface_info(interface)
    
    if server_ip is None or server_mac is None:
        print(f"[!] 错误: 无法获取网卡 '{interface}' 的信息")
        sys.exit(1)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 允许端口重用，方便快速重启脚本
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # 保持绑定到所有接口，以便接收来自任何网络接口的请求
        sock.bind(('0.0.0.0', port))
    except Exception as e:
        print(f"[!] Error: Could not bind to port {port}: {e}")
        sys.exit(1)
    
    print(f"[*] 5GC Industrial Mock Server started on port {port}")
    if interface:
        print(f"[*] 使用网卡 '{interface}' 的IP和MAC进行响应")
    print(f"[*] Server Info: IP={server_ip}, MAC={server_mac.hex(':').upper()}")
    print("-" * 60)

    while True:
        try:
            data, addr = sock.recvfrom(2048)
            if len(data) < 8: continue

            # Unpack header
            symbol, ver, cls, subtype, empty, msgno = struct.unpack(H_FMT, data[:8])
            if symbol != SYMBOL: continue

            # --- 1. DISCOVERY (GC_FIND) ---
            if cls == GC_FIND and subtype == GC_REQ:
                print(f"[{time.strftime('%H:%M:%S')}] RECV FIND from {addr} (MsgNo: {msgno})")
                resp = struct.pack(FIND_RESP_FMT, SYMBOL, 1, GC_FIND, GC_RESP, 0, msgno,
                                   server_mac, 0, socket.inet_aton(server_ip))
                sock.sendto(resp, addr)
                print(f"    SENT FIND_RESP (Size: {len(resp)} bytes)")

            # --- 2. REGISTER (GC_REGISTER) ---
            elif cls == GC_REGISTER and subtype == GC_REQ:
                print(f"[{time.strftime('%H:%M:%S')}] RECV REGISTER from {addr} (MsgNo: {msgno})")
                resp = struct.pack(REG_RESP_FMT, SYMBOL, 1, GC_REGISTER, GC_RESP, 0, msgno, 0)
                sock.sendto(resp, addr)
                print(f"    SENT REG_RESP (Size: {len(resp)} bytes, Result: 0)")

            # --- 3. HEARTBEAT (GC_HEARBEAT) ---
            elif cls == GC_HEARBEAT and subtype == GC_REQ:
                client_tm = data[8:12]
                resp = struct.pack(HB_RESP_FMT, SYMBOL, 1, GC_HEARBEAT, GC_RESP, 0, msgno, client_tm)
                sock.sendto(resp, addr)
                print(f"[{time.strftime('%H:%M:%S')}] RECV HEARTBEAT (MsgNo: {msgno}) -> SENT ACK")

        except Exception as e:
            print(f"[!] Runtime Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="5GC Mock Server")
    parser.add_argument("-p", "--port", type=int, default=50001, help="UDP port to listen on (default: 50001)")
    parser.add_argument("-i", "--interface", type=str, help="Network interface name to use (e.g., eth0, en0, wlan0)")
    parser.add_argument("-l", "--list", action="store_true", help="List available network interfaces and exit")
    
    args = parser.parse_args()

    # 列出可用网卡
    if args.list:
        print("Available network interfaces:")
        for iface, addrs in psutil.net_if_addrs().items():
            ip_addr = None
            mac_addr = None
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ip_addr = addr.address
                elif addr.family == psutil.AF_LINK:
                    mac_addr = addr.address
            if ip_addr or mac_addr:
                print(f"  {iface}: IP={ip_addr or 'N/A'}, MAC={mac_addr or 'N/A'}")
        sys.exit(0)

    try:
        start_server(args.port, args.interface)
    except KeyboardInterrupt:
        print("\n[*] Server Stopped by user.")
