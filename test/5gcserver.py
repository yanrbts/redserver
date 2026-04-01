import socket
import struct
import time
import psutil
import sys
import zlib
import hmac
import hashlib
import argparse
from datetime import datetime, timezone
from typing import Tuple, Optional, Callable, Dict

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

DEFAULT_PORT = 52719
HDR_SIZE = 12
ETH_HDR_SIZE = 14
INNER_HDR_SIZE = 8
TYPE_DATA = 0x6789
ETH_TYPE_EXPECTED = 0x0857

class ProtocolError(Exception):
    """协议相关异常"""
    pass

def get_sys_info():
    """获取本机第一个非回环的 IPv4 地址和 MAC。"""
    for interface, snics in psutil.net_if_addrs().items():
        if interface == 'lo' or 'loopback' in interface.lower(): continue
        ip, mac = None, None
        for snic in snics:
            if snic.family == socket.AF_INET: ip = snic.address
            elif snic.family == psutil.AF_LINK:
                # 兼容 Windows (-) 和 Linux (:) 的 MAC 格式
                mac_str = snic.address.replace('-', ':')
                mac = bytes([int(x, 16) for x in mac_str.split(':')])
        if ip and mac: return ip, mac
    return "127.0.0.1", b'\x00'*6

def parse_header(hdr: bytes) -> Tuple[int, int, int, int]:
        """解析 HDR，返回 (type16, len16, auth32, crc32)"""
        if len(hdr) != HDR_SIZE:
            raise ValueError(f"HDR 长度错误: {len(hdr)}")
        return struct.unpack('>HHII', hdr)

def verify_full_crc(full_data: bytes, stored_crc: int) -> bool:
    """校验整个包的 CRC32（临时清零 CRC 字段）"""
    if len(full_data) < HDR_SIZE:
        return False

    # 拷贝数据，临时清零 CRC 字段 (字节 8-11)
    temp_data = bytearray(full_data)
    temp_data[8:12] = [0, 0, 0, 0]

    # 计算 CRC
    calc_crc = zlib.crc32(temp_data) & 0xFFFFFFFF
    return calc_crc == stored_crc

def build_header(type16: int, len16: int, auth32: int = 0) -> bytes:
    """构建 HDR，Len16 为整个包长度，CRC 占位 0"""
    temp = struct.pack('>HHII', type16, len16, auth32, 0)
    # 先不计算 CRC（留给调用者全包计算）
    return temp

def calc_auth(type16: int, len16: int, payload: bytes, shared_key: bytes) -> int:
    """计算 Auth32 值"""
    data = struct.pack('>HH', type16, len16) + payload
    mac = hmac.new(shared_key, data, hashlib.sha256).digest()
    return struct.unpack('>I', mac[:4])[0]

def build_outer_packet(inner_header: bytes, inner_payload: bytes, type16: int = TYPE_DATA, auth32: int = 0) -> bytes:
    """
    独立函数：根据内层头部 + 内层 payload，构建完整的外层包（含外层头部 + CRC32）
    - inner_header: 内层头部（8字节）
    - inner_payload: 内层真实业务数据
    返回：完整包（外层头部12字节 + 内层头部 + 内层payload）
    """
    # 内层完整内容
    full_inner = inner_header + inner_payload
    
    # 外层总长度 = 外层头部12 + 内层总长度
    len16 = HDR_SIZE + ETH_HDR_SIZE + len(full_inner)
    
    # 先组外层头部（CRC占位0）
    outer_header = struct.pack('>HHII', type16, len16, auth32, 0)

    # 以太网头部：前 12 字节 0，最后 2 字节 0x0857
    ether_header = bytes(12) + struct.pack('>H', 0x0857)
    
    # 全包临时（用于计算 CRC）
    full_packet_temp = outer_header + ether_header + full_inner
    
    # 计算 CRC（临时清零 CRC 字段）
    temp_packet = bytearray(full_packet_temp)
    temp_packet[8:12] = b'\x00\x00\x00\x00'
    crc = zlib.crc32(temp_packet) & 0xFFFFFFFF
    
    # 替换 CRC 字段
    final_packet = bytearray(full_packet_temp)
    final_packet[8:12] = struct.pack('>I', crc)
    
    return bytes(final_packet)

def start_server(port):
    server_ip, server_mac = get_sys_info()
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 允许端口重用，方便快速重启脚本
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('0.0.0.0', port))
    except Exception as e:
        print(f"[!] Error: Could not bind to port {port}: {e}")
        sys.exit(1)
    
    print(f"[*] 5GC Industrial Mock Server started on port {port}")
    print(f"[*] Server Info: IP={server_ip}, MAC={server_mac.hex(':').upper()}")
    print("-" * 60)

    while True:
        try:
            data, addr = sock.recvfrom(2048)
            if len(data) < HDR_SIZE:
                print(f"[!] Packet too short ({len(data)} bytes) from {addr}")
                continue

            type16, len16, auth32, crc32 = parse_header(data[:HDR_SIZE])
            if len(data) != len16:
                print(f"[!] Length mismatch: got {len(data)}, expected {len16} from {addr}")
                continue
            
            if not verify_full_crc(data, crc32):
                print(f"[!] CRC32 failed: calc {hex(crc32)} from {addr}")
                continue
            
            

            # 4. 提取以太网头部 (12~25)
            ether_header = data[HDR_SIZE:HDR_SIZE+ETH_HDR_SIZE]

            ether_type = struct.unpack('>H', ether_header[12:14])[0]
            if (ether_type != ETH_TYPE_EXPECTED):
                print(f"[!] EtherType mismatch: expected 0x0857, got 0x{ether_type:04X} from {addr}")
                continue

            # 5. 提取内层业务头部 (26~33)
            inner_header_start = HDR_SIZE + ETH_HDR_SIZE
            symbol, ver, cls, subtype, empty, msgno = struct.unpack(H_FMT, 
                                                                   data[inner_header_start:inner_header_start+INNER_HDR_SIZE])
            if symbol != SYMBOL: 
                print(f"[!] Symbol mismatch: expected {SYMBOL}, got {symbol} from {addr}")
                continue

            payload = data[inner_header_start:len16]
            # --- 1. DISCOVERY (GC_FIND) ---
            if cls == GC_FIND and subtype == GC_REQ:
                print(f"[{time.strftime('%H:%M:%S')}] RECV FIND from {addr} (MsgNo: {msgno})")
                # resp = struct.pack(FIND_RESP_FMT, SYMBOL, 1, GC_FIND, GC_RESP, 0, msgno,
                #                    server_mac, 0, socket.inet_aton(server_ip))
                # sock.sendto(resp, addr)
                # print(f"    SENT FIND_RESP (Size: {len(resp)} bytes)")

                inner_payload = server_mac + b'\x00' + socket.inet_aton(server_ip)
                inner_header = struct.pack(H_FMT, SYMBOL, 1, GC_FIND, GC_RESP, 0, msgno)
                full_packet = build_outer_packet(
                    inner_header=inner_header, 
                    inner_payload=inner_payload,
                    type16=TYPE_DATA,
                    auth32=auth32
                )
                # sock.sendto(full_packet, addr)
                sock.sendto(full_packet, (addr[0], DEFAULT_PORT))
                print(f"    SENT FIND_RESP (Size: {len(full_packet)} bytes)")

            # --- 2. REGISTER (GC_REGISTER) ---
            elif cls == GC_REGISTER and subtype == GC_REQ:
                print(f"[{time.strftime('%H:%M:%S')}] RECV REGISTER from {addr} (MsgNo: {msgno})")
                # resp = struct.pack(REG_RESP_FMT, SYMBOL, 1, GC_REGISTER, GC_RESP, 0, msgno, 0)
                # sock.sendto(resp, addr)
                # print(f"    SENT REG_RESP (Size: {len(resp)} bytes, Result: 0)")

                # 原有内层 payload
                inner_payload = b'\x00'  # result=0
                inner_header = struct.pack(H_FMT, SYMBOL, 1, GC_REGISTER, GC_RESP, 0, msgno)
                full_packet = build_outer_packet(
                    inner_header=inner_header, 
                    inner_payload=inner_payload,
                    type16=TYPE_DATA,
                    auth32=auth32
                )

                # sock.sendto(full_packet, addr)
                sock.sendto(full_packet, (addr[0], DEFAULT_PORT))
                print(f"    SENT REG_RESP (Size: {len(full_packet)} bytes, Result: 0)")

            # --- 3. HEARTBEAT (GC_HEARBEAT) ---
            elif cls == GC_HEARBEAT and subtype == GC_REQ:
                # client_tm = data[8:12]
                # resp = struct.pack(HB_RESP_FMT, SYMBOL, 1, GC_HEARBEAT, GC_RESP, 0, msgno, client_tm)
                # sock.sendto(resp, addr)
                # print(f"[{time.strftime('%H:%M:%S')}] RECV HEARTBEAT (MsgNo: {msgno}) -> SENT ACK")

                client_tm = payload[8:12]
                # 转成整数（大端无符号）
                timestamp = struct.unpack('>I', client_tm)[0]

                # 转成可读时间
                utc_time = datetime.fromtimestamp(timestamp).astimezone(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                print(f"[{time.strftime('%H:%M:%S')}] RECV HEARTBEAT ({utc_time}) (MsgNo: {msgno}) -> SENT ACK")

                inner_payload = client_tm
                inner_header = struct.pack(H_FMT, SYMBOL, 1, GC_HEARBEAT, GC_RESP, 0, msgno)
                full_packet = build_outer_packet(
                    inner_header=inner_header, 
                    inner_payload=inner_payload,
                    type16=TYPE_DATA,
                    auth32=auth32
                )

                # sock.sendto(full_packet, addr)
                sock.sendto(full_packet, (addr[0], DEFAULT_PORT))

        except Exception as e:
            print(f"[!] Runtime Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="5GC Mock Server")
    parser.add_argument("-p", "--port", type=int, default=50001, help="UDP port to listen on (default: 50001)")
    args = parser.parse_args()

    try:
        start_server(args.port)
    except KeyboardInterrupt:
        print("\n[*] Server Stopped by user.")