#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BlackSide LRM Monitoring Tool
Professional Implementation for Network Discovery and Telemetry.
"""

import argparse
import asyncio
import hashlib
import hmac
import json
import socket
import struct
import sys
import threading
import time
import zlib
from datetime import datetime
from typing import Tuple, Dict, Any, List

# External Dependencies Check
try:
    import psutil
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError:
    print("[!] Missing dependencies. Please run: pip install rich psutil")
    sys.exit(1)

# =============================================================================
# 1. Protocol Definitions & Constants
# =============================================================================

# Auth Constants
PING_MAGIC = b'PING'
HB_FMT = '>4sIQ'
TYPE_AUTH_REQ = 0x6000
TYPE_AUTH_RESP = 0x6001
AUTH_HDR_SIZE = 12
DEFAULT_AUTH_PORT = 48350

HDR_SIZE = 12       # Outer Custom Header Size
ETH_HDR_SIZE = 14   # Mock Ethernet Header Size
TYPE_DATA = 0x6789  # Protocol Data Type Identifier
SYMBOL = b"5G"      # Internal Protocol Magic Tag

# Discovery Command Types
GC_FIND = 0x01
GC_REGISTER = 0x02
GC_HEARBEAT = 0x03

# Message Directions
GC_REQ = 0x01
GC_RESP = 0x02

# Struct Format Strings
# H_FMT: Tag(2s), Ver(B), Cmd(B), Dir(B), Reserved(B), MsgNo(H)
H_FMT = "!2sBBBBH"

# Health Packet Format: 
# Magic(I), Rack(B), Slot(B), Status(H), Uptime(I), V_Maj(H), V_Min(H), Mem(I), CPU(H), Err(H)
HLTH_FMT = ">I BBH I HH I HH"
HLTH_SIZE = struct.calcsize(HLTH_FMT)
DEFAULT_PORT = 52719

# =============================================================================
# 2. Global State Management
# =============================================================================
class GlobalState:
    """Thread-safe state container for monitoring data."""
    def __init__(self, port: int, auth_port: int):
        self.lock = threading.Lock()
        self.port = port
        self.auth_port = auth_port
        self.biz_logs: List[str] = []
        self.auth_logs: List[str] = []  # New: Auth logs
        self.probe_stats: Dict[str, Dict[str, Any]] = {}
        self.health_data: Dict[Tuple[int, int], Dict[str, Any]] = {}
        self.total_count = 0
        self.running = True

    def log_biz(self, msg: str):
        """Append business logs with timestamp, maintaining a fixed buffer size."""
        with self.lock:
            ts = datetime.now().strftime('%H:%M:%S')
            self.biz_logs.append(f"[{ts}] {msg}")
            if len(self.biz_logs) > 28:
                self.biz_logs.pop(0)

    def log_auth(self, msg: str):
        with self.lock:
            ts = datetime.now().strftime('%H:%M:%S')
            self.auth_logs.append(f"[{ts}] {msg}")
            if len(self.auth_logs) > 25: self.auth_logs.pop(0)

    def update_probe(self, ip: str, p_type: str):
        """Update discovery probe statistics for a specific client IP."""
        with self.lock:
            if ip not in self.probe_stats:
                self.probe_stats[ip] = {"f": 0, "r": 0, "h": 0, "last": ""}
            self.probe_stats[ip][p_type] += 1
            self.probe_stats[ip]["last"] = datetime.now().strftime("%H:%M:%S")
            self.total_count += 1

    def update_health(self, key: Tuple[int, int], info: Dict[str, Any]):
        """Update hardware health metrics for a specific Rack/Slot."""
        with self.lock:
            self.health_data[key] = info


# =============================================================================
# 3. Auth Protocol Handler (Independent Thread)
# =============================================================================
class AuthServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, key: bytes, state: GlobalState):
        self.key = key
        self.state = state
        self.transport = None  # 初始化为 None

    def connection_made(self, transport):
        """修复点：必须实现此方法以获取 transport 实例"""
        self.transport = transport

    def verify_full_crc(self, full_data: bytes, stored_crc: int) -> bool:
        """严格保持业务原始逻辑：拷贝数据 -> 临时清零 CRC 字段 -> 计算 CRC"""
        temp_data = bytearray(full_data)
        if len(temp_data) >= 12:
            temp_data[8:12] = b'\x00\x00\x00\x00'
        calc_crc = zlib.crc32(temp_data) & 0xFFFFFFFF
        return calc_crc == stored_crc

    def datagram_received(self, data: bytes, addr: tuple):
        if not self.transport:
            return

        # 1. 处理 PING 心跳 (透传)
        if data.startswith(PING_MAGIC):
            self.transport.sendto(data, addr)
            return

        # 2. 处理 0x6000 认证请求
        if len(data) >= AUTH_HDR_SIZE:
            try:
                type16, len16, auth32, stored_crc = struct.unpack('>HHII', data[:AUTH_HDR_SIZE])
                
                # 校验数据长度合法性
                payload = data[:len16]
                
                # 严格执行 CRC 校验
                if not self.verify_full_crc(payload, stored_crc):
                    self.state.log_auth(f"CRC ERROR from {addr[0]} (Recv: 0x{stored_crc:08x})")
                    return

                if type16 == TYPE_AUTH_REQ:
                    # 认证核心逻辑 (HMAC-SHA256)
                    time_factor = int(time.time()) // 300
                    msg_to_sign = struct.pack('>HHQ', TYPE_AUTH_RESP, AUTH_HDR_SIZE, time_factor) + data[AUTH_HDR_SIZE:len16]
                    mac = hmac.new(self.key, msg_to_sign, hashlib.sha256).digest()
                    new_auth32 = struct.unpack('>I', mac[:4])[0]

                    # 构造响应包
                    resp = bytearray(struct.pack('>HHII', TYPE_AUTH_RESP, AUTH_HDR_SIZE, new_auth32, 0))
                    # 计算响应包的 CRC
                    final_crc = zlib.crc32(resp) & 0xFFFFFFFF
                    struct.pack_into('>I', resp, 8, final_crc)
                    
                    self.transport.sendto(resp, addr)
                    self.state.log_auth(f"AUTH OK: {addr[0]} | AUTH: 0x{new_auth32:08x}")
            except Exception as e:
                self.state.log_auth(f"AUTH EXCEPTION: {e}")


# =============================================================================
# 3. Network Protocol Handler (UDP Service)
# =============================================================================
class BlackServerProtocol(asyncio.DatagramProtocol):
    """Asynchronous UDP handler for business logic and discovery responses."""
    def __init__(self, key: bytes, state: GlobalState):
        self.shared_key = key
        self.state = state
        self.transport = None
        self.ip, self.mac = self._get_local_info()

    def _get_local_info(self) -> Tuple[str, bytes]:
        """Fetch primary local IP and MAC address for protocol responses."""
        for itf, addrs in psutil.net_if_addrs().items():
            if itf == "lo":
                continue
            ip, mac = "127.0.0.1", b"\x00" * 6
            for a in addrs:
                if a.family == socket.AF_INET:
                    ip = a.address
                elif a.family == psutil.AF_LINK:
                    # Clean MAC string format and convert to bytes
                    mac = bytes(int(x, 16) for x in a.address.replace("-", ":").split(":"))
            return ip, mac
        return "127.0.0.1", b"\x00" * 6

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Main entry point for incoming UDP packets."""
        if len(data) < HDR_SIZE:
            return

        # Check for discovery symbol (5G) at expected inner offset
        inner_tag_pos = HDR_SIZE + ETH_HDR_SIZE
        if len(data) > inner_tag_pos + 2 and data[inner_tag_pos:inner_tag_pos + 2] == SYMBOL:
            self._handle_probe(data, addr)
        else:
            self._handle_business(data, addr)

    def _handle_probe(self, data: bytes, addr: Tuple[str, int]):
        """Process and respond to discovery/heartbeat probes."""
        try:
            inner_s = HDR_SIZE + ETH_HDR_SIZE
            _, _, cls, _, _, msgno = struct.unpack(H_FMT, data[inner_s:inner_s + 8])

            # Update counters: f=Find, r=Register, h=Heartbeat
            tags = {GC_FIND: "f", GC_REGISTER: "r", GC_HEARBEAT: "h"}
            self.state.update_probe(addr[0], tags.get(cls, "f"))

            auth32 = struct.unpack(">I", data[4:8])[0]
            inner_hdr = struct.pack(H_FMT, SYMBOL, 1, cls, GC_RESP, 0, msgno)

            # Response Payload Construction
            if cls == GC_FIND:
                payload = self.mac + b"\x00" + socket.inet_aton(self.ip)
            elif cls == GC_HEARBEAT and len(data) >= inner_s + 12:
                payload = data[inner_s + 8:inner_s + 12]
            else:
                payload = b"\x00"

            full_inner = inner_hdr + payload
            total_len = HDR_SIZE + ETH_HDR_SIZE + len(full_inner)

            # Construct Outer Protocol Headers
            pre = struct.pack(">HHII", TYPE_DATA, total_len, auth32, 0)
            eth = bytes(12) + struct.pack(">H", 0x0857) # Pseudo Ethernet Header
            crc = zlib.crc32(pre + eth + full_inner) & 0xFFFFFFFF
            resp = pre[:8] + struct.pack(">I", crc) + eth + full_inner

            self.transport.sendto(resp, (addr[0], self.state.port))
        except Exception:
            pass

    def _handle_business(self, data: bytes, addr: Tuple[str, int]):
        """Process business logic packets (fastpath unpacking)."""
        try:
            in_s = 54 # Data offset after Layer-2/3/4 headers
            d_len, _, _, rcp = struct.unpack(">HBHB", data[in_s:in_s + 6])
            
            # Decode HTTP-like metadata
            method = data[in_s + 6:in_s + 12].strip(b"\x00").decode("utf-8", "ignore")
            url = data[in_s + 12:in_s + 140].strip(b"\x00").decode("utf-8", "ignore")
            
            json_start = in_s + 6 + 6 + 128
            raw_json = data[json_start:json_start + d_len].decode("utf-8", "ignore")
            display_json = (raw_json[:64] + "...") if len(raw_json) > 64 else raw_json

            self.state.log_biz(f"RCP:{rcp} | {method} {url} | DATA: {display_json} ({d_len}B)")
            
            response_message = '{"status":"success", "message":"Received by Black Side"}'
            self.send_back_to_red(addr, data, response_message)
        except Exception:
            pass

    def send_back_to_red(self, addr: tuple, original_data: bytes, response_json: str):
        """Build and transmit the back-channel response packet."""
        try:
            in_s = 54
            _, _, _, orig_rcp = struct.unpack('>HBHB', original_data[in_s: in_s + 6])
            
            # Mock structured response
            mock_response = {
                "status": "ok", "code": 200, 
                "message": "BlackServer: Request processed successfully",
                "rcp_id": orig_rcp, "server_time": int(time.time())
            }
            json_bytes = json.dumps(mock_response).encode('utf-8')
            
            # Header Mirroring (Swap source/destination metadata)
            orig_eth = original_data[12:26]
            orig_d_mac, orig_s_mac = orig_eth[0:6], orig_eth[6:12]
            # 3. 动态提取原始协议类型 (EtherType)，不要写死为 b'\x08\x00'
            orig_eth_type = orig_eth[12:14]
            orig_ip_hdr = original_data[26:46]
            orig_s_ip, orig_d_ip = orig_ip_hdr[12:16], orig_ip_hdr[16:20]
            orig_sp, orig_dp = struct.unpack('>HH', original_data[46:50])

            new_eth_hdr = orig_s_mac + orig_d_mac + orig_eth_type
            new_ip_hdr = bytearray(orig_ip_hdr)
            new_ip_hdr[12:16], new_ip_hdr[16:20] = orig_d_ip, orig_s_ip
            
            # Packet Assembly
            inner_data_hdr = struct.pack('>HBHB', len(json_bytes), 1, 1, orig_rcp)
            res_method = b"POST".ljust(6, b'\x00')
            res_url = b"/api/v1/response".ljust(128, b'\x00')
            full_inner_hdr = inner_data_hdr + res_method + res_url
            
            new_udp_len = 8 + len(full_inner_hdr) + len(json_bytes)
            new_udp_hdr = struct.pack('>HHHH', orig_dp, orig_sp, new_udp_len, 0)
            
            inner_content = new_eth_hdr + bytes(new_ip_hdr) + new_udp_hdr + full_inner_hdr + json_bytes
            full_len = 12 + len(inner_content)
            
            auth_val = self.calc_auth(TYPE_DATA, full_len, inner_content)
            pre_hdr = struct.pack('>HHII', TYPE_DATA, full_len, auth_val, 0)
            final_crc = zlib.crc32(pre_hdr + inner_content) & 0xFFFFFFFF
            
            resp_packet = struct.pack('>HHII', TYPE_DATA, full_len, auth_val, final_crc) + inner_content
            self.transport.sendto(resp_packet, (addr[0], self.state.port))
        except Exception:
            pass

    def calc_auth(self, type16: int, len16: int, payload: bytes) -> int:
        """Calculate HMAC-SHA256 signature for the packet."""
        data = struct.pack('>HH', type16, len16) + payload
        return struct.unpack('>I', hmac.new(self.shared_key, data, hashlib.sha256).digest()[:4])[0]

# =============================================================================
# 4. Health Telemetry Worker (Raw Socket)
# =============================================================================
def health_monitor_worker(state: GlobalState):
    """Raw socket listener for proprietary health telemetry packets."""
    try:
        # Listening for IPv4 (0x0800) packets at Data Link Layer
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        sock.settimeout(1.0)
    except PermissionError:
        state.log_biz("HEALTH ERROR: Permission Denied. Run with sudo for raw access.")
        return

    while state.running:
        try:
            raw_pkt, _ = sock.recvfrom(2048)
            ip_data = raw_pkt[14:]
            
            # Protocol check: Verify IP Protocol field (index 9)
            if ip_data[9] == 1: # ICMP/Custom filter logic
                ip_len = (ip_data[0] & 0x0F) * 4
                payload = ip_data[ip_len + 8:]

                if len(payload) >= HLTH_SIZE:
                    magic = struct.unpack(">I", payload[:4])[0]
                    if magic == 0x484C5448: # "HLTH" Magic
                        (magic, rack, slot, status, uptime, v_maj, 
                         v_min, mem, cpu, err) = struct.unpack(HLTH_FMT, payload[:HLTH_SIZE])

                        src_ip = socket.inet_ntoa(ip_data[12:16])
                        state.update_health((rack, slot), {
                            "addr": src_ip, "status": status, "uptime": uptime,
                            "ver": f"v{v_maj}.{v_min}", "mem": mem / 1024,
                            "cpu": cpu, "err": err,
                        })
        except Exception:
            continue

# =============================================================================
# 5. UI Rendering Logic (Rich)
# =============================================================================
def draw_ui(state: GlobalState):
    """Real-time Dashboard UI using Rich Live Display."""
    layout = Layout()
    layout.split_column(
        Layout(name="top", ratio=2),
        Layout(name="bottom", ratio=1)
    )
    layout["top"].split_row(
        Layout(name="biz_box", ratio=1),
        Layout(name="auth_box", ratio=1)
    )
    layout["bottom"].split_row(
        Layout(name="health_box", ratio=2),
        Layout(name="probe_box", ratio=1)
    )

    with Live(layout, refresh_per_second=4, screen=True):
        while state.running:
            with state.lock:
                # 1. Top-Left: Business Logs
                layout["biz_box"].update(Panel(Text("\n".join(state.biz_logs), style="green"), 
                    title="[1. Business Traffic]", border_style="green"))
                
                # 2. Top-Right: Auth Logs
                layout["auth_box"].update(Panel(Text("\n".join(state.auth_logs), style="cyan"), 
                    title=f"[2. Auth Service - Port {state.auth_port}]", border_style="cyan"))

                # 3. Bottom-Left: Health Telemetry (IP 和 Version 已就绪，Version 置于末尾)
                table_h = Table(expand=True, header_style="bold yellow")
                table_h.add_column("R/S")
                table_h.add_column("Source IP")
                table_h.add_column("Status")
                table_h.add_column("CPU/Mem")
                table_h.add_column("Version")  # 版本列移至最后
                for (r, s), d in sorted(state.health_data.items()):
                    st = "[green]NORM[/]" if d["status"] == 0 else "[red]ERR[/]"
                    # 按照 R/S, IP, Status, CPU/Mem, Version 的顺序填入
                    table_h.add_row(
                        f"R{r}/S{s}", 
                        d.get("addr", "0.0.0.0"), 
                        st, 
                        f"{d['cpu']}%/{d['mem']:.1f}M",
                        d.get("ver", "v0.0")
                    )
                layout["health_box"].update(Panel(table_h, title="[3. Health Telemetry]", border_style="green"))

                # 4. Bottom-Right: Discovery Stats (As requested)
                table_p = Table(expand=True, header_style="bold yellow")
                table_p.add_column("Client IP"); table_p.add_column("F/R/H"); table_p.add_column("Last")
                for ip, s in state.probe_stats.items():
                    table_p.add_row(ip, f"{s['f']}/{s['r']}/{s['h']}", s['last'])
                layout["probe_box"].update(Panel(table_p, title="[4. Discovery Stats]", border_style="green"))

            time.sleep(0.2)

# =============================================================================
# 6. Main Entry Point
# =============================================================================
def run_service(proto_class, port, key, state):
    """Network Loop Initialization."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    coro = loop.create_datagram_endpoint(lambda: proto_class(key, state), local_addr=("0.0.0.0", port))
    loop.run_until_complete(coro)
    loop.run_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--auth-port", type=int, default=DEFAULT_AUTH_PORT)
    parser.add_argument("--key", default="secret_shared_key_lrm_2026")
    args = parser.parse_args()

    state = GlobalState(args.port, args.auth_port)
    key_bytes = args.key.encode()

    # Thread 1: Business Service (52719)
    threading.Thread(target=run_service, args=(BlackServerProtocol, args.port, key_bytes, state), daemon=True).start()
    
    # Thread 2: Auth Service (48350)
    threading.Thread(target=run_service, args=(AuthServerProtocol, args.auth_port, key_bytes, state), daemon=True).start()

    # Thread 3: Health Worker (Raw Socket)
    threading.Thread(target=health_monitor_worker, args=(state,), daemon=True).start()

    try:
        draw_ui(state)
    except KeyboardInterrupt:
        state.running = False
        print("\n[!] Terminated.")