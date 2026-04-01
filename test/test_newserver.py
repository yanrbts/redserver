import argparse
import socket
import struct
import time
import zlib
import hmac
import hashlib
import asyncio
import json
import psutil
import threading
import sys
from datetime import datetime
from typing import Tuple, Dict

# 引入 Rich 绘图库
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text

# ==============================
# 1. 核心常量与全局状态
# ==============================
DEFAULT_PORT = 52719
HDR_SIZE = 12
TYPE_DATA = 0x6789  
SYMBOL = b'5G'
GC_FIND, GC_REGISTER, GC_HEARBEAT = 0x01, 0x02, 0x03
GC_REQ, GC_RESP = 0x01, 0x02
H_FMT = "!2sBBBBH"
ETH_HDR_SIZE = 14

class GlobalState:
    def __init__(self):
        self.lock = threading.Lock()
        self.biz_logs = []      # 左窗：业务解析日志
        self.probe_stats = {}   # 右窗：探测状态统计 {ip: {'f':0, 'r':0, 'h':0, 'last':''}}
        self.total_packets = 0
        self.running = True

    def log_biz(self, msg):
        with self.lock:
            self.biz_logs.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
            if len(self.biz_logs) > 20: self.biz_logs.pop(0)

    def update_probe(self, ip, p_type):
        with self.lock:
            if ip not in self.probe_stats:
                self.probe_stats[ip] = {'f': 0, 'r': 0, 'h': 0, 'last': ''}
            self.probe_stats[ip][p_type] += 1
            self.probe_stats[ip]['last'] = datetime.now().strftime('%H:%M:%S')
            self.total_packets += 1

state = GlobalState()

# ==============================
# 2. 网络协议处理器 (Network Protocol)
# ==============================
class BlackServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, key: bytes):
        self.shared_key = key
        self.transport = None
        self.server_ip, self.server_mac = self._get_sys_info()

    def _get_sys_info(self):
        """获取本地网络信息用于探测响应"""
        for interface, snics in psutil.net_if_addrs().items():
            if interface == 'lo': continue
            ip, mac = None, None
            for snic in snics:
                if snic.family == socket.AF_INET: ip = snic.address
                elif snic.family == psutil.AF_LINK:
                    mac = bytes([int(x, 16) for x in snic.address.replace('-', ':').split(':')])
            if ip and mac: return ip, mac
        return "127.0.0.1", b'\x00'*6

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        if len(data) < HDR_SIZE: return
        
        try:
            # 基础路由判断
            type16, len16, auth32, crc32 = struct.unpack('>HHII', data[:HDR_SIZE])
            inner_tag_pos = HDR_SIZE + ETH_HDR_SIZE
            
            # 分流：探测包 vs 业务包
            if len(data) > inner_tag_pos + 2 and data[inner_tag_pos:inner_tag_pos+2] == SYMBOL:
                self._handle_probe(data, addr, auth32)
            else:
                self._handle_business(data, addr)
        except Exception as e:
            state.log_biz(f"Routing Error: {e}")

    # --- 探测逻辑分支 ---
    def _handle_probe(self, data, addr, auth32):
        inner_s = HDR_SIZE + ETH_HDR_SIZE
        symbol, ver, cls, subtype, empty, msgno = struct.unpack(H_FMT, data[inner_s:inner_s+8])
        
        resp_payload = b''
        p_tag = 'f'
        if cls == GC_FIND:
            p_tag = 'f'
            resp_payload = self.server_mac + b'\x00' + socket.inet_aton(self.server_ip)
        elif cls == GC_REGISTER:
            p_tag = 'r'
            resp_payload = b'\x00'
        elif cls == GC_HEARBEAT:
            p_tag = 'h'
            resp_payload = data[inner_s+8:inner_s+12] # Client Timestamp

        state.update_probe(addr[0], p_tag)
        
        # 组装响应包
        inner_hdr = struct.pack(H_FMT, SYMBOL, 1, cls, GC_RESP, 0, msgno)
        full_inner = inner_hdr + resp_payload
        pkt = self._build_full_packet(full_inner, auth32)
        self.transport.sendto(pkt, (addr[0], DEFAULT_PORT))

    # --- 业务逻辑分支 (剥洋葱核心) ---
    def _handle_business(self, data: bytes, addr: tuple):
        try:
            # 1. 基础校验 (CRC)
            type16, len16, auth32, crc32 = struct.unpack('>HHII', data[:HDR_SIZE])
            temp_pkt = bytearray(data)
            temp_pkt[8:12] = b'\x00\x00\x00\x00'
            if (zlib.crc32(temp_pkt) & 0xFFFFFFFF) != crc32:
                state.log_biz(f"CRC Error from {addr[0]}")
                return

            # 2. 剥洋葱解析 (Offsets)
            eth_s, ip_s, u_s, in_s = 12, 26, 46, 54
            GAP_METHOD_LEN, GAP_URL_LEN = 6, 128
            
            # 提取元数据
            s_ip = socket.inet_ntoa(data[ip_s+12:ip_s+16])
            sp, _ = struct.unpack('>HH', data[u_s:u_s+4])
            d_len, num, total, rcp = struct.unpack('>HBHB', data[in_s:in_s+6])
            
            method = data[in_s+6:in_s+6+GAP_METHOD_LEN].strip(b'\x00').decode('utf-8', 'ignore')
            url = data[in_s+6+GAP_METHOD_LEN:in_s+6+GAP_METHOD_LEN+GAP_URL_LEN].strip(b'\x00').decode('utf-8', 'ignore')
            
            # --- 新增：处理 JSON 数据截断与大小统计 ---
            json_start = in_s + 6 + GAP_METHOD_LEN + GAP_URL_LEN
            raw_json = data[json_start : json_start + d_len].decode('utf-8', 'ignore')
            
            display_limit = 64
            if len(raw_json) > display_limit:
                # 截断显示：前32位 + ... + (总大小)
                json_display = f"{raw_json[:display_limit]}... ({d_len}B)"
            else:
                json_display = f"{raw_json} ({d_len}B)"
            
            # UI 输出：整合所有字段
            log_msg = f"AUTH:0x{auth32:08x} | {s_ip}:{sp} -> {method} {url} | RCP:{rcp} | DATA: {json_display}"
            state.log_biz(log_msg)
            
            # 3. 组装并发送响应
            self._send_business_resp(addr, data, rcp)
            
        except Exception as e:
            state.log_biz(f"Biz Unpack Error: {e}")

    def _send_business_resp(self, addr, original_data, orig_rcp):
        """黑区回传逻辑：构造完整的隧道嵌套响应包"""
        # 构建业务 JSON
        resp_json = json.dumps({"status": "ok", "rcp_id": orig_rcp, "ts": int(time.time())}).encode('utf-8')
        
        # 1. Ethernet (交换源目MAC)
        orig_eth = original_data[12:26]
        new_eth = orig_eth[6:12] + orig_eth[0:6] + b'\x08\x00'
        
        # 2. IP (交换源目IP)
        orig_ip = bytearray(original_data[26:46])
        orig_ip[12:16], orig_ip[16:20] = orig_ip[16:20], orig_ip[12:16]
        new_ip = bytes(orig_ip)
        
        # 3. UDP (交换端口)
        orig_sp, orig_dp = struct.unpack('>HH', original_data[46:50])
        biz_hdr = struct.pack('>HBHB', len(resp_json), 1, 1, orig_rcp)
        biz_path = b"POST".ljust(6, b'\x00') + b"/api/v1/res".ljust(128, b'\x00')
        udp_len = 8 + len(biz_hdr) + len(biz_path) + len(resp_json)
        new_udp = struct.pack('>HHHH', orig_dp, orig_sp, udp_len, 0)
        
        # 合并 Inner Payload
        inner_content = new_eth + new_ip + new_udp + biz_hdr + biz_path + resp_json
        
        # 4. 构建外层 Auth & CRC
        full_len = HDR_SIZE + len(inner_content)
        auth_val = self._calc_auth(TYPE_DATA, full_len, inner_content)
        
        pre_hdr = struct.pack('>HHII', TYPE_DATA, full_len, auth_val, 0)
        final_crc = zlib.crc32(pre_hdr + inner_content) & 0xFFFFFFFF
        resp_pkt = struct.pack('>HHII', TYPE_DATA, full_len, auth_val, final_crc) + inner_content
        
        self.transport.sendto(resp_pkt, (addr[0], DEFAULT_PORT))

    def _calc_auth(self, type16, len16, payload):
        msg = struct.pack('>HH', type16, len16) + payload
        return struct.unpack('>I', hmac.new(self.shared_key, msg, hashlib.sha256).digest()[:4])[0]

    def _build_full_packet(self, inner_payload, auth32):
        """辅助函数：为探测响应构建外层"""
        total_len = HDR_SIZE + ETH_HDR_SIZE + len(inner_payload)
        outer_pre = struct.pack('>HHII', TYPE_DATA, total_len, auth32, 0)
        ether = bytes(12) + struct.pack('>H', 0x0857)
        final_crc = zlib.crc32(outer_pre + ether + inner_payload) & 0xFFFFFFFF
        return outer_pre[:8] + struct.pack('>I', final_crc) + ether + inner_payload

# ==============================
# 3. UI 线程 (Main Thread)
# ==============================
def run_ui_dashboard():
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body")
    )
    layout["body"].split_row(
        Layout(name="left", ratio=2),
        Layout(name="right", ratio=1)
    )

    console = Console()
    with Live(layout, refresh_per_second=4, screen=True):
        while state.running:
            # Header
            layout["header"].update(Panel(
                Text(f"🚀 BlackSide Industrial Server | Pkts: {state.total_packets} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
                     justify="center", style="bold white on blue"),
                title="System Status", border_style="bright_blue"
            ))

            # Left: Business
            with state.lock:
                biz_display = "\n".join(state.biz_logs)
            layout["left"].update(Panel(Text(biz_display, style="green"), title="[剥洋葱解析与回传日志]", border_style="green"))

            # Right: Probes
            table = Table(expand=True, box=None)
            table.add_column("Client IP", style="cyan")
            table.add_column("F/R/H", justify="center", style="magenta")
            table.add_column("Last Seen", style="yellow")
            
            with state.lock:
                for ip, s in state.probe_stats.items():
                    table.add_row(ip, f"{s['f']}/{s['r']}/{s['h']}", s['last'])
            
            layout["right"].update(Panel(table, title="[探测统计: Find/Reg/HB]", border_style="magenta"))
            time.sleep(0.25)

# ==============================
# 4. 启动与线程管理
# ==============================
def network_worker(key):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    coro = loop.create_datagram_endpoint(lambda: BlackServerProtocol(key), local_addr=('0.0.0.0', DEFAULT_PORT))
    transport, protocol = loop.run_until_complete(coro)
    loop.run_forever()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--key', default='secret_shared_key_lrm_2026')
    args = parser.parse_args()
    
    # 启动网络后台
    t = threading.Thread(target=network_worker, args=(args.key.encode(),), daemon=True)
    t.start()
    
    # 运行 UI
    try:
        run_ui_dashboard()
    except KeyboardInterrupt:
        state.running = False
        print("\nShutdown.")