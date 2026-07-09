#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (c) 2026-2026, Red LRM.
# Author: [yanruibing]
# All rights reserved.
#
# Subsystem: Isolated Identity Authentication Engine (Independent Thread Pipeline)

import socket
import struct
import zlib
import time
import os
import hmac
import hashlib
import threading
import asyncio
from datetime import datetime
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from art import text2art

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.align import Align

console = Console()

# =============================================================================
# 1. GLOBAL CONSTANTS & SHAREABLE STATE
# =============================================================================
DATA_BIND_PORT = 52719          # Business data mirroring infrastructure port
AUTH_BIND_PORT = 48350          # Isolated control-plane auth port
TYPE_DATA = 0x6789              # Custom pipeline protocol type
AUTH_TOKEN = 0xABCDEFFF         # Static default business auth signature

PING_MAGIC = b'PING'
TYPE_AUTH_REQ = 0x6000
TYPE_AUTH_RESP = 0x6001
AUTH_HDR_SIZE = 12
AUTH_KEY = b"RedLRM_Secret_Key_2026"

class GlobalState:
    def __init__(self):
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.total_packets = 0
        self.current_auth_value = 0x00000000
        self.system_error = "None"
        
        # Thread-safe log queues protecting shared UI layout metrics
        self.rx_logs = []
        self.tx_logs = []
        self.auth_logs = []
        self._lock = threading.Lock()

    def log_rx(self, log_entry):
        with self._lock:
            self.rx_logs.append(log_entry)

    def log_tx(self, log_entry):
        with self._lock:
            self.tx_logs.append(log_entry)

    def log_auth(self, log_entry):
        with self._lock:
            self.auth_logs.append(log_entry)

state = GlobalState()

# =============================================================================
# 2. UI MATRIX RENDER ENGINE (Rich Live Dynamic Slicing)
# =============================================================================
def get_max_logs_for_screen():
    """精确计算当前终端下，中层数据窗口能够容纳的最大行数，防止下方留白"""
    try:
        terminal_height = os.get_terminal_size().lines
        # 顶部配置面板(4行) + 底部Auth面板(7行) + 各层边框及留空占位(约4行) = 15行
        # 剩余空间全部分配给中层数据窗口
        available_middle_height = terminal_height - 15
        return max(2, available_middle_height)
    except OSError:
        return 6

def generate_dashboard():
    # -------------------------------------------------------------------------
    # Panel 1: Top Panel (System Profile Metrics)
    # -------------------------------------------------------------------------
    sys_table = Table.grid(padding=(0, 4))
    sys_table.add_column(style="bold cyan")
    sys_table.add_column(style="white")
    sys_table.add_column(style="bold cyan")
    sys_table.add_column(style="white")
    sys_table.add_column(style="bold magenta")
    sys_table.add_column(style="bold green")
    
    sys_table.add_row(
        "DATA NODE:", f"0.0.0.0:{DATA_BIND_PORT}", 
        "TOTAL PKTS:", f"{state.total_packets}",
        "AUTH CORE VALUE:", f"0x{state.current_auth_value:08X}"
    )
    sys_table.add_row(
        "AUTH NODE:", f"0.0.0.0:{AUTH_BIND_PORT}", 
        "SYS RUNTIME ERROR:", f"[red]{state.system_error}[/red]",
        "", ""
    )
    
    top_panel = Panel(
        sys_table, 
        title="[bold magenta]NET ENGINE DUAL-STREAM PROFILE[/bold magenta]", 
        border_style="bright_blue",
        title_align="left"
    )

    max_display_lines = get_max_logs_for_screen()

    # -------------------------------------------------------------------------
    # Panel 2: Middle Panel (RX / TX Symmetric Split Windows)
    # -------------------------------------------------------------------------
    # Data Bus RX Window
    rx_table = Table(box=None, expand=True)
    rx_table.add_column("TIME", style="dim white", width=9)
    rx_table.add_column("NODE", style="green", width=19)
    rx_table.add_column("TYPE", style="magenta", width=8)
    rx_table.add_column("LEN", style="yellow", width=6)
    rx_table.add_column("L3/L4 DATA FLOW", style="cyan")

    with state._lock:
        while len(state.rx_logs) > max_display_lines:
            state.rx_logs.pop(0)
        for log in state.rx_logs:
            rx_table.add_row(log["time"], log["addr"], log["type"], log["len"], log["flow"])

    left_panel = Panel(rx_table, title="[bold green]DATA BUS RECEIVE (RX LOG)[/bold green]", border_style="green", title_align="left")

    # Data Bus TX Window
    tx_table = Table(box=None, expand=True)
    tx_table.add_column("TIME", style="dim white", width=9)
    tx_table.add_column("TARGET", style="green", width=19)
    tx_table.add_column("TYPE", style="magenta", width=8)
    tx_table.add_column("LEN", style="yellow", width=6)
    tx_table.add_column("INJECTED REVERSE FLOW", style="cyan")

    with state._lock:
        while len(state.tx_logs) > max_display_lines:
            state.tx_logs.pop(0)
        for log in state.tx_logs:
            tx_table.add_row(log["time"], log["addr"], log["type"], log["len"], log["flow"])

    right_panel = Panel(tx_table, title="[bold gold3]DATA BUS INJECTION (TX LOG)[/bold gold3]", border_style="gold3", title_align="left")

    middle_layout = Layout()
    middle_layout.split_row(Layout(left_panel, ratio=1), Layout(right_panel, ratio=1))

    # -------------------------------------------------------------------------
    # Panel 3: Bottom Split Panel (Auth Metric Display & Logs)
    # -------------------------------------------------------------------------
    # Left Sub-window: Artistic Display of current Auth Token Value
    auth_art_text = f"[reverse bold green]  0x{state.current_auth_value:08X}  [/reverse bold green]"
    auth_val_panel = Panel(
        Align.center(auth_art_text, vertical="middle"),
        title="[bold bright_green]ACTIVE TOKEN[/bold bright_green]",
        border_style="bright_green"
    )

    # Right Sub-window: Telemetry Link Heartbeat Logs
    auth_table = Table(box=None, expand=True)
    auth_table.add_column("TIME", style="dim white", width=9)
    auth_table.add_column("REMOTE NODE", style="green", width=19)
    auth_table.add_column("EVENT TYPE", style="bold magenta", width=14)
    auth_table.add_column("DIAGNOSTIC CONTROL PLANE LOGS", style="white")

    # 压低高度后，右侧日志视窗固定展示 3 行最新控制报文
    max_auth_lines = 4
    with state._lock:
        while len(state.auth_logs) > max_auth_lines:
            state.auth_logs.pop(0)
        for log in state.auth_logs:
            auth_table.add_row(log["time"], log["addr"], log["event"], log["msg"])

    auth_log_panel = Panel(
        auth_table,
        title="[bold magenta]TELEMETRY TRANSMISSION LOGS[/bold magenta]",
        border_style="magenta",
        title_align="left"
    )

    # 横向切分底部 Auth 区域 (左侧艺术令牌:比重1, 右侧日志流:比重3)
    bottom_layout = Layout()
    bottom_layout.split_row(
        Layout(auth_val_panel, ratio=1),
        Layout(auth_log_panel, ratio=3)
    )

    # -------------------------------------------------------------------------
    # Main Framework Assembler Structure
    # -------------------------------------------------------------------------
    main_layout = Layout()
    main_layout.split_column(
        Layout(top_panel, size=4),          # 顶部固定4行
        Layout(middle_layout, ratio=1),     # 中层动态拉伸（吃满剩余行数）
        Layout(bottom_layout, size=7)       # 底部硬性压低，固定占7行
    )
    return main_layout

# =============================================================================
# 3. AUTHENTICATION PROTOCOL HANDLER (Isolated Native Thread Module)
# =============================================================================
class AuthServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, key: bytes, global_state: GlobalState):
        self.key = key
        self.state = global_state
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def verify_full_crc(self, full_data: bytes, stored_crc: int) -> bool:
        temp_data = bytearray(full_data)
        if len(temp_data) >= 12:
            temp_data[8:12] = b'\x00\x00\x00\x00'
        calc_crc = zlib.crc32(temp_data) & 0xFFFFFFFF
        return calc_crc == stored_crc

    def datagram_received(self, data: bytes, addr: tuple):
        if not self.transport:
            return

        current_time = datetime.now().strftime("%H:%M:%S")
        addr_str = f"{addr[0]}:{addr[1]}"

        # Execution Branch A: Raw PING Link Probing Verification
        if data.startswith(PING_MAGIC):
            self.transport.sendto(data, addr)
            self.state.log_auth({
                "time": current_time, "addr": addr_str,
                "event": "HEARTBEAT PING", "msg": f"Echo PONG dispatched. Footprint: {len(data)}B"
            })
            return

        # Execution Branch B: Sovereign 0x6000 HMAC Token Authorization
        if len(data) >= AUTH_HDR_SIZE and (data[0] == 0x60 or data[0] == 0x61):
            try:
                type16, len16, auth32, stored_crc = struct.unpack('>HHII', data[:AUTH_HDR_SIZE])
                
                if type16 == TYPE_AUTH_REQ:
                    payload = data[:len16]
                    
                    if not self.verify_full_crc(payload, stored_crc):
                        self.state.log_auth({
                            "time": current_time, "addr": addr_str,
                            "event": "CRC ERROR", "msg": f"Ingress payload CRC error. Drop frame."
                        })
                        return

                    # Standard HMAC-SHA256 Multi-Core Matrix Crypto Calculation
                    time_factor = int(time.time()) // 300
                    msg_to_sign = struct.pack('>HHQ', TYPE_AUTH_RESP, AUTH_HDR_SIZE, time_factor) + data[AUTH_HDR_SIZE:len16]
                    mac = hmac.new(self.key, msg_to_sign, hashlib.sha256).digest()
                    new_auth32 = struct.unpack('>I', mac[:4])[0]
                    self.state.current_auth_value = new_auth32

                    # Package Encapsulation Response Structure
                    resp = bytearray(struct.pack('>HHII', TYPE_AUTH_RESP, AUTH_HDR_SIZE, new_auth32, 0))
                    final_crc = zlib.crc32(resp) & 0xFFFFFFFF
                    struct.pack_into('>I', resp, 8, final_crc)
                    
                    self.transport.sendto(bytes(resp), addr)
                    self.state.log_auth({
                        "time": current_time, "addr": addr_str,
                        "event": "AUTH SUCCESS", "msg": f"Token 0x{new_auth32:08x} synchronized cleanly."
                    })
            except Exception as e:
                self.state.log_auth({
                    "time": current_time, "addr": addr_str,
                    "event": "AUTH EXCEPTION", "msg": str(e)
                })

def start_auth_thread_loop(port, key, global_state):
    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    
    listen = loop.create_datagram_endpoint(
        lambda: AuthServerProtocol(key, global_state),
        local_addr=('0.0.0.0', port)
    )
    
    transport, protocol = loop.run_until_complete(listen)
    try:
        loop.run_forever()
    finally:
        transport.close()
        loop.close()

# =============================================================================
# 4. DATA BUS ROUTING FRAMEWORK (Twisted Engine Main Thread)
# =============================================================================
class RedLrmDataMirrorEngine(DatagramProtocol):
    maxPacketSize = 65535
    
    def startProtocol(self):
        try:
            sock = self.transport.getHandle()
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16777216)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16777216)
        except Exception as e:
            state.system_error = str(e)

    def datagramReceived(self, data, addr):
        current_time = datetime.now().strftime("%H:%M:%S")
        addr_str = f"{addr[0]}:{addr[1]}"

        try:
            if len(data) < 12: return
            gw_type, gw_len, gw_auth, gw_crc = struct.unpack('>HHII', data[:12])
            inner_ethernet_packet = data[12:]
            if len(inner_ethernet_packet) < 42: return
            
            # Layer-2/Layer-3 Symmetric Flow Swap Routing Engine
            orig_eth_hdr = inner_ethernet_packet[0:14]
            orig_dst_mac, orig_src_mac, ether_type = orig_eth_hdr[0:6], orig_eth_hdr[6:12], orig_eth_hdr[12:14]
            new_eth_hdr = orig_src_mac + orig_dst_mac + ether_type

            ip_start = 14
            orig_ip_hdr = inner_ethernet_packet[ip_start : ip_start + 20]
            orig_src_ip, orig_dst_ip = orig_ip_hdr[12:16], orig_ip_hdr[16:20]
            new_ip_hdr_view = bytearray(orig_ip_hdr)
            new_ip_hdr_view[12:16], new_ip_hdr_view[16:20] = orig_dst_ip, orig_src_ip
            new_ip_hdr_view[10:12] = b'\x00\x00'
            new_ip_hdr = bytes(new_ip_hdr_view)

            udp_start = 34
            orig_udp_hdr = inner_ethernet_packet[udp_start : udp_start + 8]
            orig_src_port, orig_dst_port = struct.unpack('>HH', orig_udp_hdr[0:4])
            app_payload = inner_ethernet_packet[udp_start + 8 :]

            new_udp_len = 8 + len(app_payload)
            new_udp_hdr = struct.pack('>HHHH', orig_dst_port, orig_src_port, new_udp_len, 0)

            new_inner_content = new_eth_hdr + new_ip_hdr + new_udp_hdr + app_payload
            full_len = 12 + len(new_inner_content)
            
            resp_packet = struct.pack('>HHII', TYPE_DATA, full_len, AUTH_TOKEN, 0) + new_inner_content
            final_crc = zlib.crc32(resp_packet) & 0xFFFFFFFF
            resp_packet = struct.pack('>HHII', TYPE_DATA, full_len, AUTH_TOKEN, final_crc) + new_inner_content
            
            # Push Mirror Routing Telemetry
            src_ip_str, dst_ip_str = socket.inet_ntoa(orig_src_ip), socket.inet_ntoa(orig_dst_ip)
            state.log_rx({
                "time": current_time, "addr": addr_str,
                "type": f"0x{gw_type:04X}", "len": f"{len(data)}B",
                "flow": f"{src_ip_str}:{orig_src_port} -> {dst_ip_str}:{orig_dst_port}"
            })

            self.transport.write(resp_packet, addr)
            
            state.log_tx({
                "time": current_time, "addr": addr_str,
                "type": f"0x{TYPE_DATA:04X}", "len": f"{full_len}B",
                "flow": f"{dst_ip_str}:{orig_dst_port} -> {src_ip_str}:{orig_src_port} ({len(app_payload)}B)"
            })
            state.total_packets += 1

        except Exception as e:
            state.system_error = str(e)

# =============================================================================
# 5. EXECUTION BOOTSTRAP MATRIX
# =============================================================================
if __name__ == "__main__":
    # 1. Spawn Thread for Isolated Authentication Control Plane
    auth_thread = threading.Thread(
        target=start_auth_thread_loop,
        args=(AUTH_BIND_PORT, AUTH_KEY, state),
        daemon=True
    )
    auth_thread.start()

    # 2. Instantiate Main Business Network Protocol (Twisted Core)
    reactor.listenUDP(DATA_BIND_PORT, RedLrmDataMirrorEngine())
    
    # 3. Open UI Canvas Loop Layer
    with Live(generate_dashboard(), console=console, screen=True, auto_refresh=True, refresh_per_second=10) as live:
        def update_ui():
            live.update(generate_dashboard())
            reactor.callLater(0.1, update_ui)
            
        reactor.callLater(0.1, update_ui)
        
        try:
            reactor.run()
        except KeyboardInterrupt:
            pass