#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import threading
from datetime import datetime
from art import text2art  # 🌟 请确保已运行: pip install rich art
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.align import Align

# 初始化 Rich 控制台
console = Console()

# 模拟网关的核心业务端口配置
DATA_BIND_PORT = 8888
AUTH_BIND_PORT = 9999

# -------------------------------------------------------------------------
# 全局网关状态管理器 (带线程锁，模拟生产环境真实状态更新)
# -------------------------------------------------------------------------
class GatewayState:
    def __init__(self):
        self._lock = threading.Lock()
        self.total_packets = 1024
        self.current_auth_value = 0xABCDEFFF
        self.system_error = "NONE"
        
        # 中层 RX/TX 模拟日志
        self.rx_logs = [
            {"time": "13:45:30", "addr": "192.168.1.10:52311", "type": "TCP", "len": "64B", "flow": "RX_DATA_STREAM -> DECRYPTING..."},
            {"time": "13:45:31", "addr": "192.168.1.11:52312", "type": "UDP", "len": "128B", "flow": "RX_VOIP_STREAM -> BYPASS"},
        ]
        self.tx_logs = [
            {"time": "13:45:30", "addr": "10.0.0.5:80", "type": "TCP", "len": "1024B", "flow": "TX_PROXY_OUT -> DISPATCHED"},
            {"time": "13:45:32", "addr": "10.0.0.6:443", "type": "TCP", "len": "512B", "flow": "TX_SSL_FORWARD -> ENCRYPTED"},
        ]
        
        # 底层认证授权日志
        self.auth_logs = [
            {"time": "13:45:32", "addr": "192.168.211.127:48350", "event": "HEARTBEAT PING", "msg": "Echo PONG dispatched. Footprint: 16B"},
            {"time": "13:45:37", "addr": "192.168.211.127:48350", "event": "HEARTBEAT PING", "msg": "Echo PONG dispatched. Footprint: 16B"},
            {"time": "13:45:42", "addr": "192.168.211.127:48350", "event": "HEARTBEAT PING", "msg": "Echo PONG dispatched. Footprint: 16B"}
        ]

state = GatewayState()

# -------------------------------------------------------------------------
# 动态中间层日志行数计算（防止屏幕溢出）
# -------------------------------------------------------------------------
def get_max_logs_for_screen():
    try:
        height = os.get_terminal_size().lines
        return max(3, height - 18)  # 根据当前终端高度动态分配中部流量日志的行数
    except:
        return 4

# -------------------------------------------------------------------------
# 🧠 核心 UI 渲染架构生成器
# -------------------------------------------------------------------------
def generate_dashboard():
    # =========================================================================
    # Panel 1: Top Panel (顶部系统概览栏 + 最右上角动态时钟)
    # =========================================================================
    # 动态捕获当前时间（时:分:秒）
    current_time_str = datetime.now().strftime("%H:%M:%S")

    # 创建顶栏专用网格，开启两端对齐
    sys_table = Table.grid(expand=True)
    sys_table.add_column(style="bold cyan", justify="left", ratio=1) # 左侧数据
    sys_table.add_column(style="white", justify="center", ratio=1)   # 中间全局状态
    sys_table.add_column(style="bold bright_green", justify="right") # 🌟 修正后的样式：最右侧时间强行靠右对齐

    # 注入第一行数据：左侧放流量总包，最右侧注入高亮时钟
    sys_table.add_row(
        f"DATA NODE: 0.0.0.0:{DATA_BIND_PORT}   TOTAL PKTS: {state.total_packets}",
        f"AUTH CORE VALUE: 0x{state.current_auth_value:08X}",
        f"[bold white on grey15] 🕒 {current_time_str} [/bold white on grey15]"
    )
    
    # 注入第二行数据：辅助网络节点状态
    sys_table.add_row(
        f"AUTH NODE: 0.0.0.0:{AUTH_BIND_PORT}",
        f"SYS RUNTIME ERROR: [red]{state.system_error}[/red]",
        ""  # 时间下方留空
    )
    
    top_panel = Panel(
        sys_table, 
        title="[bold magenta]NET ENGINE DUAL-STREAM PROFILE[/bold magenta]", 
        border_style="bright_blue",
        title_align="left"
    )

    max_display_lines = get_max_logs_for_screen()

    # =========================================================================
    # Panel 2: Middle Panel (双流接收/发送监控)
    # =========================================================================
    # 左窗：RX 接收流
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

    # 右窗：TX 注入流
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

    # =========================================================================
    # Panel 3: Bottom Split Panel (专业艺术大字，物理槽位铁锁连环)
    # =========================================================================
    # 1. 调用 art 库生成全字符支持的 'standard' 工业字体
    token_str = f"0X{state.current_auth_value:08X}"
    raw_art = text2art(token_str, font='standard').rstrip()

    # 2. 强行渲染为加粗、高亮科技绿
    bold_art_display = f"[bold bright_green]{raw_art}[/bold bright_green]"

    # 3. 构造左侧 Token 容器
    auth_val_panel = Panel(
        Align.center(bold_art_display, vertical="middle"),
        title="[bold bright_green]ACTIVE TOKEN[/bold bright_green]",
        border_style="bright_green"
    )

    # 4. 构造右侧审计日志
    auth_table = Table(box=None, expand=True)
    auth_table.add_column("TIME", style="dim white", width=9)
    auth_table.add_column("REMOTE NODE", style="green", width=19)
    auth_table.add_column("EVENT TYPE", style="bold magenta", width=14)
    auth_table.add_column("DIAGNOSTIC CONTROL PLANE LOGS", style="white")

    max_auth_lines = 3
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

    # 5. 横向切割：用 size=65 将左侧大字领地强行焊死，防抖动，右侧自由吃满
    bottom_layout = Layout()
    bottom_layout.split_row(
        Layout(auth_val_panel, size=65),   # 锁死大字区域宽度为 65 列
        Layout(auth_log_panel, ratio=1)
    )

    # =========================================================================
    # 框架总装配器
    # =========================================================================
    main_layout = Layout()
    main_layout.split_column(
        Layout(top_panel, size=4),          # 顶部指标栏固定 4 行高
        Layout(middle_layout, ratio=1),     # 中间日志层动态适配
        Layout(bottom_layout, size=9)       # 底部大字+控制台锁死 9 行高
    )
    return main_layout

# -------------------------------------------------------------------------
# 异步后台线程：模拟网关真实数据的吞吐刷新
# -------------------------------------------------------------------------
def background_data_feeder():
    count = 0
    while True:
        time.sleep(1)
        count += 1
        current_time = datetime.now().strftime("%H:%M:%S")
        
        with state._lock:
            state.total_packets += 7
            state.current_auth_value = 0xABCDEF00 + (count % 256)
            
            # 定时追加中层流数据
            state.rx_logs.append({
                "time": current_time, 
                "addr": f"192.168.1.{10 + (count%10)}:52311", 
                "type": "TCP", "len": "64B", "flow": "ASYNC_PACKET_REASSEMBLE -> SUCCESS"
            })
            state.tx_logs.append({
                "time": current_time, 
                "addr": f"10.0.0.{20 + (count%10)}:443", 
                "type": "TCP", "len": "128B", "flow": "VPN_GATEWAY_FORWARD -> DISPATCHED"
            })
            
            # 定时追加底层审计日志
            if count % 5 == 0:
                state.auth_logs.append({
                    "time": current_time,
                    "addr": "192.168.211.127:48350",
                    "event": "HEARTBEAT PING",
                    "msg": "Echo PONG dispatched. Footprint: 16B"
                })

# -------------------------------------------------------------------------
# 程序主入口
# -------------------------------------------------------------------------
if __name__ == "__main__":
    # 启动后台 feeder 线程
    feeder_thread = threading.Thread(target=background_data_feeder, daemon=True)
    feeder_thread.start()

    # 启动 Live 刷新
    with Live(generate_dashboard(), console=console, screen=True, auto_refresh=True, refresh_per_second=4) as live:
        try:
            while True:
                time.sleep(0.25)
                live.update(generate_dashboard())
        except KeyboardInterrupt:
            console.clear()
            print("[+] Network telemetry monitor safely stopped.")