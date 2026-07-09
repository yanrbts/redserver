#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import time
from art import text2art  # 🌟 引入专业的艺术字库
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.layout import Layout
from rich.align import Align

console = Console()

class MockState:
    def __init__(self):
        self.current_auth_value = 0xABCDEFFF
        self.auth_logs = [
            {"time": "13:09:01", "addr": "192.168.211.127:48350", "event": "HEARTBEAT PING", "msg": "Echo PONG dispatched. Size: 16B"},
            {"time": "13:09:06", "addr": "192.168.211.127:48350", "event": "HEARTBEAT PING", "msg": "Echo PONG dispatched. Size: 16B"},
            {"time": "13:09:11", "addr": "192.168.211.127:48350", "event": "HEARTBEAT PING", "msg": "Echo PONG dispatched. Size: 16B"}
        ]

state = MockState()

def generate_test_dashboard():
    # 1. 顶部配置栏
    sys_table = Table.grid(padding=(0, 4))
    sys_table.add_column(style="bold cyan")
    sys_table.add_column(style="white")
    sys_table.add_row("ENGINE STATUS:", "[green]RUNNING (ART LIBRARY MODE)[/green]", "AUTH NODE:", "0.0.0.0:48350")
    top_panel = Panel(sys_table, title="[bold magenta]NET ENGINE PROFILE[/bold magenta]", border_style="bright_blue", title_align="left")

    # 2. 中层流量窗口
    rx_table = Table(box=None, expand=True)
    rx_table.add_column("TIME", style="dim white", width=9)
    rx_table.add_column("FLOW", style="cyan")
    rx_table.add_row("13:09:11", "192.168.1.100:54321 -> 192.168.1.1:80 [MOCK DATA]")
    left_panel = Panel(rx_table, title="[bold green]RECEIVE TRAFFIC (RX LOG)[/bold green]", border_style="green", title_align="left")
    middle_layout = Layout()
    middle_layout.split_row(Layout(left_panel, ratio=1), Layout(Panel(Table(box=None), title="[bold gold3]RESPONSE INJECTION (TX LOG)[/bold gold3]", border_style="gold3"), ratio=1))

    # -------------------------------------------------------------------------
    # 3. 🧠 核心注入：利用 art 库生成高清晰、防变形的工业大字
    # -------------------------------------------------------------------------
    # 'chr73' 或 'cybermedium' 字体是业界公认最适合点阵网关展示的字体，
    # 它的特点是：间距干净，每个字母带有优雅的修边，非常美观且好认！
    token_str = f"0X{state.current_auth_value:08X}"
    raw_art = text2art(token_str, font='cybermedium').rstrip()

    # 2. 🌟 核心改动：用 [bold bright_green] 标签强行把整块艺术字加粗、提亮
    bold_art_display = f"[bold bright_green]{raw_art}[/bold bright_green]"

    # 3. 塞进物理锁定的面板里
    auth_val_panel = Panel(
        Align.center(bold_art_display, vertical="middle"),  # 居中大字
        title="[bold bright_green]ACTIVE TOKEN[/bold bright_green]",
        border_style="bright_green",
        width=62,
        expand=False
    )

    # 右侧控制台日志
    auth_table = Table(box=None, expand=True)
    auth_table.add_column("TIME", style="dim white", width=9)
    auth_table.add_column("REMOTE NODE", style="green", width=19)
    auth_table.add_column("EVENT TYPE", style="bold magenta", width=14)
    auth_table.add_column("DIAGNOSTIC LOGS", style="white")

    for log in state.auth_logs:
        auth_table.add_row(log["time"], log["addr"], log["event"], log["msg"])

    auth_log_panel = Panel(
        auth_table,
        title="[bold magenta]TELEMETRY TRANSMISSION LOGS[/bold magenta]",
        border_style="magenta",
        title_align="left"
    )

    # 4. 底部横向切割：左边大字强行圈地 62 列，右边日志自动吃满
    bottom_layout = Layout()
    bottom_layout.split_row(
        Layout(auth_val_panel, size=62),
        Layout(auth_log_panel, ratio=1)
    )

    # 5. 主骨架纵向装配：这种字体完美契合 5 行高，底部保留 9 行，既压低了高度，画面又干净
    main_layout = Layout()
    main_layout.split_column(
        Layout(top_panel, size=4),
        Layout(middle_layout, ratio=1),
        Layout(bottom_layout, size=9)
    )
    return main_layout

if __name__ == "__main__":
    with Live(generate_test_dashboard(), console=console, screen=True, auto_refresh=True, refresh_per_second=2) as live:
        count = 0
        try:
            while True:
                time.sleep(1)
                count += 1
                state.current_auth_value = 0xABCDEF00 + (count % 256)
                live.update(generate_test_dashboard())
        except KeyboardInterrupt:
            pass