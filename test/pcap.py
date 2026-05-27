#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import re
from datetime import datetime

# 引入 Rich 库相关组件，用于构建终端 UI
from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree
from rich.rule import Rule
from rich import box

# 引入 Scapy 用于解析 PCAP 文件
try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, ARP, Ether, Raw, wrpcap, DNSQR, DNSRR
except ImportError:
    print("❌ 缺少依赖库 scapy，请运行: pip install scapy")
    sys.exit(1)

# 处理跨平台统一按键与鼠标读取映射
if os.name == 'nt':
    import msvcrt
    def get_key():
        """Windows 下非阻塞读取按键，并进行标准化映射"""
        if msvcrt.kbhit():
            ch = msvcrt.getch()
            if ch in (b'\x00', b'\xe0'):  # 方向键前缀
                ch2 = msvcrt.getch()
                if ch2 == b'H': return "up"
                if ch2 == b'P': return "down"
            if ch == b'\x08':
                return "backspace"
            if ch in (b'\r', b'\n'):
                return "enter"
            if ch == b'\x1b':
                return "esc"
            if ch == b'\t':
                return "tab"
            try:
                return ch.decode('utf-8', errors='ignore')
            except:
                return ""
        return None
else:
    import select
    def get_key():
        """Linux/macOS 下利用 select 保证非阻塞，再用 os.read 瞬发解析控制字符与鼠标点击"""
        try:
            # select 超时设为 0.0 秒（即刻返回），保证主循环绝对流畅
            rlist, _, _ = select.select([0], [], [], 0.0)
            if rlist:
                data = os.read(0, 8)
                if not data:
                    return None
                
                # 🎯 鼠标点击事件解析 (\x1b[M + 3字节)
                if data.startswith(b'\x1b[M') and len(data) >= 6:
                    btn = data[3]
                    cx = data[4] - 32
                    cy = data[5] - 32
                    # 只响应左键点击按下 (btn & 3 == 0)
                    if (btn & 3) == 0:
                        return ("click", cx, cy)
                    return None

                # 精准解析并转换 ANSI 方向键等特殊转义字符序列
                if data in (b'\x1b[A', b'\x1bOA'):
                    return "up"
                elif data in (b'\x1b[B', b'\x1bOB'):
                    return "down"
                elif data in (b'\x1b', b'\x1b\x1b'):
                    return "esc"
                elif data in (b'\x7f', b'\b', b'\x08'):
                    return "backspace"
                elif data in (b'\r', b'\n'):
                    return "enter"
                elif data == b'\t':
                    return "tab"
                
                try:
                    decoded = data.decode('utf-8', errors='ignore')
                    if len(decoded) == 1 and decoded.isprintable():
                        return decoded
                except:
                    pass
        except OSError:
            pass
        return None


class PcapAnalyzer:
    # 🎯 预设的命令补全词库，包含常用过滤关键字段与协议
    COMPLETIONS = [
        "ip.src", "ip.dst", "ip.addr", "ip.len",
        "tcp.sport", "tcp.dport", "tcp.port", "tcp.flags",
        "udp.sport", "udp.dport", "udp.port",
        "frame.len", "len", "proto", "src", "dst", "info",
        "tcp", "udp", "ip", "arp", "dns", "http", "ether"
    ]

    def __init__(self, pcap_path):
        self.pcap_path = pcap_path
        self.all_packets = []      # 存储所有解析后的数据包字典
        self.filtered_packets = [] # 存储过滤后的数据包
        self.selected_idx = 0      # 当前选中的数据包索引 (在过滤列表中的位置)
        self.scroll_offset = 0     # 列表滚动的偏移量
        self.filter_text = ""      # 当前输入的过滤文本
        self.is_filtering = False  # 是否处于编辑过滤条件状态
        self.filter_error = False  # 标志当前过滤条件是否存在语法错误
        self.console = Console()
        
        # 自动补全机制核心关联属性
        self.completion_matches = [] # 存储当前匹配到的补全列表
        self.completion_idx = -1     # 补全指针位置
        self.last_input_prefix = ""  # 触发补全前的原始单词前缀

        # 实时动态监听机制相关属性
        self.last_loaded_count = 0  # 上一次已读取并解析的包数量
        self.follow_tail = True     # 是否开启“追尾模式”（即新包进来时，自动滚动到最底部）
        self.pcap_start_time = 0.0  # 记录首个包的绝对时间作为相对时间基准

        # 初始化 Rich 布局
        self.layout = Layout()
        self.setup_layout()

    def setup_layout(self):
        """切分终端窗口：上面左右两个子窗口，下面一个过滤输入口"""
        self.layout.split_column(
            Layout(name="upper", ratio=9),
            Layout(name="lower", size=3)
        )
        self.layout["upper"].split_row(
            Layout(name="packet_list", ratio=3),
            Layout(name="packet_detail", ratio=2)
        )

    def generate_mock_pcap(self):
        """如果本地没有 pcap，自动生成一个模拟数据包文件，方便开箱即用展示"""
        print("💡 未检测到本地 PCAP 文件，正在为您自动生成模拟测试数据...")
        pkts = [
            Ether()/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=51234, dport=53)/DNS(rd=1, qd=DNSQR(qname="google.com")),
            Ether()/IP(src="8.8.8.8", dst="192.168.1.100")/UDP(sport=53, dport=51234)/DNS(an=DNSRR(rrname="google.com", rdata="142.250.190.46")),
            Ether()/IP(src="192.168.1.100", dst="142.250.190.46")/TCP(sport=43210, dport=80, flags="S"),
            Ether()/IP(src="142.250.190.46", dst="192.168.1.100")/TCP(sport=80, dport=43210, flags="SA"),
            Ether()/IP(src="192.168.1.100", dst="142.250.190.46")/TCP(sport=43210, dport=80, flags="A")/Raw(load="GET / HTTP/1.1\r\nHost: google.com\r\n\r\n"),
            Ether()/IP(src="142.250.190.46", dst="192.168.1.100")/TCP(sport=80, dport=43210, flags="PA")/Raw(load="HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Hello World</body></html>"),
            Ether()/ARP(op="who-has", psrc="192.168.1.1", pdst="192.168.1.100")
        ]
        wrpcap(self.pcap_path, pkts)
        time.sleep(1)

    def load_pcap(self, is_initial=True):
        """利用 Scapy RawPcapReader 增量秒级读取数据，彻底解决因重复整盘扫描引起的键盘响应卡死"""
        if not os.path.exists(self.pcap_path):
            if is_initial:
                self.generate_mock_pcap()
            else:
                return False

        try:
            from scapy.utils import RawPcapReader
            from scapy.layers.l2 import Ether

            new_packets_added = False
            with RawPcapReader(self.pcap_path) as pcap_reader:
                packets_in_file = 0
                for i, (raw_pkt, pkt_metadata) in enumerate(pcap_reader):
                    packets_in_file += 1
                    if i < self.last_loaded_count:
                        continue  # 快速掠过已经被加载的报文段
                    
                    if isinstance(pkt_metadata, tuple):
                        sec = pkt_metadata[0]
                        usec = pkt_metadata[1]
                        length = pkt_metadata[2]
                    else:
                        sec = getattr(pkt_metadata, 'sec', getattr(pkt_metadata, 'tsec', 0))
                        usec = getattr(pkt_metadata, 'usec', getattr(pkt_metadata, 'tusec', 0))
                        length = getattr(pkt_metadata, 'caplen', getattr(pkt_metadata, 'wirelen', len(raw_pkt)))
                    
                    absolute_time = sec + usec / 1000000.0
                    
                    if self.last_loaded_count == 0 and i == 0:
                        self.pcap_start_time = absolute_time

                    pkt_time = f"{absolute_time - self.pcap_start_time:.6f}"
                    
                    pkt = Ether(raw_pkt)
                    src, dst, proto, info = "Unknown", "Unknown", "Unknown", ""
                    
                    if IP in pkt:
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                        proto = "IP"
                        if TCP in pkt:
                            proto = "TCP"
                            info = f"{pkt[TCP].sport} -> {pkt[TCP].dport} [{pkt[TCP].flags}]"
                            if pkt.haslayer(Raw):
                                try:
                                    raw_payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                                    first_line = raw_payload.split('\r\n')[0]
                                    if "HTTP" in first_line:
                                        proto = "HTTP"
                                        info += f" | {first_line}"
                                except:
                                    pass
                        elif UDP in pkt:
                            proto = "UDP"
                            info = f"{pkt[UDP].sport} -> {pkt[UDP].dport}"
                            if DNS in pkt:
                                proto = "DNS"
                                if pkt[DNS].qr == 0:
                                    info += f" Query: {pkt[DNS].qd.qname.decode('utf-8', errors='ignore') if pkt[DNS].qd else ''}"
                                else:
                                    info += " Response"
                    elif ARP in pkt:
                        proto = "ARP"
                        src = pkt[ARP].psrc
                        dst = pkt[ARP].pdst
                        if pkt[ARP].op == 1:
                            info = f"Who has {pkt[ARP].pdst}? Tell {pkt[ARP].psrc}"
                        elif pkt[ARP].op == 2:
                            info = f"{pkt[ARP].psrc} is at {pkt[ARP].hwsrc}"
                    elif Ether in pkt:
                        src = pkt[Ether].src
                        dst = pkt[Ether].dst
                        proto = "Ethernet"
                    
                    self.all_packets.append({
                        "id": i + 1,
                        "time": pkt_time,
                        "src": src,
                        "dst": dst,
                        "proto": proto,
                        "len": length,
                        "info": info,
                        "raw": pkt
                    })
                    new_packets_added = True

                self.last_loaded_count = packets_in_file

            if new_packets_added:
                self.apply_filter(keep_selection=not self.follow_tail)
                return True
            return False

        except Exception as e:
            if is_initial:
                self.console.print(f"[bold red]解析 PCAP 失败: {e}[/bold red]")
                sys.exit(1)
            return False

    def _eval_condition(self, pkt_dict, and_chunk):
        """解析并计算单个原子的 Wireshark 过滤条件"""
        and_chunk = and_chunk.strip()
        if not and_chunk:
            return True

        raw_pkt = pkt_dict["raw"]
        operators = ["==", "!=", ">=", "<=", ">", "<"]
        op = None
        for o in operators:
            if o in and_chunk:
                op = o
                break

        if op:
            parts = and_chunk.split(op, 1)
            field = parts[0].strip().lower()
            val_str = parts[1].strip().strip('"').strip("'")

            actual_val = None
            is_numeric = False

            if field == "ip.src":
                actual_val = raw_pkt[IP].src if IP in raw_pkt else None
            elif field == "ip.dst":
                actual_val = raw_pkt[IP].dst if IP in raw_pkt else None
            elif field == "ip.addr":
                src = raw_pkt[IP].src if IP in raw_pkt else None
                dst = raw_pkt[IP].dst if IP in raw_pkt else None
                if op == "==": return src == val_str or dst == val_str
                elif op == "!=": return src != val_str and dst != val_str
                return False
            elif field == "tcp.sport":
                actual_val = raw_pkt[TCP].sport if TCP in raw_pkt else None
                is_numeric = True
            elif field == "tcp.dport":
                actual_val = raw_pkt[TCP].dport if TCP in raw_pkt else None
                is_numeric = True
            elif field == "tcp.port":
                sport = raw_pkt[TCP].sport if TCP in raw_pkt else None
                dport = raw_pkt[TCP].dport if TCP in raw_pkt else None
                try:
                    v = int(val_str)
                    if op == "==": return sport == v or dport == v
                    if op == "!=": return sport != v and dport != v
                    if op == ">": return (sport is not None and sport > v) or (dport is not None and dport > v)
                    if op == "<": return (sport is not None and sport < v) or (dport is not None and dport < v)
                    if op == ">=": return (sport is not None and sport >= v) or (dport is not None and dport >= v)
                    if op == "<=": return (sport is not None and sport <= v) or (dport is not None and dport <= v)
                except ValueError: return False
            elif field == "udp.sport":
                actual_val = raw_pkt[UDP].sport if UDP in raw_pkt else None
                is_numeric = True
            elif field == "udp.dport":
                actual_val = raw_pkt[UDP].dport if UDP in raw_pkt else None
                is_numeric = True
            elif field == "udp.port":
                sport = raw_pkt[UDP].sport if UDP in raw_pkt else None
                dport = raw_pkt[UDP].dport if UDP in raw_pkt else None
                try:
                    v = int(val_str)
                    if op == "==": return sport == v or dport == v
                    if op == "!=": return sport != v and dport != v
                    if op == ">": return (sport is not None and sport > v) or (dport is not None and dport > v)
                    if op == "<": return (sport is not None and sport < v) or (dport is not None and dport < v)
                    if op == ">=": return (sport is not None and sport >= v) or (dport is not None and dport >= v)
                    if op == "<=": return (sport is not None and sport <= v) or (dport is not None and dport <= v)
                except ValueError: return False
            elif field in ("frame.len", "len"):
                actual_val = len(raw_pkt)
                is_numeric = True
            elif field == "ip.len":
                actual_val = raw_pkt[IP].len if IP in raw_pkt else None
                is_numeric = True
            else:
                if field == "proto":
                    actual_val = pkt_dict["proto"].lower()
                    val_str = val_str.lower()
                elif field == "src":
                    actual_val = pkt_dict["src"].lower()
                    val_str = val_str.lower()
                elif field == "dst":
                    actual_val = pkt_dict["dst"].lower()
                    val_str = val_str.lower()
                elif field == "info":
                    actual_val = pkt_dict["info"].lower()
                    val_str = val_str.lower()
                    if op == "==": return val_str in actual_val
                    if op == "!=": return val_str not in actual_val
                else:
                    return False

            if actual_val is None:
                return False

            if is_numeric:
                try:
                    actual_num = int(actual_val)
                    target_num = int(val_str)
                    if op == "==": return actual_num == target_num
                    if op == "!=": return actual_num != target_num
                    if op == ">": return actual_num > target_num
                    if op == "<": return actual_num < target_num
                    if op == ">=": return actual_num >= target_num
                    if op == "<=": return actual_num <= target_num
                except ValueError: return False
            else:
                actual_str = str(actual_val)
                if op == "==": return actual_str == val_str
                if op == "!=": return actual_str != val_str
                if op == ">": return actual_str > val_str
                if op == "<": return actual_str < val_str
                if op == ">=": return actual_str >= val_str
                if op == "<=": return actual_str <= val_str
            return False
        else:
            token = and_chunk.lower()
            if token == "tcp": return TCP in raw_pkt
            elif token == "udp": return UDP in raw_pkt
            elif token == "ip": return IP in raw_pkt
            elif token == "arp": return ARP in raw_pkt
            elif token == "dns": return DNS in raw_pkt
            elif token == "http": return pkt_dict["proto"].lower() == "http"
            elif token in ("ether", "ethernet"): return Ether in raw_pkt
            else:
                return (token in pkt_dict["proto"].lower() or
                        token in pkt_dict["src"].lower() or
                        token in pkt_dict["dst"].lower() or
                        token in pkt_dict["info"].lower())

    def apply_filter(self, keep_selection=False):
        """执行高级 Wireshark 级过滤逻辑（支持 logical and/or 表达式以及字段级比较）"""
        self.filter_error = False
        if not self.filter_text.strip():
            self.filtered_packets = list(self.all_packets)
            if self.follow_tail and self.filtered_packets:
                self.selected_idx = len(self.filtered_packets) - 1
            elif not keep_selection:
                self.selected_idx = 0
                self.scroll_offset = 0
            return

        query = self.filter_text.strip()
        try:
            or_chunks = re.split(r'\s+or\s+', query, flags=re.IGNORECASE)
            filtered = []
            for pkt in self.all_packets:
                any_or_match = False
                for or_chunk in or_chunks:
                    and_chunks = re.split(r'\s+and\s+', or_chunk, flags=re.IGNORECASE)
                    all_and_match = True
                    for and_chunk in and_chunks:
                        if not self._eval_condition(pkt, and_chunk):
                            all_and_match = False
                            break
                    if all_and_match:
                        any_or_match = True
                        break
                if any_or_match:
                    filtered.append(pkt)
            self.filtered_packets = filtered
        except Exception:
            self.filter_error = True
            self.filtered_packets = list(self.all_packets)

        if self.follow_tail and self.filtered_packets:
            self.selected_idx = len(self.filtered_packets) - 1
        elif keep_selection:
            if self.filtered_packets:
                self.selected_idx = min(self.selected_idx, len(self.filtered_packets) - 1)
            else:
                self.selected_idx = 0
        else:
            self.selected_idx = 0
            self.scroll_offset = 0

    def exec_autocomplete(self):
        """🎯 核心自动补全逻辑：根据输入框最末尾的 Token 进行补全匹配与循环替换
        如果输入内容为空或以操作符结尾，按下 Tab 会直接循环轮播所有可用候选命令词。
        """
        # 1. 拆分最后正在键入的单词片段（以非字母数字及点号的字符，如空格、操作符等作为分隔基准）
        tokens = re.split(r'([^a-zA-Z0-9\._])', self.filter_text)
        last_word = tokens[-1]

        # 2. 状态机：如果已经处于连续按下 Tab 切换补全项的状态中
        if self.completion_idx != -1 and self.completion_matches:
            self.completion_idx = (self.completion_idx + 1) % len(self.completion_matches)
            new_completion = self.completion_matches[self.completion_idx]
            
            # 替换掉最后一个补全出来的单词
            tokens[-1] = new_completion
            self.filter_text = "".join(tokens)
            return

        # 3. 状态机：初次在当前状态下激发 Tab 键
        if not last_word:
            # 💡 核心改动：如果当前没有输入任何字符（或者刚敲完空格/操作符），直接匹配全词库
            matches = list(self.COMPLETIONS)
        else:
            # 否则根据当前前缀做正常的 startswith 过滤匹配
            matches = [item for item in self.COMPLETIONS if item.startswith(last_word.lower())]
        
        if matches:
            self.completion_matches = matches
            self.completion_idx = 0
            self.last_input_prefix = last_word
            
            tokens[-1] = matches[0]
            self.filter_text = "".join(tokens)

    def reset_completion_state(self):
        """清除自动补全状态机（当用户输入新字符或退格时触发）"""
        self.completion_matches = []
        self.completion_idx = -1
        self.last_input_prefix = ""

    def generate_packet_list_table(self, height):
        """渲染左侧数据包列表，提供无列分割条、Wireshark级连续整行选中高亮效果"""
        table = Table(box=box.SIMPLE_HEAD, expand=True, show_edge=False, show_lines=False)
        table.add_column("序号", width=6, justify="right")
        table.add_column("相对时间", width=12)
        table.add_column("源地址", width=16)
        table.add_column("目的地址", width=16)
        table.add_column("协议", width=8)
        table.add_column("长度", width=6, justify="right")
        table.add_column("简要信息")

        visible_rows = max(3, height - 7)
        if self.selected_idx >= self.scroll_offset + visible_rows:
            self.scroll_offset = self.selected_idx - visible_rows + 1
        elif self.selected_idx < self.scroll_offset:
            self.scroll_offset = self.selected_idx

        for i in range(self.scroll_offset, min(len(self.filtered_packets), self.scroll_offset + visible_rows)):
            pkt = self.filtered_packets[i]
            is_selected = (i == self.selected_idx)
            
            if is_selected:
                table.add_row(
                    str(pkt["id"]), pkt["time"], pkt["src"], pkt["dst"],
                    pkt["proto"], str(pkt["len"]), pkt["info"], style="bold white on blue"
                )
            else:
                table.add_row(
                    Text(str(pkt["id"])), Text(pkt["time"], style="cyan"),
                    Text(pkt["src"], style="green"), Text(pkt["dst"], style="red"),
                    Text(pkt["proto"], style="yellow"), Text(str(pkt["len"])),
                    Text(pkt["info"], style="magenta")
                )

        status_flag = " [bold green]● LIVE 实时追尾中[/bold green]" if self.follow_tail else " [bold yellow]⏸ 滚动挂起 (按 G 键恢复最新行追尾)[/bold yellow]"
        title = f" 数据包列表 (当前: {len(self.filtered_packets)}/{len(self.all_packets)}){status_flag} "
        return Panel(table, title=title, border_style="sky_blue3", box=box.ROUNDED)

    def generate_hex_dump(self, raw_bytes):
        """安全生成格式美观的 16 进制及 ASCII 码对照载荷区"""
        text = Text()
        for i in range(0, len(raw_bytes), 16):
            chunk = raw_bytes[i:i+16]
            text.append(f"{i:04x}  ", style="yellow")
            hex_str = " ".join(f"{b:02x}" for b in chunk)
            text.append(f"{hex_str:<47}", style="default")
            text.append("  | ", style="default")
            for b in chunk:
                char = chr(b) if 32 <= b < 127 else "."
                text.append(char, style="cyan")
            text.append("\n")
        return text

    def generate_packet_detail_panel(self):
        """渲染右侧的详细报文解析（协议树 + 自适应载荷 Hex 视图）"""
        if not self.filtered_packets:
            return Panel(Align.center("\n\n无数据包", vertical="middle"), title=" 详细解析 ", border_style="grey50", box=box.ROUNDED)

        current_pkt = self.filtered_packets[self.selected_idx]["raw"]
        root_tree = Tree("[bold green]Frame (数据帧)[/bold green]")
        
        temp_layer = current_pkt
        while temp_layer:
            layer_name = temp_layer.name
            layer_tree = root_tree.add(f"[bold yellow]{layer_name}[/bold yellow]")
            for field_name, val in temp_layer.fields.items():
                node_text = Text()
                node_text.append(str(field_name), style="white")
                node_text.append(": ", style="default")
                node_text.append(str(val), style="cyan")
                layer_tree.add(node_text)
            temp_layer = temp_layer.payload if hasattr(temp_layer, 'payload') and temp_layer.payload and temp_layer.payload.name != "NoPayload" else None

        raw_bytes = bytes(current_pkt)
        hex_dump_text = self.generate_hex_dump(raw_bytes)

        detail_table = Table.grid(expand=True)
        detail_table.add_row(root_tree)
        detail_table.add_row(Rule("(Hex Dump)", style="grey50"))
        detail_table.add_row(hex_dump_text)

        pkt_id = self.filtered_packets[self.selected_idx]["id"]
        return Panel(detail_table, title=f" 详细解析 - 编号 #{pkt_id} ", border_style="gold1", box=box.ROUNDED)

    def generate_filter_bar(self):
        """安全生成底部控制与输入状态栏"""
        if self.is_filtering:
            cursor = "█" if int(time.time() * 2) % 2 == 0 else " "
            input_area = Text()
            input_area.append("🔍 过滤条件 ", style="default")
            input_area.append(">>> ", style="bold green")
            input_area.append(self.filter_text, style="yellow")
            input_area.append(cursor, style="default")
            
            if self.filter_error:
                input_area.append(" [语法错误!]", style="bold red")
                
            border_color = "green"
            guide = "[Tab] 轮播/自动补全 | [Enter] 搜索锁定 | [ESC] 取消"
        else:
            input_area = Text()
            input_area.append("🔍 过滤条件 (按 ", style="default")
            input_area.append("/", style="bold cyan")
            input_area.append(" 键编辑): ", style="default")
            input_area.append(self.filter_text if self.filter_text else "无过滤", style="yellow")
            
            border_color = "sky_blue3"
            guide = "[↑/↓]/[鼠标] 选中行 | [G] 最新追加 | [/] 过滤 | [Q] 退出"

        grid = Table.grid(expand=True)
        grid.add_column(ratio=2)
        grid.add_column(ratio=1, justify="right")
        grid.add_row(input_area, Text(guide, style="grey50"))

        return Panel(grid, border_style=border_color, title=" 交互过滤面板 ", box=box.ROUNDED)

    def run_tui(self):
        """启动高度稳定、支持实时键盘输入与鼠标点击的 TUI 渲染和交互大循环"""
        last_width, last_height = self.console.size
        needs_update = True
        last_blink_time = time.time()
        last_file_poll_time = time.time()

        if os.name != 'nt':
            import termios
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            new_settings = termios.tcgetattr(fd)
            new_settings[3] = new_settings[3] & ~termios.ICANON & ~termios.ECHO
            new_settings[6][termios.VMIN] = 1
            new_settings[6][termios.VTIME] = 0
            termios.tcsetattr(fd, termios.TCSADRAIN, new_settings)
            
            sys.stdout.write("\x1b[?1000h")
            sys.stdout.flush()

        try:
            with Live(self.layout, screen=True, auto_refresh=False) as live:
                while True:
                    current_time = time.time()

                    # 1. 监测窗口大小变化
                    current_width, current_height = self.console.size
                    if current_width != last_width or current_height != last_height:
                        last_width, last_height = current_width, current_height
                        needs_update = True

                    # 2. 定时轮询外部文件写入
                    if current_time - last_file_poll_time >= 0.5:
                        last_file_poll_time = current_time
                        if self.load_pcap(is_initial=False):
                            needs_update = True

                    # 3. 控制过滤编辑模式下的光标闪烁
                    if self.is_filtering:
                        if current_time - last_blink_time >= 0.4:
                            last_blink_time = current_time
                            needs_update = True

                    # 4. 动态渲染
                    if needs_update:
                        self.layout["packet_list"].update(self.generate_packet_list_table(current_height))
                        self.layout["packet_detail"].update(self.generate_packet_detail_panel())
                        self.layout["lower"].update(self.generate_filter_bar())
                        live.refresh()
                        needs_update = False

                    # 5. 读取按键事件
                    key = get_key()
                    if key is None:
                        time.sleep(0.01)
                        continue

                    needs_update = True

                    # 鼠标事件响应
                    if isinstance(key, tuple) and key[0] == "click":
                        cx, cy = key[1], key[2]
                        list_panel_width = int(current_width * 3 / 5)
                        visible_rows = max(3, current_height - 7)
                        
                        if cx < list_panel_width and 4 <= cy < 4 + visible_rows:
                            clicked_visible_row = cy - 4
                            clicked_idx = self.scroll_offset + clicked_visible_row
                            if clicked_idx < len(self.filtered_packets):
                                self.selected_idx = clicked_idx
                                self.follow_tail = False

                    elif self.is_filtering:
                        # 📝 过滤输入模式
                        if key in ("up", "down"):
                            continue
                        elif key == "enter":
                            self.is_filtering = False
                            self.reset_completion_state()
                            self.apply_filter()
                        elif key == "esc":
                            self.is_filtering = False
                            self.reset_completion_state()
                        elif key == "tab":
                            # 🎯 触发自动补全引擎
                            self.exec_autocomplete()
                        elif key == "backspace":
                            self.filter_text = self.filter_text[:-1]
                            self.reset_completion_state()  # 输入发生改变，重置匹配状态
                        else:
                            if len(key) == 1 and key.isprintable():
                                self.filter_text += key
                                self.reset_completion_state()  # 输入发生改变，重置匹配状态
                    else:
                        # 🔍 正常报文浏览模式
                        if key == "up":
                            if self.selected_idx > 0:
                                self.selected_idx -= 1
                                self.follow_tail = False
                        elif key == "down":
                            if self.selected_idx < len(self.filtered_packets) - 1:
                                self.selected_idx += 1
                                if self.selected_idx == len(self.filtered_packets) - 1:
                                    self.follow_tail = True
                        elif key.lower() == "g":
                            self.follow_tail = True
                            if self.filtered_packets:
                                self.selected_idx = len(self.filtered_packets) - 1
                        elif key == "/":
                            self.is_filtering = True
                            self.reset_completion_state()
                            last_blink_time = time.time()
                        elif key.lower() == "q":
                            break
        finally:
            if os.name != 'nt':
                sys.stdout.write("\x1b[?1000l")
                sys.stdout.flush()
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="🚀 终端 PCAP 动态分析器 (支持外部程序实时写入追尾)")
    parser.add_argument("pcap_file", nargs="?", default="../output.pcap", help="待解析的 .pcap 文件的路径")
    args = parser.parse_args()

    analyzer = PcapAnalyzer(args.pcap_file)
    analyzer.load_pcap(is_initial=True)
    
    try:
        analyzer.run_tui()
    except KeyboardInterrupt:
        pass
    finally:
        print("\n👋 感谢使用，已成功退出分析器。")


if __name__ == "__main__":
    main()