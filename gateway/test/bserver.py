#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Copyright (c) 2026-2026, Red LRM.
Author: [yanruibing]
All rights reserved.

High-Performance Layer-2/Layer-4 Topology Mirroring & Decapsulation Engine.
Perfectly cross-aligned with C-Gateway 'hdr_t' structural primitives.
"""

import socket
import struct
import zlib
import sys
import time
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

# ==========================================
# 🌟 全局协议常量对齐
# ==========================================
TYPE_DATA = 0x6789       # 你的自定义协议 sovereign 类型码
AUTH_TOKEN = 0xABCDEFFF   # 你的安全校验令牌签名

class RedLrmTestServer(DatagramProtocol):
    maxPacketSize = 65535
    
    def startProtocol(self):
        # 🌟 核心修复：强行撑开 Python 底层套接字的发送缓冲区到 16MB
        try:
            from twisted.internet.fdesc import _setCloseOnExec
            # 获取原生的 socket 对象
            sock = self.transport.getHandle()
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16777216)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16777216)
            print("[+] Successfully raised OS UDP buffers to 16MB.")
        except Exception as e:
            print(f"[-] Failed to set socket options: {e}")
        print(f"[+] Red LRM Test Server initialized and listening on port {self.transport.getHost().port}...")

    def calc_auth(self, msg_type, full_len, payload):
        """模拟你的安全指纹计算函数"""
        return AUTH_TOKEN

    def datagramReceived(self, data, addr):
        """
        核心接收阵列回调
        data 布局: [12B 网关头] + [原始客户端以太网帧(Eth + IP + UDP + 业务数据)]
        """
        try:
            # 1. 边界防御与外部 12 字节网关头解包
            if len(data) < 12:
                print("[-] Dropped packet: smaller than 12-byte gateway header.")
                return

            gw_type, gw_len, gw_auth, gw_crc = struct.unpack('>HHII', data[:12])
            inner_ethernet_packet = data[12:]
            
            if len(inner_ethernet_packet) < 42:
                print("[-] Dropped packet: Layer-2 payload is corrupted or truncated.")
                return
            
            # =======================================================================
            # 🌟 新增：零破坏型接收数据高清打印桩（仅做打印，不改动任何数据）
            # =======================================================================
            # print("-" * 70)
            print(f"[←] Incoming Raw Data from {addr[0]}:{addr[1]} | Wire Length: {len(data)} bytes")
            # print(f"    [Gateway Header] Type: 0x{gw_type:04X} | Len: {gw_len} | Auth: 0x{gw_auth:08X} | CRC: 0x{gw_crc:08X}")
            
            # # 以 16 字节为一行进行优雅的 Hex / ASCII 对齐查看
            # print("    [Hex Dump]:")
            # for i in range(0, len(data), 16):
            #     chunk = data[i:i+16]
            #     hex_str = " ".join(f"{b:02x}" for b in chunk)
            #     ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            #     print(f"        {i:04x}:  {hex_str:<48}  |{ascii_str}|")
            # print("-" * 70)
            # =======================================================================

            # 2. 精准剥离与镜像对调以太网二层 (MAC)
            orig_eth_hdr = inner_ethernet_packet[0:14]
            orig_dst_mac = orig_eth_hdr[0:6]
            orig_src_mac = orig_eth_hdr[6:12]
            ether_type = orig_eth_hdr[12:14]

            new_eth_hdr = orig_src_mac + orig_dst_mac + ether_type

            # 3. 精准剥离与镜像对调网络三层 (IP)
            ip_start = 14
            orig_ip_hdr = inner_ethernet_packet[ip_start : ip_start + 20]
            orig_src_ip = orig_ip_hdr[12:16]
            orig_dst_ip = orig_ip_hdr[16:20]

            new_ip_hdr_view = bytearray(orig_ip_hdr)
            new_ip_hdr_view[12:16] = orig_dst_ip
            new_ip_hdr_view[16:20] = orig_src_ip
            new_ip_hdr_view[10:12] = b'\x00\x00' 
            new_ip_hdr = bytes(new_ip_hdr_view)

            # 4. 精准剥离与镜像对调传输四层 (UDP)
            udp_start = 34
            orig_udp_hdr = inner_ethernet_packet[udp_start : udp_start + 8]
            orig_src_port, orig_dst_port = struct.unpack('>HH', orig_udp_hdr[0:4])
            app_payload = inner_ethernet_packet[udp_start + 8 :]

            new_udp_len = 8 + len(app_payload)
            new_udp_hdr = struct.pack('>HHHH', orig_dst_port, orig_src_port, new_udp_len, 0)

            # 5. 线性流水线闭环：重新封装成完整的反向以太网资产
            new_inner_content = new_eth_hdr + new_ip_hdr + new_udp_hdr + app_payload
            full_len = 12 + len(new_inner_content)
            
            # 6. 计算安全验证码
            auth_val = self.calc_auth(TYPE_DATA, full_len, new_inner_content)
            
            # 严格按照 C 语言定义的结构体，生成 CRC 清零的大端预备头
            pre_hdr = struct.pack('>HHII', TYPE_DATA, full_len, auth_val, 0)
            final_crc = zlib.crc32(pre_hdr + new_inner_content) & 0xFFFFFFFF
            
            # 7. 生成最终发往 C 语言网关的反向数据流报文
            resp_packet = struct.pack('>HHII', TYPE_DATA, full_len, auth_val, final_crc) + new_inner_content
            
            # 🌟 核心修复：Twisted 使用 write 代替 sendto 发送 UDP
            self.transport.write(resp_packet, addr)
            
            print(f"[⇄] Swapped & Injected packet: Type=0x{gw_type:04X} TotalLen={full_len} "
                  f"InnerAppLen={len(app_payload)}B -> Returned to Gateway {addr[0]}:{addr[1]}")

        except Exception as e:
            print(f"[-] Critical exception during pipeline stream tracking: {e}", file=sys.stderr)

# ==========================================
# 🚀 守护进程点火启动
# ==========================================
if __name__ == "__main__":
    # 绑定监听在你日志里出现的 52719 端口
    BIND_PORT = 52719
    
    reactor.listenUDP(BIND_PORT, RedLrmTestServer())
    try:
        reactor.run()
    except KeyboardInterrupt:
        print("\n[-] Server shutdown gracefully.")