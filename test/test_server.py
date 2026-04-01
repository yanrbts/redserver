import argparse
import logging
import socket
import struct
import time
import zlib
import hmac
import hashlib
import asyncio
import json
import psutil
from datetime import datetime, timezone
from typing import Tuple, Optional, Callable, Dict

# ==============================
# 配置与常量 (保持你的定义)
# ==============================
DEFAULT_PORT = 52719
HDR_SIZE = 12
TYPE_DATA = 0x6789  
SYMBOL = b'5G'
GC_FIND, GC_REGISTER, GC_HEARBEAT = 0x01, 0x02, 0x03
GC_REQ, GC_RESP = 0x01, 0x02
H_FMT = "!2sBBBBH"
ETH_HDR_SIZE = 14
ETH_TYPE_EXPECTED = 0x0857

LOG_FORMAT = '[%(asctime)s] %(levelname)-5s | %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger('UnifiedServer')

# ==============================
# 1. 探测逻辑执行器
# ==============================
class ProbeExecutor:
    def __init__(self):
        self.server_ip, self.server_mac = self._get_sys_info()

    def _get_sys_info(self):
        for interface, snics in psutil.net_if_addrs().items():
            if interface == 'lo' or 'loopback' in interface.lower(): continue
            ip, mac = None, None
            for snic in snics:
                if snic.family == socket.AF_INET: ip = snic.address
                elif snic.family == psutil.AF_LINK:
                    mac_str = snic.address.replace('-', ':')
                    mac = bytes([int(x, 16) for x in mac_str.split(':')])
            if ip and mac: return ip, mac
        return "127.0.0.1", b'\x00'*6

    def build_outer_packet(self, inner_header: bytes, inner_payload: bytes, type16: int, auth32: int) -> bytes:
        full_inner = inner_header + inner_payload
        len16 = HDR_SIZE + ETH_HDR_SIZE + len(full_inner)
        outer_header = struct.pack('>HHII', type16, len16, auth32, 0)
        ether_header = bytes(12) + struct.pack('>H', 0x0857)
        full_packet_temp = outer_header + ether_header + full_inner
        temp_packet = bytearray(full_packet_temp)
        temp_packet[8:12] = b'\x00\x00\x00\x00'
        crc = zlib.crc32(temp_packet) & 0xFFFFFFFF
        final_packet = bytearray(full_packet_temp)
        final_packet[8:12] = struct.pack('>I', crc)
        return bytes(final_packet)

    def run(self, data: bytes, addr: tuple, transport, auth32):
        inner_start = HDR_SIZE + ETH_HDR_SIZE
        symbol, ver, cls, subtype, empty, msgno = struct.unpack(H_FMT, data[inner_start:inner_start+8])
        
        if cls == GC_FIND and subtype == GC_REQ:
            logger.info(f"[Probe] RECV FIND from {addr}")
            inner_payload = self.server_mac + b'\x00' + socket.inet_aton(self.server_ip)
            inner_header = struct.pack(H_FMT, SYMBOL, 1, GC_FIND, GC_RESP, 0, msgno)
            pkt = self.build_outer_packet(inner_header, inner_payload, TYPE_DATA, auth32)
            transport.sendto(pkt, (addr[0], DEFAULT_PORT))

        elif cls == GC_REGISTER and subtype == GC_REQ:
            logger.info(f"[Probe] RECV REGISTER from {addr}")
            inner_header = struct.pack(H_FMT, SYMBOL, 1, GC_REGISTER, GC_RESP, 0, msgno)
            pkt = self.build_outer_packet(inner_header, b'\x00', TYPE_DATA, auth32)
            transport.sendto(pkt, (addr[0], DEFAULT_PORT))

        elif cls == GC_HEARBEAT and subtype == GC_REQ:
            client_tm = data[inner_start+8:inner_start+12]
            inner_header = struct.pack(H_FMT, SYMBOL, 1, GC_HEARBEAT, GC_RESP, 0, msgno)
            pkt = self.build_outer_packet(inner_header, client_tm, TYPE_DATA, auth32)
            transport.sendto(pkt, (addr[0], DEFAULT_PORT))

# ==============================
# 2. BlackServer (你的原始类，完全不动)
# ==============================
class ProtocolError(Exception):
    pass

class BlackServer(asyncio.DatagramProtocol):
    def __init__(self, shared_key: bytes):
        self.shared_key = shared_key
        self.transport = None
        self.probe_executor = ProbeExecutor() # 内部集成探测执行器

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """ UDP 接收核心分发器：在这里做路由，不改动你下面的业务逻辑 """
        if not data or len(data) < HDR_SIZE:
            return

        try:
            # 基础解析用于路由
            type16, len16, auth32, crc32 = struct.unpack('>HHII', data[:HDR_SIZE])
            
            # --- 路由判断 ---
            inner_tag_pos = HDR_SIZE + ETH_HDR_SIZE
            if len(data) > inner_tag_pos + 2 and data[inner_tag_pos:inner_tag_pos+2] == SYMBOL:
                # 命中探测包标识 '5G'，执行探测逻辑
                self.probe_executor.run(data, addr, self.transport, auth32)
            else:
                # 否则，完全执行原有的业务处理流程
                self._process_auth_packet(data, addr)
        except Exception as e:
            logger.error(f"Routing Error: {e}")

    def _process_auth_packet(self, data: bytes, addr: tuple):
        if len(data) < HDR_SIZE:
            logger.warning(f"包太短 ({len(data)} 字节)，来自 {addr}")
            return
        try:
            logger.info(f"RAW RECEIVE ({len(data)} bytes): {data.hex(' ')[:47].upper()}")
            type16, len16, auth32, crc32 = self.parse_header(data[:HDR_SIZE])
            if len(data) != len16:
                raise ProtocolError(f"长度不匹配: 实际 {len(data)}，Len16={len16}")
            if not self.verify_full_crc(data, crc32):
                raise ProtocolError("全包 CRC 校验失败")
            if type16 == TYPE_DATA:
                self.unpack_tunneled_packet(data, addr)
        except ProtocolError as e:
            logger.warning(f"协议错误: {e} 来自 {addr}")
        except Exception as e:
            logger.exception(f"处理包失败: {e} 来自 {addr}")

    def unpack_tunneled_packet(self, data: bytes, addr: tuple):
        try:
            GAP_METHOD_LEN = 6
            GAP_URL_LEN = 128
            a_type, a_len, a_auth, a_crc = struct.unpack('>HHII', data[0:12])
            eth_s = 12
            d_mac = ":".join(f"{b:02x}" for b in data[eth_s:eth_s + 6])
            s_mac = ":".join(f"{b:02x}" for b in data[eth_s + 6:eth_s + 12])
            ip_s = 26
            s_ip = socket.inet_ntoa(data[ip_s + 12: ip_s + 16])
            d_ip = socket.inet_ntoa(data[ip_s + 16: ip_s + 20])
            u_s = 46
            sp, dp, u_l, _ = struct.unpack('>HHHH', data[u_s: u_s + 8])
            in_s = 54
            d_len, num, total, rcp = struct.unpack('>HBHB', data[in_s: in_s + 6])
            m_s = in_s + 6
            method = data[m_s: m_s + GAP_METHOD_LEN].strip(b'\x00').decode('utf-8')
            url_s = m_s + GAP_METHOD_LEN
            url = data[url_s: url_s + GAP_URL_LEN].strip(b'\x00').decode('utf-8')
            json_s = url_s + GAP_URL_LEN
            json_data = data[json_s: json_s + d_len].decode('utf-8')

            print(f"\n┌─ [剥洋葱解析] AuthID: 0x{a_auth:08x} 长度: {a_len}")
            print(f"│ [MAC] {s_mac} -> {d_mac}")
            print(f"│ [IP ] {s_ip} -> {d_ip} | Port: {sp} -> {dp}")
            print(f"│ [Bus] Method: {method} | URL: {url} | Fragment: {num}/{total}")
            print(f"└─ [JSON] {json_data}")

            response_message = '{"status":"success", "message":"Received by Black Side"}'
            self.send_back_to_red(addr, data, response_message)
        except Exception as e:
            logger.error(f"解析偏移错误: {e}")

    def send_back_to_red(self, addr: tuple, original_data: bytes, response_json: str):
        try:
            in_s = 54
            _, _, _, orig_rcp = struct.unpack('>HBHB', original_data[in_s: in_s + 6])
            mock_response = {
                "status": "ok",
                "code": 200,
                "message": "BlackServer: Request processed successfully",
                "rcp_id": orig_rcp,
                "server_time": int(time.time())
            }
            json_bytes = json.dumps(mock_response).encode('utf-8')
            GAP_METHOD_LEN = 6
            GAP_URL_LEN = 128
            orig_eth = original_data[12:26]
            orig_d_mac, orig_s_mac = orig_eth[0:6], orig_eth[6:12]
            orig_ip_hdr = original_data[26:46]
            orig_s_ip, orig_d_ip = orig_ip_hdr[12:16], orig_ip_hdr[16:20]
            orig_sp, orig_dp = struct.unpack('>HH', original_data[46:50])

            new_eth_hdr = orig_s_mac + orig_d_mac + b'\x08\x00'
            new_ip_hdr = bytearray(orig_ip_hdr)
            new_ip_hdr[12:16], new_ip_hdr[16:20] = orig_d_ip, orig_s_ip
            
            inner_data_hdr = struct.pack('>HBHB', len(json_bytes), 1, 1, orig_rcp)
            res_method = b"POST".ljust(GAP_METHOD_LEN, b'\x00')
            res_url = b"/api/v1/response".ljust(GAP_URL_LEN, b'\x00')
            full_inner_hdr = inner_data_hdr + res_method + res_url
            new_udp_len = 8 + len(full_inner_hdr) + len(json_bytes)
            new_udp_hdr = struct.pack('>HHHH', orig_dp, orig_sp, new_udp_len, 0)
            full_len = 12 + 14 + 20 + 8 + len(full_inner_hdr) + len(json_bytes)
            inner_content = new_eth_hdr + bytes(new_ip_hdr) + new_udp_hdr + full_inner_hdr + json_bytes
            auth_val = self.calc_auth(TYPE_DATA, full_len, inner_content)
            pre_hdr = struct.pack('>HHII', TYPE_DATA, full_len, auth_val, 0)
            final_crc = zlib.crc32(pre_hdr + inner_content) & 0xFFFFFFFF
            resp_packet = struct.pack('>HHII', TYPE_DATA, full_len, auth_val, final_crc) + inner_content
            
            self.transport.sendto(resp_packet, (addr[0], DEFAULT_PORT))
            logger.info(f"成功回传响应 | rcpId: {orig_rcp}")
        except Exception as e:
            logger.error(f"Failed to build response: {e}")

    @staticmethod
    def parse_header(hdr: bytes) -> Tuple[int, int, int, int]:
        return struct.unpack('>HHII', hdr)

    def verify_full_crc(self, full_data: bytes, stored_crc: int) -> bool:
        temp_data = bytearray(full_data)
        temp_data[8:12] = [0, 0, 0, 0]
        return (zlib.crc32(temp_data) & 0xFFFFFFFF) == stored_crc

    def calc_auth(self, type16: int, len16: int, payload: bytes) -> int:
        data = struct.pack('>HH', type16, len16) + payload
        return struct.unpack('>I', hmac.new(self.shared_key, data, hashlib.sha256).digest()[:4])[0]

# ==============================
# 启动逻辑
# ==============================
async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default='0.0.0.0')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT)
    parser.add_argument('--key', default='secret_shared_key_lrm_2026')
    args = parser.parse_args()

    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: BlackServer(args.key.encode('utf-8')),
        local_addr=(args.host, args.port)
    )
    logger.info(f"Unified Server started on {args.host}:{args.port}")
    await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())