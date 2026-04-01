import argparse
import logging
import socket
import struct
import threading
import time
import zlib
import hmac
import hashlib
from typing import Tuple, Optional, Callable, Dict
import asyncio
import json

# ==============================
# 配置与常量
# ==============================
DEFAULT_PORT = 52719
HDR_SIZE = 12
TYPE_DATA = 0x6789       # 普通业务包（下发/上报）

LOG_FORMAT = '[%(asctime)s] %(levelname)-5s | %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger('BlackServer')


class ProtocolError(Exception):
    """协议相关异常"""
    pass

class BlackServer(asyncio.DatagramProtocol):
    """ black server """

    def __init__(self, shared_key: bytes):
        self.shared_key = shared_key
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """ UDP 接收核心分发器 """
        if not data:
            return
        self._process_auth_packet(data, addr)
    
    def _process_auth_packet(self, data: bytes, addr: tuple):
        """处理单个接收到的 UDP 包"""
        if len(data) < HDR_SIZE:
            logger.warning(f"包太短 ({len(data)} 字节)，来自 {addr}")
            return

        try:
            logger.info(f"RAW RECEIVE ({len(data)} bytes): {data.hex(' ')[:47].upper()}")
            type16, len16, auth32, crc32 = self.parse_header(data[:HDR_SIZE])

            # 长度一致性校验
            if len(data) != len16:
                raise ProtocolError(f"长度不匹配: 实际 {len(data)}，Len16={len16}")

            # 全包 CRC 校验（关键修改）
            if not self.verify_full_crc(data, crc32):
                raise ProtocolError("全包 CRC 校验失败")

            payload = data[HDR_SIZE:len16] if len16 > HDR_SIZE else b''

            logger.debug(f"收到 {addr} -> type={hex(type16)}, len16={len16}, payload_len={len(payload)}")

            if type16 == TYPE_DATA:
                self.unpack_tunneled_packet(data, addr)
        except ProtocolError as e:
            logger.warning(f"协议错误: {e} 来自 {addr}")
        except Exception as e:
            logger.exception(f"处理包失败: {e} 来自 {addr}")
    
    def unpack_tunneled_packet(self, data: bytes, addr: tuple):
        """
        按照 C 结构体定义的绝对偏移量进行剥洋葱解析
        """
        try:
            # --- 宏定义校准 ---
            GAP_METHOD_LEN = 6
            GAP_URL_LEN = 128

            # --- 层 1: Auth (0-12) ---
            # 此时 data[0:2] 应该是 0x67 0x89
            a_type, a_len, a_auth, a_crc = struct.unpack('>HHII', data[0:12])

            # --- 层 2: Eth (12-26) ---
            eth_s = 12
            d_mac = ":".join(f"{b:02x}" for b in data[eth_s:eth_s + 6])
            s_mac = ":".join(f"{b:02x}" for b in data[eth_s + 6:eth_s + 12])

            # --- 层 3: IP (26-46) ---
            ip_s = 26
            s_ip = socket.inet_ntoa(data[ip_s + 12: ip_s + 16])
            d_ip = socket.inet_ntoa(data[ip_s + 16: ip_s + 20])

            # --- 层 4: UDP (46-54) ---
            u_s = 46
            sp, dp, u_l, _ = struct.unpack('>HHHH', data[u_s: u_s + 8])

            # --- 层 5: InnerData (54 开始) ---
            in_s = 54
            # 结构: dataLen(2)+num(1)+total(2)+rcpId(1)
            d_len, num, total, rcp = struct.unpack('>HBHB', data[in_s: in_s + 6])

            # Method 偏移 = 54 + 6 = 60
            m_s = in_s + 6
            method = data[m_s: m_s + GAP_METHOD_LEN].strip(b'\x00').decode('utf-8')

            # URL 偏移 = 60 + 6 = 66
            url_s = m_s + GAP_METHOD_LEN
            url = data[url_s: url_s + GAP_URL_LEN].strip(b'\x00').decode('utf-8')

            # --- 层 6: JSON Payload ---
            # 起点 = 66 + 128 = 194
            json_s = url_s + GAP_URL_LEN
            json_data = data[json_s: json_s + d_len].decode('utf-8')

            # --- 格式化打印 ---
            print(f"\n┌─ [剥洋葱解析] AuthID: 0x{a_auth:08x} 长度: {a_len}")
            print(f"│ [MAC] {s_mac} -> {d_mac}")
            print(f"│ [IP ] {s_ip} -> {d_ip} | Port: {sp} -> {dp}")
            print(f"│ [Bus] Method: {method} | URL: {url} | Fragment: {num}/{total}")
            print(f"└─ [JSON] {json_data}")

            response_message = '{"status":"success", "message":"Received by Black Side"}'
            self.send_back_to_red(addr, data, response_message)
        except Exception as e:
            # 如果报错，通常是由于传入的 data 依然不是从 0x6789 开始的
            logger.error(f"解析偏移错误: {e}. 检查 _process_packet 的传参！")
    
    # def send_back_to_red(self, addr: tuple, original_data: bytes, response_json: str):
    #     """
    #     Constructs a tunnel packet to send data back from Black -> Red.
    #     Matches the C struct: tunnel_payload_t
    #     """
    #     try:
    #         # 1. Prepare business data (JSON)
    #         json_bytes = response_json.encode('utf-8')
            
    #         # 2. Extract original headers to swap Src/Dst (Absolute Offsets)
    #         # Offset 12: Ethernet (14 bytes)
    #         # Offset 26: IP (20 bytes)
    #         # Offset 46: UDP (8 bytes)
            
    #         # --- Extract Ethernet ---
    #         orig_eth = original_data[12:26]
    #         orig_d_mac = orig_eth[0:6]
    #         orig_s_mac = orig_eth[6:12]
            
    #         # --- Extract IP ---
    #         orig_ip_hdr = original_data[26:46]
    #         orig_s_ip = orig_ip_hdr[12:16]
    #         orig_d_ip = orig_ip_hdr[16:20]
            
    #         # --- Extract UDP Ports ---
    #         # orig_sp is the "Proxy Port" (e.g., 12147) allocated by Red Zone
    #         orig_sp, orig_dp = struct.unpack('>HH', original_data[46:50])

    #         # 3. Build Swapped Layers
    #         # Eth: NewDst = OrigSrc, NewSrc = OrigDst
    #         new_eth_hdr = orig_s_mac + orig_d_mac + b'\x08\x00'
            
    #         # IP: Swap IPs
    #         new_ip_hdr = bytearray(orig_ip_hdr)
    #         new_ip_hdr[12:16] = orig_d_ip # New Source is Black's IP
    #         new_ip_hdr[16:20] = orig_s_ip # New Dest is Red's IP
            
    #         # UDP: CRITICAL STEP - Swap Ports
    #         # The Proxy Port (12147) MUST be in the destination field for Red to find the NAT entry
    #         new_udp_hdr = struct.pack('>HHHH', orig_dp, orig_sp, 8 + len(json_bytes), 0)

    #         # 4. Auth Layer Header (Outer)
    #         # Total size: 12 (AuthHdr) + 14 (Eth) + 20 (IP) + 8 (UDP) + payload
    #         full_len = 12 + 14 + 20 + 8 + len(json_bytes)
            
    #         # Calculate Auth (HMAC) on all layers following the 12-byte Auth header
    #         inner_content = new_eth_hdr + new_ip_hdr + new_udp_hdr + json_bytes
    #         auth_val = self.calc_auth(TYPE_DATA, full_len, inner_content)
            
    #         # 5. Final Assembly with CRC32
    #         # Pack with CRC=0 first to calculate the real CRC
    #         pre_hdr = struct.pack('>HHII', TYPE_DATA, full_len, auth_val, 0)
    #         full_packet_temp = pre_hdr + inner_content
            
    #         final_crc = zlib.crc32(full_packet_temp) & 0xFFFFFFFF
    #         final_hdr = struct.pack('>HHII', TYPE_DATA, full_len, auth_val, final_crc)
            
    #         # Final binary packet
    #         resp_packet = final_hdr + inner_content
            
    #         RED_ZONE_PORT = 52719 
    #         target_addr = (addr[0], RED_ZONE_PORT) 
            
    #         temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #         try:
    #             # 如果是发给本机，addr[0] 会是 127.0.0.1
    #             temp_sock.sendto(resp_packet, target_addr)
    #             logger.info(f"回传包已发出 -> {target_addr} | 代理端口: {orig_sp}")
    #         finally:
    #             temp_sock.close()

    #         # if self.transport:
    #         #     self.transport.sendto(resp_packet, target_addr)
    #         #     logger.info(f"回传包已发出 -> {target_addr} | 代理端口: {orig_sp}")

    #     except Exception as e:
    #         logger.error(f"Failed to build response: {e}")


    def send_back_to_red(self, addr: tuple, original_data: bytes, response_json: str):
        """
        构造从 Black -> Red 的完整隧道响应包。
        包含：Auth(12) + Eth(14) + IP(20) + UDP(8) + InnerData(140) + JSON Payload
        """
        try:
            # --- 1. 准备模拟的成功响应 JSON ---
            # 提取原始 rcpId (根据你的偏移量 54+5=59 字节处是 rcpId)
            in_s = 54
            _, _, _, orig_rcp = struct.unpack('>HBHB', original_data[in_s: in_s + 6])
            
            # 构造模拟数据
            mock_response = {
                "status": "ok",
                "code": 200,
                "message": "BlackServer: Request processed successfully",
                "rcp_id": orig_rcp,
                "server_time": int(time.time())
            }
            json_bytes = json.dumps(mock_response).encode('utf-8')
            
            # --- 2. 宏定义校准 ---
            GAP_METHOD_LEN = 6
            GAP_URL_LEN = 128

            # --- 3. 提取原始头部以交换源/目 ---
            orig_eth = original_data[12:26]
            orig_d_mac = orig_eth[0:6]
            orig_s_mac = orig_eth[6:12]
            
            orig_ip_hdr = original_data[26:46]
            orig_s_ip = orig_ip_hdr[12:16]
            orig_d_ip = orig_ip_hdr[16:20]
            
            orig_sp, orig_dp = struct.unpack('>HH', original_data[46:50])

            # --- 4. 构建交换后的协议层 ---
            new_eth_hdr = orig_s_mac + orig_d_mac + b'\x08\x00'
            
            new_ip_hdr = bytearray(orig_ip_hdr)
            new_ip_hdr[12:16] = orig_d_ip 
            new_ip_hdr[16:20] = orig_s_ip 
            
            # --- 5. 构造 InnerData 业务头 (140字节) ---
            # 结构: dataLen(2)+num(1)+total(2)+rcpId(1)
            inner_data_hdr = struct.pack('>HBHB', 
                len(json_bytes), # dataLen
                1,               # num
                1,               # total
                orig_rcp         # rcpId
            )
            res_method = b"POST".ljust(GAP_METHOD_LEN, b'\x00')
            res_url = b"/api/v1/response".ljust(GAP_URL_LEN, b'\x00')
            full_inner_hdr = inner_data_hdr + res_method + res_url

            # --- 6. UDP Header ---
            # 长度 = 8(UDP) + 140(InnerHdr) + JSON长度
            new_udp_len = 8 + len(full_inner_hdr) + len(json_bytes)
            new_udp_hdr = struct.pack('>HHHH', orig_dp, orig_sp, new_udp_len, 0)

            # --- 7. Auth Layer Header & Total Length ---
            # 总长度 = 12(Auth) + 14(Eth) + 20(IP) + 8(UDP) + 140(Inner) + Payload
            full_len = 12 + 14 + 20 + 8 + len(full_inner_hdr) + len(json_bytes)
            
            inner_content = new_eth_hdr + bytes(new_ip_hdr) + new_udp_hdr + full_inner_hdr + json_bytes
            
            auth_val = self.calc_auth(TYPE_DATA, full_len, inner_content)
            
            # --- 8. CRC32 计算 ---
            pre_hdr = struct.pack('>HHII', TYPE_DATA, full_len, auth_val, 0)
            final_crc = zlib.crc32(pre_hdr + inner_content) & 0xFFFFFFFF
            final_hdr = struct.pack('>HHII', TYPE_DATA, full_len, auth_val, final_crc)
            
            # 最终二进制包
            resp_packet = final_hdr + inner_content
            
            # --- 9. 发送回红区 ---
            RED_ZONE_PORT = 52719 
            target_addr = (addr[0], RED_ZONE_PORT) 
            
            temp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                temp_sock.sendto(resp_packet, target_addr)
                logger.info(f"成功回传响应 | rcpId: {orig_rcp} | Payload: {len(json_bytes)} bytes")
            finally:
                temp_sock.close()

        except Exception as e:
            logger.error(f"Failed to build response: {e}")


    
    def _handle_data_packet(self, payload: bytes, addr: tuple):
        """处理普通业务包（填充 Auth）"""
        # 计算 Auth 时使用接收到的 Len16（已包含 HDR + payload）
        real_auth = self.calc_auth(TYPE_DATA, HDR_SIZE + len(payload), payload)

        new_hdr = self.build_header(TYPE_DATA, HDR_SIZE + len(payload), real_auth)

        # 填充 CRC（全包计算）
        pkt = new_hdr + payload
        temp_hdr = struct.pack('>HHII', TYPE_DATA, HDR_SIZE + len(payload), real_auth, 0)
        crc = zlib.crc32(temp_hdr + payload) & 0xFFFFFFFF
        new_hdr = struct.pack('>HHII', TYPE_DATA, HDR_SIZE + len(payload), real_auth, crc)
        pkt = new_hdr + payload

        # TODO: 下发到黑区或其他处理
        logger.info(f"data: {payload} 业务包已填充 Auth: 0x{real_auth:08x}，来自 {addr}")

    @staticmethod
    def parse_header(hdr: bytes) -> Tuple[int, int, int, int]:
        """解析 HDR，返回 (type16, len16, auth32, crc32)"""
        if len(hdr) != HDR_SIZE:
            raise ValueError(f"HDR 长度错误: {len(hdr)}")
        return struct.unpack('>HHII', hdr)

    def verify_full_crc(self, full_data: bytes, stored_crc: int) -> bool:
        """校验整个包的 CRC32（临时清零 CRC 字段）"""
        if len(full_data) < HDR_SIZE:
            return False

        # 拷贝数据，临时清零 CRC 字段 (字节 8-11)
        temp_data = bytearray(full_data)
        temp_data[8:12] = [0, 0, 0, 0]

        # 计算 CRC
        calc_crc = zlib.crc32(temp_data) & 0xFFFFFFFF
        return calc_crc == stored_crc

    def build_header(self, type16: int, len16: int, auth32: int = 0) -> bytes:
        """构建 HDR，Len16 为整个包长度，CRC 占位 0"""
        temp = struct.pack('>HHII', type16, len16, auth32, 0)
        # 先不计算 CRC（留给调用者全包计算）
        return temp

    def calc_auth(self, type16: int, len16: int, payload: bytes) -> int:
        """计算 Auth32 值"""
        data = struct.pack('>HH', type16, len16) + payload
        mac = hmac.new(self.shared_key, data, hashlib.sha256).digest()
        return struct.unpack('>I', mac[:4])[0]
    
async def main():
    # 命令行参数解析
    parser = argparse.ArgumentParser(description="黑区服务")
    parser.add_argument('--host', default='127.0.0.1', help='监听地址')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='监听端口')
    parser.add_argument('--key', default='secret_shared_key_lrm_2026', help='共享密钥')
    args = parser.parse_args()

    loop = asyncio.get_running_loop()
    
    logger.info(f"黑区服务启动: {args.host}:{args.port}")
    logger.info(f"共享密钥: {args.key}")

    # 启动异步监听端点
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: BlackServer(args.key.encode('utf-8')),
        local_addr=(args.host, args.port)
    )

    try:
        await asyncio.Future()  # 永久运行
    finally:
        transport.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("服务停止")


    