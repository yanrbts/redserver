import argparse
import asyncio
import logging
import struct
import zlib
import hmac
import hashlib
import time
from typing import Tuple

# 协议常量 (严格对齐你的代码)
PING_MAGIC = b'PING'
HB_FMT = '>4sIQ'          # Magic(4s), Seq(I), Timestamp(Q)
TYPE_AUTH_REQ = 0x6000    # Auth 申请请求
TYPE_AUTH_RESP = 0x6001   # Auth 响应
HDR_SIZE = 12             # Auth HDR 长度
DEFAULT_PORT = 48350

# 日志配置
LOG_FORMAT = '[%(asctime)s] %(levelname)-5s | %(message)s'
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT)
logger = logging.getLogger('CryptoMachine')

class CryptoServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, shared_key: bytes):
        self.shared_key = shared_key
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """ UDP 接收核心分发器 """
        if not data:
            return

        # 逻辑 1: 处理探测心跳 PING 并原样返回
        if data.startswith(PING_MAGIC):
            self._handle_heartbeat(data, addr)
            return

        # 逻辑 2: 处理 Auth 申请请求
        self._process_auth_packet(data, addr)

    def _handle_heartbeat(self, data: bytes, addr: tuple):
        """ 严格保持原样返回逻辑 """
        hb_size = struct.calcsize(HB_FMT)
        if len(data) < hb_size:
            return
        # 原样返回接收到的前 hb_size 字节
        self.transport.sendto(data[:hb_size], addr)

    def _process_auth_packet(self, data: bytes, addr: tuple):
        """ 严格保持你提供的 Auth 处理与校验逻辑 """
        if len(data) < HDR_SIZE:
            logger.warning(f"包太短 ({len(data)} 字节)，来自 {addr}")
            return

        try:
            # 1. 解析头部
            type16, len16, auth32, crc32 = struct.unpack('>HHII', data[:HDR_SIZE])

            # 2. 长度一致性校验
            if len(data) != len16:
                logger.warning(f"长度不匹配: 实际 {len(data)}, Len16={len16} 来自 {addr}")
                return

            # 3. 全包 CRC 校验 (拷贝数据并临时清零 CRC 字段)
            if not self.verify_full_crc(data, crc32):
                logger.warning(f"全包 CRC 校验失败 来自 {addr}")
                return

            # 4. 执行业务：处理 Auth 请求
            payload = data[HDR_SIZE:len16]
            self._handle_auth_request(payload, addr)

        except Exception as e:
            logger.error(f"处理包失败: {e} 来自 {addr}")

    def verify_full_crc(self, full_data: bytes, stored_crc: int) -> bool:
        """ 你的原始逻辑：拷贝数据 -> 临时清零 CRC 字段 -> 计算 CRC """
        temp_data = bytearray(full_data)
        temp_data[8:12] = b'\x00\x00\x00\x00'  # 清零 8-11 字节
        calc_crc = zlib.crc32(temp_data) & 0xFFFFFFFF
        return calc_crc == stored_crc

    def _handle_auth_request(self, payload: bytes, addr: tuple):
        # 引入当前时间因子（例如：每 300 秒跳变一次，与你 5 分钟刷新频率对齐）
        # time.time() // 300 会得到一个每 5 分钟才变一次的整数
        time_factor = int(time.time()) // 300 
        
        # 将时间因子拼入 HMAC 计算源
        # 即使 payload 为空，msg 也会随时间变化
        msg = struct.pack('>HHQ', TYPE_AUTH_RESP, HDR_SIZE, time_factor) + payload
        
        mac = hmac.new(self.shared_key, msg, hashlib.sha256).digest()
        auth_val = struct.unpack('>I', mac[:4])[0]

        # 构造响应返回
        resp = bytearray(struct.pack('>HHII', TYPE_AUTH_RESP, HDR_SIZE, auth_val, 0))
        resp_crc = zlib.crc32(resp) & 0xFFFFFFFF
        struct.pack_into('>I', resp, 8, resp_crc)
        
        self.transport.sendto(resp, addr)
        logger.info(f"Auth 响应 -> {addr} | Value: 0x{auth_val:08x} (TimeFactor: {time_factor})")


# ==========================================
# 2. 转发协议类 (实现数据直接透传)
# ==========================================
# class ForwardProtocol(asyncio.DatagramProtocol):
#     def __init__(self, black_addr: Tuple[str, int]):
#         self.black_addr = black_addr
#         self.transport = None

#     def connection_made(self, transport):
#         self.transport = transport

#     def datagram_received(self, data: bytes, addr: Tuple[str, int]):
#         """ 52719 端口收到数据，直接通过网卡转给黑区 """
#         if not data: return
#         # 直接发送，不做任何 auth 校验或协议解析
#         self.transport.sendto(data, self.black_addr)
#         logger.debug(f"数据转发: {len(data)} bytes | {addr} -> {self.black_addr}")

def print_banner(args):
    # ASCII Art Logo
    logo = r"""
    ##########################################################
    #                                                        #
    #    ____    ____  ______  ______  __    __  ____  ___   #
    #   / ___|  /    ||      ||      ||  |  |  |/    ||   \  #
    #  | |  _  |  o  ||      ||      ||  |  |  ||  o  ||    \ #
    #  | | | | |     ||_|  |_||_|  |_||  |  |  ||     ||  D  |#
    #  | |_| | |  _  |  |  |    |  |  |  :  |  ||  _  ||    / #
    #   \____| |__|__|  |__|    |__|   \   /   ||__|__||___/  #
    #                                                        #
    #               017A CRYPTO-GATEWAY v2.0                 #
    ##########################################################
    """
    print(logo)

    # 需要显示的配置信息
    configs = [
        f"服务运行模式: 双向认证 / 业务透传",
        f"监听网卡地址: {args.host}",
        f"AUTH 认证端口: {args.auth_port}",
        f"BYPASS 转发端口: {args.data_port}",
        f"黑区后端目标: {args.black_ip}:{args.black_port}"
    ]

    # 计算 Logo 边框宽度（此处大约为 60 字符）
    width = 60
    for line in configs:
        # 使用 center(width) 确保内容在视觉上相对于 Logo 居中
        print(line.center(width))
    print("\n")
    logger.info(f"服务器就绪...")

async def main():
    parser = argparse.ArgumentParser(description="017A 密码机 + 数据转发网关")
    parser.add_argument('--host', default='0.0.0.0', help='监听所有网卡')
    parser.add_argument('--auth-port', type=int, default=48350, help='Auth 监听端口')
    parser.add_argument('--data-port', type=int, default=52719, help='转发监听端口')
    parser.add_argument('--key', default='secret_shared_key_lrm_2026', help='共享密钥')
    parser.add_argument('--black-ip', required=True, help='黑区目标 IP')
    parser.add_argument('--black-port', type=int, default=52719, help='黑区目标端口')
    
    args = parser.parse_args()
    black_addr = (args.black_ip, args.black_port)

    print_banner(args)

    loop = asyncio.get_running_loop()

    # 任务 1: Auth 服务 (48350)
    auth_transport, _ = await loop.create_datagram_endpoint(
        lambda: CryptoServerProtocol(args.key.encode('utf-8')),
        local_addr=(args.host, args.auth_port)
    )

    # 任务 2: 转发服务 (52719)
    # fwd_transport, _ = await loop.create_datagram_endpoint(
    #     lambda: ForwardProtocol(black_addr),
    #     local_addr=(args.host, args.data_port)
    # )

    try:
        await asyncio.Future()  # 运行直到被停止
    finally:
        auth_transport.close()
        # fwd_transport.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("服务停止")