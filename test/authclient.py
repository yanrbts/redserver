import asyncio
import struct
import zlib
import hmac
import hashlib
import time
import logging

# 协议常量 (与服务端严格对齐)
TYPE_AUTH_REQ = 0x6000
TYPE_AUTH_RESP = 0x6001
HDR_SIZE = 12

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)-5s | %(message)s')
logger = logging.getLogger('AuthClient')

class AuthClientProtocol(asyncio.DatagramProtocol):
    def __init__(self, shared_key: bytes, on_con_lost):
        self.shared_key = shared_key
        self.on_con_lost = on_con_lost
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        logger.info("连接已建立，准备发送 Auth 请求...")
        self.send_auth_request()

    def send_auth_request(self):
        """构造并发送 12 字节的 Auth 请求包"""
        # 结构：Type(2), Len(2), Auth(4), CRC(4)
        # 请求时不带 Payload，Auth 填 0
        header_no_crc = struct.pack('>HHII', TYPE_AUTH_REQ, HDR_SIZE, 0, 0)
        
        # 计算全包 CRC (此时包就是 header_no_crc)
        crc = zlib.crc32(header_no_crc) & 0xFFFFFFFF
        
        # 重新打包带上真正的 CRC
        full_packet = struct.pack('>HHII', TYPE_AUTH_REQ, HDR_SIZE, 0, crc)
        
        self.transport.sendto(full_packet)
        logger.info(f"已发送 TYPE_AUTH_REQ (0x6000), CRC: {hex(crc)}")

    def datagram_received(self, data, addr):
        """处理来自服务端的响应"""
        if len(data) < HDR_SIZE:
            logger.warning("收到非法短包")
            return

        try:
            type16, len16, auth32, crc32 = struct.unpack('>HHII', data[:HDR_SIZE])
            
            # 1. 验证 CRC (拷贝清零法)
            temp_data = bytearray(data)
            temp_data[8:12] = b'\x00\x00\x00\x00'
            if (zlib.crc32(temp_data) & 0xFFFFFFFF) != crc32:
                logger.error("响应包 CRC 校验失败！")
                return

            if type16 == TYPE_AUTH_RESP:
                logger.info(f"收到 Auth 响应 | Auth码: 0x{auth32:08x}")
                
                # 2. 验证 HMAC 结果 (可选，用于确认服务端密钥是否一致)
                # 注意：服务端计算时引入了 5 分钟时间因子 time.time() // 300
                t_factor = int(time.time()) // 300
                payload = data[HDR_SIZE:len16]
                msg = struct.pack('>HHQ', TYPE_AUTH_RESP, HDR_SIZE, t_factor) + payload
                
                expected_mac = hmac.new(self.shared_key, msg, hashlib.sha256).digest()
                expected_auth = struct.unpack('>I', expected_mac[:4])[0]
                
                if auth32 == expected_auth:
                    logger.info("✅ Auth 码验证成功！密钥匹配。")
                else:
                    logger.warning(f"❌ Auth 码验证失败！预期: 0x{expected_auth:08x}, 收到: 0x{auth32:08x}")
                    logger.warning("请检查两端密钥(Key)或时间同步状态。")

        except Exception as e:
            logger.error(f"解析响应出错: {e}")
        finally:
            self.transport.close()

    def connection_lost(self, exc):
        self.on_con_lost.set_result(True)

async def request_auth(host, port, key):
    loop = asyncio.get_running_loop()
    on_con_lost = loop.create_future()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: AuthClientProtocol(key.encode(), on_con_lost),
        remote_addr=(host, port)
    )

    try:
        await on_con_lost
    finally:
        transport.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="密码机 Auth 请求客户端")
    parser.add_argument('--host', default='127.0.0.1', help='服务端地址')
    parser.add_argument('--port', type=int, default=48350, help='服务端端口')
    parser.add_argument('--key', default='secret_shared_key_lrm_2026', help='共享密钥')
    
    args = parser.parse_args()
    
    try:
        asyncio.run(request_auth(args.host, args.port, args.key))
    except KeyboardInterrupt:
        pass