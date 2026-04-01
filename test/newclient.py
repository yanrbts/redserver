import socket
import struct
import argparse
import json
import os
import time
import sys

# --- 严格匹配 C 宏定义 ---
GAP_METHOD_LEN = 6
GAP_URL_LEN    = 128

class GapFullClient:
    def __init__(self, server_ip, server_port, local_port=0, timeout=2.0):
        self.server_addr = (server_ip, server_port)
        self.timeout = timeout
        
        # 创建 UDP Socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        # 绑定本地端口（如果 local_port 为 0，系统会自动分配随机端口）
        try:
            self.sock.bind(('0.0.0.0', local_port))
            actual_addr = self.sock.getsockname()
            print(f"[*] 本地监听启动: {actual_addr[0]}:{actual_addr[1]}")
        except Exception as e:
            print(f"[!] 绑定本地端口 {local_port} 失败: {e}")
            sys.exit(1)
            
        self.sock.settimeout(timeout)

    def _build_packet(self, data_size, rcp_id):
        """构造包含 Header 和 JSON 的完整二进制包"""
        # 生成 JSON 数据
        base_dict = {"rcpId": rcp_id, "msg": "hello", "padding": ""}
        current_json = json.dumps(base_dict).encode()
        
        if data_size > len(current_json):
            base_dict["padding"] = "x" * (data_size - len(current_json))
            json_bytes = json.dumps(base_dict).encode()
        else:
            json_bytes = current_json

        # 构造 Header (Packed)
        header_fmt = f"!H B H B {GAP_METHOD_LEN}s {GAP_URL_LEN}s"
        header = struct.pack(
            header_fmt,
            len(json_bytes),
            1, # num
            1, # total
            rcp_id,
            b"POST".ljust(GAP_METHOD_LEN, b'\x00')[:GAP_METHOD_LEN],
            b"/data".ljust(GAP_URL_LEN, b'\x00')[:GAP_URL_LEN]
        )
        return header + json_bytes

    def _unpack_inner_response(self, data):
        """
        直接解析内部业务头 (Inner Header)
        结构: dataLen(2) + num(1) + total(2) + rcpId(1) + Method(6) + URL(128) = 140字节
        """
        try:
            # 1. 长度校验
            if len(data) < 140:
                return f"[!] 数据包太短，无法解析头 (实际长度: {len(data)})"

            # 2. 解析 140 字节的 Header
            # 使用 '!' 代表大端 (Network Byte Order)
            header_fmt = f"!H B H B {GAP_METHOD_LEN}s {GAP_URL_LEN}s"
            header_size = struct.calcsize(header_fmt)
            
            header_data = data[:header_size]
            data_len, num, total, rcp_id, method, url = struct.unpack(header_fmt, header_data)

            # 3. 提取 JSON Payload
            # Payload 紧跟在 140 字节头后面
            json_start = header_size
            # 使用 data_len 截取，防止末尾有填充脏数据
            json_bytes = data[json_start : json_start + data_len]
            
            # 4. 转换字符串
            res_method = method.strip(b'\x00').decode('utf-8', errors='ignore')
            res_url = url.strip(b'\x00').decode('utf-8', errors='ignore')
            
            # 打印解析出的头部信息以便调试
            print(f"\n[+] 内部头解析成功:")
            print(f"    | rcpId: {rcp_id} | 状态: {num}/{total} | 载荷长度: {data_len}")
            print(f"    | 方法: {res_method} | 路径: {res_url}")

            # 5. 解析并返回 JSON
            try:
                return json.loads(json_bytes.decode('utf-8'))
            except json.JSONDecodeError:
                return json_bytes.decode('utf-8', errors='ignore')

        except Exception as e:
            return f"[!] 解析异常: {e}"

    def start(self, count, interval, data_size, rcp_id):
        sent_count = 0
        print(f"[*] 目标地址: {self.server_addr}")
        
        try:
            while True:
                if count != 0 and sent_count >= count:
                    break

                packet = self._build_packet(data_size, rcp_id)
                sent_count += 1
                
                self.sock.sendto(packet, self.server_addr)
                print(f"[{sent_count}] 已发送 {len(packet)} 字节", end=' ', flush=True)

                # 接收回包
                try:
                    resp_raw, addr = self.sock.recvfrom(65535)
                    # --- 调用直接解析函数 ---
                    result = self._unpack_inner_response(resp_raw)
                    print(f"| 返回内容: {result}")
                except socket.timeout:
                    print("| [!] 等待超时")

                if count == 0 or sent_count < count:
                    time.sleep(interval)
        except KeyboardInterrupt:
            print("\n[*] 停止发送")
        finally:
            self.sock.close()

def main():
    parser = argparse.ArgumentParser(description="GAP 高性能 UDP 调试客户端")
    
    # 核心地址参数
    parser.add_argument("--ip", type=str, required=True, help="服务端 IP")
    parser.add_argument("--port", type=int, required=True, help="服务端端口")
    parser.add_argument("-lp", "--local-port", type=int, default=0, help="本地监听端口 (默认随机)")
    
    # 控制参数
    parser.add_argument("-s", "--size", type=int, default=512, help="发送 JSON 载荷大小")
    parser.add_argument("-r", "--rcp", type=int, default=1, help="Report ID")
    parser.add_argument("-c", "--count", type=int, default=1, help="发送次数 (0 为持续发送)")
    parser.add_argument("-i", "--interval", type=float, default=1.0, help="发送间隔 (秒)")
    parser.add_argument("-t", "--timeout", type=float, default=2.0, help="等待回包超时时间 (秒)")
    
    args = parser.parse_args()

    client = GapFullClient(args.ip, args.port, args.local_port, args.timeout)
    client.start(args.count, args.interval, args.size, args.rcp)

if __name__ == "__main__":
    main()