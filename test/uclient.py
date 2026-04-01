#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import socket
import time
import string
import random
import select

def parse_arguments():
    parser = argparse.ArgumentParser(description="UDP 隔离网关双向测试工具")
    parser.add_argument("-H", "--host", required=True, help="目标 IP (如 192.168.211.130)")
    parser.add_argument("-P", "--port", type=int, required=True, help="目标端口 (如 52719)")
    parser.add_argument("-L", "--local-port", type=int, default=8899, help="本地绑定监听端口 (如 8899)")
    parser.add_argument("-s", "--size", type=int, default=1500, help="生成的 JSON 数据载荷大小")
    parser.add_argument("-c", "--count", type=int, default=1, help="发送次数 (0 为持续发送)")
    parser.add_argument("-i", "--interval", type=float, default=1.0, help="发送间隔")
    parser.add_argument("-t", "--timeout", type=float, default=2.0, help="等待回包超时时间")
    return parser.parse_args()

def generate_large_json(target_size):
    header = '{"rcpId": 1, "method": "REPORT", "url": "/api/v1/sensor", "data": "'
    footer = '"}'
    current_fixed_len = len(header) + len(footer)
    padding_len = max(10, target_size - current_fixed_len)
    random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=padding_len))
    return (header + random_str + footer).encode('utf-8')

def main():
    args = parse_arguments()
    data = generate_large_json(args.size)

    # 创建 UDP Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # --- 核心修改：绑定本地端口 ---
        # 这样发送出去的包，源端口将固定为 local_port，方便网关回传
        sock.bind(('0.0.0.0', args.local_port))
        sock.setblocking(False) # 设置为非阻塞模式，配合 select 使用
        
        print(f"--- 隔离网关双向测试 ---")
        print(f"本地绑定: 0.0.0.0:{args.local_port}")
        print(f"目标地址: {args.host}:{args.port}")
        print(f"发送载荷: {len(data)} 字节")
        print("-" * 40)

        sent_count = 0
        while True:
            # 1. 发送数据
            sock.sendto(data, (args.host, args.port))
            sent_count += 1
            print(f"[{sent_count:4d}] 已发送请求...")

            # 2. 监听回包 (使用 select 等待数据)
            # 等待 args.timeout 秒看是否有数据可读
            ready = select.select([sock], [], [], args.timeout)
            if ready[0]:
                recv_data, server_addr = sock.recvfrom(65535)
                print(f"       收到回包来自 {server_addr} ({len(recv_data)} 字节)")
                try:
                    # 尝试打印回包内容（如果是普通 JSON）
                    print(f"       内容: {recv_data.decode('utf-8', 'ignore')[:100]}...")
                except:
                    print(f"       内容: {recv_data.hex()[:50].upper()} (HEX)")
            else:
                print(f"       [!] 超时未收到响应")

            # 3. 循环控制
            if args.count > 0 and sent_count >= args.count:
                break
            
            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("\n[!] 用户停止测试")
    except Exception as e:
        print(f"\n[错误] {e}")
    finally:
        sock.close()
        print(f"\n测试完成。总发送: {sent_count}")

if __name__ == "__main__":
    main()