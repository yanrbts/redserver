# 黑区测试服务用例文档（详细版）

**版本**：v1.1  
**测试日期**：2026-04-17  
**测试目的**：全面验证协议解析、CRC 校验、业务数据处理、分片响应、健康遥测及 UI 监控的正确性。

---

## 1. 测试环境

- Python 版本：3.12+
- 依赖：`rich`, `psutil`
- 运行权限：Health Telemetry 需要 `sudo`
- 默认端口：Business 52719，Auth 48350

---

## 2. 核心功能测试点（详细版）

### 2.1 Auth 服务（端口 48350）—— CRC 校验 & 认证流程

| 测试编号 | 测试项 | 测试步骤 | 预期结果 | 关键验证点 |
|----------|--------|----------|----------|------------|
| AUTH-01 | PING 心跳透传 | 发送 `b'PING'` 到 48350 端口 | 原样返回相同数据 | 直接透传，不进行 CRC 校验 |
| AUTH-02 | 合法认证请求 | 构造完整 `0x6000` 请求包（含正确 CRC） | 返回 `0x6001` 响应，日志显示 "AUTH OK" | CRC 校验通过 |
| AUTH-03 | CRC 校验失败 | 修改任意字节后发送 | 丢弃请求，日志显示 "CRC ERROR" | `verify_full_crc()` 正确清零 CRC 字段后校验 |
| AUTH-04 | 时间因子计算 | 发送请求，观察响应中的 auth32 | auth32 必须使用 `time.time()//300` 计算 | HMAC-SHA256 前 4 字节正确 |
| AUTH-05 | 异常包处理 | 发送长度不足 12 字节或格式错误数据 | 捕获异常，日志显示 "AUTH EXCEPTION" | 不崩溃 |

**关键协议解析**：
- 包头格式：`>HHII`（type16, len16, auth32, stored_crc）
- CRC 校验逻辑：临时将 [8:12] 清零后计算 `zlib.crc32`

---

### 2.2 探测协议处理（Discovery）

| 测试编号 | 测试项 | 测试步骤 | 预期结果 | 关键验证点 |
|----------|--------|----------|----------|------------|
| PROBE-01 | GC_FIND 探测 | 发送 `H_FMT` + SYMBOL 的 FIND 包 | 返回 MAC + IP，Probe Stats 中 F+1 | 正确解析 `inner_s = 12 + 14 = 26` 偏移 |
| PROBE-02 | GC_REGISTER | 发送 REGISTER 包 | Probe Stats 中 R+1 | 解析 `cls` 字段 |
| PROBE-03 | GC_HEARBEAT | 发送心跳包（带 4 字节 payload） | Probe Stats 中 H+1 | 正确提取 payload 并返回 |

**关键协议解析**：
- 外层头：12 字节
- 伪以太头：14 字节
- 内层头：`H_FMT = "!2sBBBBH"`（SYMBOL + ver + cls + dir + rsv + msgno）

---

### 2.3 业务数据处理（Business）—— 重点解析

| 测试编号 | 测试项 | 测试步骤 | 预期结果 | 关键验证点 |
|----------|--------|----------|----------|------------|
| BIZ-01 | 普通业务数据解析 | 发送标准业务包 | 日志显示 RCP、Method、URL、JSON 内容 | 正确解析 `in_s = 54` 偏移 |
| BIZ-02 | URL 与 Method 解析 | 发送业务包 | 正确提取 128 字节 URL 和 6 字节 Method | `url_raw = data[in_s:in_s+128]`, `method_raw = data[in_s+128:in_s+134]` |
| BIZ-03 | 数值字段解析 | 发送业务包 | 正确解析 rcpId, total, num, d_len | `struct.unpack(">BHBH", data[num_start:num_start+6])` |
| BIZ-04 | JSON 数据提取 | 发送业务包 | 正确截取 JSON 并显示 | `json_start = num_start + 6` |

---

### 2.4 分片响应测试（--fragment 模式）

| 测试编号 | 测试项 | 测试步骤 | 预期结果 | 关键验证点 |
|----------|--------|----------|----------|------------|
| FRAG-01 | 大包分片发送 | 启动 `--fragment`，发送业务请求 | 日志显示 "SENT FRAG"，发送多个分片包 | 每片大小 ≤ 1300 字节 |
| FRAG-02 | 分片头构造 | 观察分片包 | 正确填充 `total_frags`、`num`、`dataLen` | `header_fmt = ">128s 6s B H B H"` |
| FRAG-03 | 分片延迟 | 发送超大 JSON | 每片间隔 0.001s | 防止网络丢包 |

**分片关键参数**：
- `TUNNEL_INNER_HDR_FIXED = 140`
- `INNER_TARGET_PAYLOAD = 1300`
- `MAX_CHUNK_SIZE = 1160`

---

### 2.5 Health Telemetry（健康遥测）

| 测试编号 | 测试项 | 测试步骤 | 预期结果 | 关键验证点 |
|----------|--------|----------|----------|------------|
| HLTH-01 | 健康包接收 | 发送 HLTH 格式包 | UI 表格显示 Rack/Slot、CPU、Mem、Version | 正确解析 `HLTH_FMT = ">I BBH I HHH I HH"` |
| HLTH-02 | 多设备显示 | 发送多个不同 Rack/Slot 包 | 表格按 R/S 排序显示 | `state.update_health((rack, slot), {...})` |

---

## 3. 测试执行命令

```bash
# 普通模式
sudo python3 test_sif_new.py

# 服务器分片模式
sudo python3 test_sif_new.py --fragment

# 客户端发送数据
python newclient.py --ip 192.168.211.130 --port 52719 -s 200 -c 0 -lp 58888