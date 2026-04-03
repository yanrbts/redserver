# Red-LRM 工程接口规范文档

## 文档信息
- **版本**: v1.0
- **日期**: 2026-02-06
- **作者**: Red-LRM Team
- **适用范围**: src/ 目录下的核心接口模块

---

## 目录
1. [auth.h - 认证管理接口](#auth-h)
2. [5gc.h - 5GC服务接口](#5gc-h)
3. [5gcmanager.h - 5GC管理器接口](#5gcmanager-h)
4. [hdr.h - 协议头接口](#hdr-h)
5. [udp.h - UDP通信接口](#udp-h)
6. [util.h - 工具函数接口](#util-h)
7. [gap.h - 隧道数据包接口](#gap-h)
8. [xdp/xdp_pkt_parser.h - 数据包解析接口](#xdp-pkt-parser-h)
9. [cmd.h - 命令框架接口](#cmd-h)
10. [af_unix.h - Unix域服务器接口](#af-unix-h)
11. [pkteng.h - 数据包引擎接口](#pkteng-h)
12. [session_manager.h - 会话管理接口](#session-manager-h)

---

<a name="auth-h"></a>
## auth.h - 认证管理接口

### 概述
认证管理模块提供与认证服务器通信、获取和管理认证值的功能。支持认证缓存、自动刷新和网络探测。

### 常量定义
```c
#define AUTH_MIN_REFRESH_TIME 300    // 最小刷新间隔（秒）
#define AUTH_MAX_REFRESH_TIME 600    // 最大刷新间隔（秒）
```

### 数据结构

#### auth_t
认证管理结构体
```c
typedef struct {
    uint32_t auth_interval;     // 认证刷新间隔（秒）
    uint32_t auth_value;        // 当前认证值
    time_t last_auth_update;    // 最后认证更新时间
} auth_t;
```

### 函数接口

#### auth_create
**功能**: 创建并初始化认证管理对象

**语法**:
```c
auth_t* auth_create(uint32_t interval);
```

**参数**:
- `interval`: 认证刷新间隔（秒）

**返回值**:
- 成功: 返回新创建的auth_t指针
- 失败: 返回NULL

**说明**: 
- 分配内存并初始化认证管理结构
- interval应在AUTH_MIN_REFRESH_TIME到AUTH_MAX_REFRESH_TIME范围内

#### auth_refresh
**功能**: 执行网络请求更新认证值

**语法**:
```c
int auth_refresh(auth_t *at, const char *aip, uint16_t aport);
```

**参数**:
- `at`: 认证管理对象指针
- `aip`: 认证服务器IP地址字符串
- `aport`: 认证服务器端口号

**返回值**:
- 成功: 0
- 失败: -1

**说明**: 
- 通常由后台线程或定时器调用
- 封装与认证服务器的网络I/O操作

#### auth_get
**功能**: 获取缓存的认证值

**语法**:
```c
int auth_get(auth_t *at, uint32_t *out_auth);
```

**参数**:
- `at`: 认证管理对象指针
- `out_auth`: 输出参数，存储认证值

**返回值**:
- 成功: 0
- 失败: 负数错误码

**说明**: 
- 如果认证值过期，会自动触发刷新
- 线程安全的认证值获取

#### auth_free
**功能**: 释放认证管理对象

**语法**:
```c
void auth_free(auth_t *at);
```

**参数**:
- `at`: 认证管理对象指针（可为NULL）

**返回值**: 无

**说明**: 
- 安全释放所有相关资源
- 防止内存泄漏

#### auth_ping_probe
**功能**: 网络存活探测

**语法**:
```c
int auth_ping_probe(udp_conn_t *conn, const char *host, uint16_t port);
```

**参数**:
- `conn`: UDP连接句柄指针
- `host`: 目标IPv4地址字符串
- `port`: 目标端口号

**返回值**:
- 成功: 0（收到Pong）
- 超时: -2（800ms内无响应）
- 错误: -1（套接字或验证错误）

**说明**: 
- 实现应用级Ping
- 发送心跳包并等待相同回显响应

---

<a name="5gc-h"></a>
## 5gc.h - 5GC服务接口

### 概述
5GC服务模块提供5G核心网络服务的发现、注册和心跳功能。支持多端口探测和状态管理。

### 常量定义
```c
#define GC_RETRY_THRESHOLD          3       // 连续失败阈值
#define GC_FIND_INTERVAL            10      // 发现间隔（秒）
#define GC_REGISTER_INTERVAL        3       // 注册间隔（秒）
#define GC_HEARBEAT_INTERVAL        3       // 心跳间隔（秒）
#define GC_DEFAULT_BROADCAST_PORT   50001   // 默认广播端口
#define GC_BROADCAST_IP             "255.255.255.255"  // 广播IP
```

### 枚举类型

#### gc_porttype_e
端口类型枚举
```c
typedef enum gc_porttype {
    GC_MGR_BLACK = 0,    // 黑区端口
    GC_MGR_SWITCH = 1    // 交换机端口
} gc_porttype_e;
```

#### RespCode
响应码枚举
```c
enum RespCode {
    GC_NO_ERROR     = 0,    // 成功
    GC_PARAM_ERROR  = 1,    // 参数错误
    GC_OUT_OF_RES   = 2,    // 资源不足
    GC_MOUDLE_ERROR = 3,    // 模块错误
    GC_SYS_BUSY     = 4,    // 系统繁忙
    GC_TASK_BUSY    = 5,    // 任务繁忙
    GC_SERVICE_EXIST = 6    // 服务已存在
};
```

#### MsgType
消息类型枚举
```c
enum MsgType {
    GC_FIND = 0x01,         // 查找
    GC_REGISTER = 0x02,     // 注册
    GC_HEARBEAT = 0x03      // 心跳
};
```

#### SubType
子消息类型枚举
```c
enum SubType {
    GC_SUB_REQ  = 0x01,     // 请求
    GC_SUB_RESP = 0x02      // 响应
};
```

#### IpType
IP类型枚举
```c
enum IpType {
    GC_IPV4 = 0x00,
    GC_IPV6 = 0x01
};
```

#### Role
角色枚举
```c
enum Role {
    GC_B_5GC = 0x01,    // 基础网络5GC
    GC_L_5GC = 0x02,    // 陆军5GC
    GC_H_5GC = 0x03,    // 海军5GC
    GC_K_5GC = 0x04,    // 空军5GC
    GC_J_5GC = 0x05     // 火箭军5GC
};
```

#### gc_state_e
状态枚举
```c
typedef enum {
    GC_STATE_DISCOVERY = 0,  // 发现状态
    GC_STATE_REGISTER,       // 注册状态
    GC_STATE_HEARTBEAT,      // 心跳状态
} gc_state_e;
```

### 数据结构

#### gc_header_t
协议头结构
```c
typedef struct {
    uint8_t symbol[2];      // 协议标识
    uint8_t version;        // 版本号
    uint8_t cls;            // 消息类型
    uint8_t type;           // 子消息类型
    uint8_t empty;          // 分片标记
    uint16_t msgno;         // 消息序号
} __attribute__((packed)) gc_header_t;
```

#### gc_req_find_t
查找请求结构
```c
typedef struct {
    gc_header_t head;
    uint8_t iptype;
    struct in_addr svipv4;
    uint16_t port;
} __attribute__((packed)) gc_req_find_t;
```

#### gc_resp_find_t
查找响应结构
```c
typedef struct {
    gc_header_t head;
    uint8_t devid[6];       // 设备标识号
    uint8_t iptype;         // IP地址类型
    struct in_addr ipv4;    // 交换机IP
} __attribute__((packed)) gc_resp_find_t;
```

#### gc_req_register_t
注册请求结构
```c
typedef struct {
    gc_header_t head;
    uint8_t svrid[6];       // 唯一标识
    uint8_t iptype;         // IP类型
    uint8_t svrip[4];       // 服务器IP
    uint8_t svrrole;        // 服务器角色
} __attribute__((packed)) gc_req_register_t;
```

#### gc_resp_register_t
注册响应结构
```c
typedef struct {
    gc_header_t head;
    uint8_t result;         // 结果码
} __attribute__((packed)) gc_resp_register_t;
```

#### gc_hearbeat_t
心跳结构
```c
typedef struct {
    gc_header_t head;
    uint8_t tm[4];          // 时间戳
} __attribute__((packed)) gc_hearbeat_t;
```

#### gc_ctx_t
5GC服务上下文结构
```c
typedef struct gc_ctx {
    udp_conn_t *conn;                    // 网络连接
    gc_resp_find_t node;                 // 协议数据
    gc_state_e state;                     // 当前状态
    int fail_count;                       // 失败计数
    uint16_t target_port;                 // 目标端口
    uint16_t src_port;                    // 源端口
    uint16_t last_query_msgno;            // 最后查询消息号
    bool is_running;                      // 运行标志
    gc_porttype_e porttype;               // 端口类型
    pthread_t worker_tid;                 // 工作线程ID
    pthread_rwlock_t lock;                // 读写锁
    gc_handler_t on_find_req;            // 查找请求回调
    gc_handler_t on_register_req;        // 注册请求回调
    gc_handler_t on_heartbeat_req;       // 心跳请求回调
    void (*on_state_change)(struct gc_ctx *ctx, gc_state_e new_state); // 状态变化回调
    gc_manager_t *mgr;                   // 父管理器
} gc_ctx_t;
```

### 回调函数类型

#### gc_handler_t
通用处理器类型
```c
typedef void (*gc_handler_t)(gc_ctx_t *ctx, const void *payload, size_t len, struct sockaddr_in *from);
```

### 函数接口

#### gc_service_create
**功能**: 创建5GC服务上下文

**语法**:
```c
gc_ctx_t* gc_service_create(uint16_t src_port, uint16_t target_port, gc_porttype_e porttype);
```

**参数**:
- `src_port`: 本地源UDP端口（0表示系统分配）
- `target_port`: 目标UDP端口
- `porttype`: 操作模式（GC_MGR_BLACK或GC_MGR_SWITCH）

**返回值**:
- 成功: 返回新上下文指针
- 失败: 返回NULL

**警告**: 返回的上下文必须使用gc_service_destroy()释放

#### gc_service_destroy
**功能**: 销毁5GC服务上下文

**语法**:
```c
void gc_service_destroy(gc_ctx_t *ctx);
```

**参数**:
- `ctx`: 要销毁的上下文指针

**返回值**: 无

#### gc_service_start
**功能**: 启动5GC服务后台线程

**语法**:
```c
int gc_service_start(gc_ctx_t *ctx);
```

**参数**:
- `ctx`: 服务上下文指针

**返回值**:
- 成功: 0
- 失败: -1

**说明**: 
- 创建POSIX线程运行gc_worker_thread
- 设置is_running标志启动状态机

#### gc_service_stop
**功能**: 停止5GC服务

**语法**:
```c
void gc_service_stop(gc_ctx_t *ctx);
```

**参数**:
- `ctx`: 服务上下文指针

**返回值**: 无

#### gc_set_handlers
**功能**: 注册回调函数

**语法**:
```c
void gc_set_handlers(gc_ctx_t *ctx, gc_handler_t find, gc_handler_t reg, gc_handler_t hb);
```

**参数**:
- `ctx`: 5GC上下文指针
- `find`: 查找请求回调函数
- `reg`: 注册请求回调函数
- `hb`: 心跳请求回调函数

**返回值**: 无

#### gc_get_device_id
**功能**: 获取设备MAC地址

**语法**:
```c
int gc_get_device_id(gc_ctx_t *ctx, uint8_t out_devid[6]);
```

**参数**:
- `ctx`: 5GC上下文指针
- `out_devid`: 输出缓冲区（至少6字节）

**返回值**:
- 成功: 0
- 失败: -1

#### gc_get_server_ip
**功能**: 获取服务器IP地址

**语法**:
```c
int gc_get_server_ip(gc_ctx_t *ctx, uint32_t *out_ip);
```

**参数**:
- `ctx`: 5GC上下文指针
- `out_ip`: 输出参数，存储IP地址（网络字节序）

**返回值**:
- 成功: 0
- 失败: -1

#### get_next_msgno
**功能**: 生成下一个消息序号

**语法**:
```c
uint16_t get_next_msgno(void);
```

**参数**: 无

**返回值**: 下一个唯一消息序号

#### gc_build_header
**功能**: 构建协议头

**语法**:
```c
void gc_build_header(gc_header_t *head, uint8_t cls, uint8_t type, uint16_t msgno);
```

**参数**:
- `head`: 要初始化的协议头指针
- `cls`: 消息类型
- `type`: 子消息类型
- `msgno`: 消息序号

**返回值**: 无

---

<a name="5gcmanager-h"></a>
## 5gcmanager.h - 5GC管理器接口

### 概述
5GC管理器模块提供多5GC上下文管理、多端口探测和广播服务功能。

### 常量定义
```c
#define CG_DEFAULT_SRC_PORT         8888    // 默认源端口
#define GC_DEFAULT_BROADCAST_PORT   50001   // 默认广播端口
#define GC_BROADCAST_IP             "255.255.255.255"  // 广播IP
```

### 数据结构

#### gc_mgr_port_t
管理器端口结构
```c
typedef struct gc_mgr_port {
    uint16_t        port;             // 远程探测端口
    gc_porttype_e   type;             // 端口类型
} gc_mgr_port_t;
```

#### gc_manager_t
5GC管理器结构
```c
typedef struct gc_manager {
    udp_conn_t         *broadcast_conn;     // 广播连接
    uint16_t            src_port;           // 共享源端口
    bool                is_running;         // 运行标志
    
    pthread_t           broadcast_tid;      // 广播线程ID
    pthread_rwlock_t    lock;               // 保护子列表和探测端口
    
    gc_ctx_t          **child_ctxs;         // 子上下文数组
    size_t              num_childs;          // 子上下文数量
    size_t              child_capacity;      // 子上下文容量
    
    struct probe_port {
        uint16_t        port;               // 远程探测端口
        uint16_t        last_msgno;         // 最后发送消息号
        uint64_t        last_send_ms;       // 最后发送时间戳
        gc_porttype_e   type;               // 端口类型
        bool            active;              // 活动标志
    } *probe_ports;                         // 探测端口数组
    size_t              num_probe_ports;    // 探测端口数量
    size_t              probe_capacity;     // 探测端口容量
    
    // 回调函数
    gc_manager_handler_t        on_find_req;          // 查找请求处理器
    gc_manager_handler_t        on_register_req;      // 注册请求处理器
    gc_manager_handler_t        on_heartbeat_req;     // 心跳请求处理器
    gc_manager_new_target_cb_t  on_new_target;        // 新目标回调
    void                       (*on_child_state_change)(gc_ctx_t*, gc_state_e); // 子状态变化回调
} gc_manager_t;
```

### 回调函数类型

#### gc_manager_handler_t
管理器处理器类型
```c
typedef void (*gc_manager_handler_t)(struct gc_manager *mgr, const void *payload, size_t len, struct sockaddr_in *from);
```

#### gc_manager_new_target_cb_t
新目标回调类型
```c
typedef void (*gc_manager_new_target_cb_t)(struct gc_manager *mgr, gc_resp_find_t *new_node, uint16_t probe_port);
```

### 函数接口

#### gc_mgr_create
**功能**: 创建5GC管理器实例

**语法**:
```c
gc_manager_t* gc_mgr_create(uint16_t src_port, const gc_mgr_port_t *target_ports, size_t num_ports);
```

**参数**:
- `src_port`: 本地源UDP端口（0表示系统分配）
- `target_ports`: 目标端口数组（可为NULL）
- `num_ports`: 目标端口数组大小

**返回值**:
- 成功: 返回管理器实例指针
- 失败: 返回NULL

#### gc_mgr_destroy
**功能**: 销毁5GC管理器实例

**语法**:
```c
void gc_mgr_destroy(gc_manager_t *mgr);
```

**参数**:
- `mgr`: 管理器实例指针

**返回值**: 无

#### gc_mgr_start
**功能**: 启动5GC管理器

**语法**:
```c
int gc_mgr_start(gc_manager_t *mgr);
```

**参数**:
- `mgr`: 管理器实例指针

**返回值**:
- 成功: 0
- 失败: -1

#### gc_mgr_stop
**功能**: 停止5GC管理器

**语法**:
```c
void gc_mgr_stop(gc_manager_t *mgr);
```

**参数**:
- `mgr`: 管理器实例指针

**返回值**: 无

#### gc_mgr_set_find_handler
**功能**: 设置查找请求处理器

**语法**:
```c
void gc_mgr_set_find_handler(gc_manager_t *mgr, gc_manager_handler_t handler);
```

**参数**:
- `mgr`: 管理器实例指针
- `handler`: 处理器函数指针

**返回值**: 无

#### gc_mgr_set_new_target_cb
**功能**: 设置新目标回调

**语法**:
```c
void gc_mgr_set_new_target_cb(gc_manager_t *mgr, gc_manager_new_target_cb_t cb);
```

**参数**:
- `mgr`: 管理器实例指针
- `cb`: 回调函数指针

**返回值**: 无

#### gc_mgr_set_child_state_cb
**功能**: 设置子状态变化回调

**语法**:
```c
void gc_mgr_set_child_state_cb(gc_manager_t *mgr, void (*cb)(gc_ctx_t*, gc_state_e));
```

**参数**:
- `mgr`: 管理器实例指针
- `cb`: 回调函数指针

**返回值**: 无

#### gc_mgr_add_probe_port
**功能**: 动态添加探测端口

**语法**:
```c
int gc_mgr_add_probe_port(gc_manager_t *mgr, uint16_t port);
```

**参数**:
- `mgr`: 管理器实例指针
- `port`: 要添加的UDP端口

**返回值**:
- 成功: 0
- 失败: -1

#### gc_mgr_get_child_count
**功能**: 获取子上下文数量

**语法**:
```c
size_t gc_mgr_get_child_count(gc_manager_t *mgr);
```

**参数**:
- `mgr`: 管理器实例指针

**返回值**: 子上下文数量

#### gc_mgr_get_child
**功能**: 按索引获取子上下文

**语法**:
```c
gc_ctx_t* gc_mgr_get_child(gc_manager_t *mgr, size_t index);
```

**参数**:
- `mgr`: 管理器实例指针
- `index`: 子上下文索引

**返回值**:
- 成功: 子上下文指针
- 失败: NULL

#### gc_mgr_find_child
**功能**: 按IP和端口查找子上下文

**语法**:
```c
gc_ctx_t* gc_mgr_find_child(gc_manager_t *mgr, uint32_t ip, uint16_t port);
```

**参数**:
- `mgr`: 管理器实例指针
- `ip`: 目标IPv4地址（网络字节序）
- `port`: 目标UDP端口

**返回值**:
- 成功: 子上下文指针
- 失败: NULL

#### gc_mgr_resume_probe_port
**功能**: 恢复指定端口的探测

**语法**:
```c
void gc_mgr_resume_probe_port(gc_manager_t *mgr, uint16_t port);
```

**参数**:
- `mgr`: 管理器实例指针
- `port`: 要恢复的UDP端口

**返回值**: 无

#### gc_mgr_remove_child
**功能**: 移除并销毁子上下文

**语法**:
```c
void gc_mgr_remove_child(gc_manager_t *mgr, gc_ctx_t *child);
```

**参数**:
- `mgr`: 管理器实例指针
- `child`: 要移除的子上下文指针

**警告**: 调用后child指针不可再使用

#### gc_mgr_get_ip_by_type
**功能**: 按端口类型获取服务器IP

**语法**:
```c
int gc_mgr_get_ip_by_type(gc_manager_t *mgr, gc_porttype_e porttype, uint32_t *out_ip);
```

**参数**:
- `mgr`: 管理器实例指针
- `porttype`: 端口类型（GC_MGR_BLACK或GC_MGR_SWITCH）
- `out_ip`: 输出参数，存储IP地址（网络字节序）

**返回值**:
- 成功: 0
- 失败: -1

**警告**: out_ip不能为NULL

#### gc_mgr_get_mac_by_type
**功能**: 按端口类型获取设备MAC地址

**语法**:
```c
int gc_mgr_get_mac_by_type(gc_manager_t *mgr, gc_porttype_e porttype, uint8_t out_mac[6]);
```

**参数**:
- `mgr`: 管理器实例指针
- `porttype`: 端口类型（GC_MGR_BLACK或GC_MGR_SWITCH）
- `out_mac`: 输出缓冲区（6字节）

**返回值**:
- 成功: 0
- 失败: -1

**警告**: out_mac不能为NULL

---

<a name="hdr-h"></a>
## hdr.h - 协议头接口

### 概述
协议头模块提供认证协议的头部构建、解析和CRC校验功能。

### 常量定义
```c
#define AUTH_REQ            0x6000    // 认证请求
#define AUTH_REP            0x6001    // 认证响应
#define AUTH_DATA           0x6789    // 认证数据
#define HDR_SIZE            12        // 头大小
#define AUTH_DATA_LENGTH    1514      // 认证数据长度
#define AUTH_PAYLOAD_SIZE   1502      // 认证载荷大小
#define BUFFER_SIZE         1514      // 缓冲区大小
```

### 数据结构

#### hdr_t
协议头结构
```c
typedef struct {
    uint8_t type[2];    // 类型16位：[0]=高字节，[1]=低字节
    uint8_t len[2];     // 长度16位：[0]=高字节，[1]=低字节
    uint8_t auth[4];    // 认证32位：大端序
    uint8_t crc[4];     // CRC32：大端序
} __attribute__((packed)) hdr_t;
```

### 函数接口

#### hdr_build
**功能**: 构建协议头（手动大端序）

**语法**:
```c
void hdr_build(unsigned char *raw_hdr, uint16_t type, uint32_t total_len, uint32_t auth);
```

**参数**:
- `raw_hdr`: 输出缓冲区（必须HDR_SIZE字节）
- `type`: 消息类型（主机序）
- `total_len`: 总数据包长度（主机序）
- `auth`: 认证值（主机序）

**返回值**: 无

#### hdr_parse
**功能**: 解析协议头（大端序转主机序）

**语法**:
```c
int hdr_parse(const unsigned char *raw_hdr, uint16_t *type_out, uint16_t *len_out, uint32_t *auth_out, uint32_t *crc_out);
```

**参数**:
- `raw_hdr`: 输入头缓冲区（HDR_SIZE字节）
- `type_out`: 输出解析的类型（主机序）
- `len_out`: 输出解析的总长度（主机序）
- `auth_out`: 输出解析的认证值（主机序）
- `crc_out`: 输出解析的CRC值（主机序）

**返回值**:
- 成功: 0
- 失败: -1

#### hdr_verify_crc
**功能**: 验证CRC32校验

**语法**:
```c
int hdr_verify_crc(const unsigned char *raw_hdr, ssize_t raw_len);
```

**参数**:
- `raw_hdr`: 头缓冲区（HDR_SIZE字节）
- `raw_len`: 原始数据长度

**返回值**:
- 匹配: 1
- 不匹配: 0

---

<a name="udp-h"></a>
## udp.h - UDP通信接口

### 概述
UDP通信模块提供标准UDP套接字和原始套接字的创建、配置和数据传输功能。

### 常量定义
```c
#define UDP_MAX_PKT_SIZE 65535    // UDP数据报最大理论大小
```

### 数据结构

#### udp_conn_t
UDP连接结构
```c
typedef struct {
    int fd;                 // 套接字文件描述符
    uint16_t port;          // 绑定的端口号
    int current_timeout;    // 当前超时设置
} udp_conn_t;
```

#### raw_sock_t
原始套接字结构
```c
typedef struct {
    int sockfd;             // 套接字文件描述符
    int if_index;           // 接口索引
    char if_name[IFNAMSIZ]; // 接口名称
} raw_sock_t;
```

### 函数接口

#### udp_init_listener
**功能**: 初始化UDP监听套接字

**语法**:
```c
udp_conn_t* udp_init_listener(uint16_t port, int recv_buf_mb);
```

**参数**:
- `port`: 要监听的本地端口
- `recv_buf_mb`: 内核接收缓冲区大小（MB）

**返回值**:
- 成功: 返回连接句柄指针
- 失败: 返回NULL

**说明**: 
- 创建套接字并绑定到所有可用接口
- 配置内核接收缓冲区防止数据包丢失

#### udp_send_raw
**功能**: 发送原始二进制数据

**语法**:
```c
ssize_t udp_send_raw(udp_conn_t *conn, const char *dst_ip, uint16_t dst_port, const void *data, size_t len);
```

**参数**:
- `conn`: 套接字句柄描述符
- `dst_ip`: 目标IPv4地址字符串
- `dst_port`: 目标UDP端口（主机序）
- `data`: 要发送的二进制数据缓冲区指针
- `len`: 数据大小（字节）

**返回值**:
- 成功: 发送的字节数
- 失败: -1

#### udp_recv_raw
**功能**: 接收二进制数据（带超时）

**语法**:
```c
ssize_t udp_recv_raw(udp_conn_t *conn, void *buf, size_t buf_size, struct sockaddr_in *client_addr, int timeout_ms);
```

**参数**:
- `conn`: 套接字句柄描述符
- `buf`: 存储接收数据的缓冲区
- `buf_size`: 提供的缓冲区大小
- `client_addr`: 输出：发送者地址详情
- `timeout_ms`: 等待超时（毫秒，0表示无限阻塞）

**返回值**:
- 成功: 接收的字节数
- 超时: 0
- 失败: -1

**说明**: 
- 对于大数据报（>20KB），确保缓冲区足够大
- 包装recvfrom并设置套接字超时

#### udp_close
**功能**: 关闭UDP连接

**语法**:
```c
void udp_close(udp_conn_t *conn);
```

**参数**:
- `conn`: 要销毁的udp_conn_t句柄指针

**返回值**: 无

#### udp_set_broadcast
**功能**: 启用/禁用广播功能

**语法**:
```c
int udp_set_broadcast(udp_conn_t *conn, int enable);
```

**参数**:
- `conn`: 已初始化的udp_conn_t句柄指针
- `enable`: 1启用，0禁用

**返回值**:
- 成功: 0
- 失败: -1

#### udp_set_connect
**功能**: 设置默认远程地址

**语法**:
```c
int udp_set_connect(udp_conn_t *conn, uint32_t dst_ip_n, uint16_t dst_port);
```

**参数**:
- `conn`: 套接字句柄描述符
- `dst_ip_n`: 目标IPv4地址（网络字节序）
- `dst_port`: 目标UDP端口（主机序）

**返回值**:
- 成功: 0
- 失败: -1

**警告**: 修改套接字状态，在多目标场景中谨慎使用

#### udp_reset_connect
**功能**: 重置为未连接状态

**语法**:
```c
int udp_reset_connect(udp_conn_t *conn);
```

**参数**:
- `conn`: 套接字句柄描述符

**返回值**:
- 成功: 0
- 失败: -1

#### raw_sock_open
**功能**: 初始化链路层原始套接字

**语法**:
```c
raw_sock_t *raw_sock_open(const char *if_name);
```

**参数**:
- `if_name`: 网络接口名称（如"eth0"、"wwan0"）

**返回值**:
- 成功: 返回套接字句柄指针
- 失败: 返回NULL

**说明**: 
- 创建绑定到特定网络接口的原始套接字
- 允许在以太网层发送和接收数据包

#### raw_sock_send
**功能**: 链路层原始数据传输

**语法**:
```c
ssize_t raw_sock_send(raw_sock_t *ctx, const uint8_t *dst_mac, const void *data, size_t data_len);
```

**参数**:
- `ctx`: 已初始化的raw_sock_t句柄指针
- `dst_mac`: 目标MAC地址（6字节）。如果为NULL，使用data的前6字节
- `data`: 包含原始二进制流的缓冲区（包括以太网头）
- `data_len`: 要发送的数据总长度

**返回值**:
- 成功: 发送的字节数
- 失败: -1

#### raw_sock_close
**功能**: 关闭原始套接字

**语法**:
```c
void raw_sock_close(raw_sock_t *ctx);
```

**参数**:
- `ctx`: 要关闭的raw_sock_t句柄指针

**返回值**: 无

---

<a name="util-h"></a>
## util.h - 工具函数接口

### 概述
工具函数模块提供网络接口信息获取、时间处理和IP地址转换等实用功能。

### 函数接口

#### get_interface_binary_info
**功能**: 获取第一个活动接口的二进制MAC和IPv4地址

**语法**:
```c
int get_interface_binary_info(uint8_t *mac_bin, uint32_t *ip_bin);
```

**参数**:
- `mac_bin`: 存储二进制MAC地址的缓冲区（6字节）
- `ip_bin`: 存储IPv4地址的指针（网络字节序）

**返回值**:
- 成功: 0
- 失败: -1

**说明**: 
- 迭代可用网络接口查找第一个非环回IPv4接口
- 提取网络字节序的IP地址和6字节二进制MAC地址

#### get_production_ip
**功能**: 自动查找第一个活动非环回IPv4接口

**语法**:
```c
int get_production_ip(char *ip_buf, char *if_name);
```

**参数**:
- `ip_buf`: IP字符串输出缓冲区（至少16字节）
- `if_name`: 接口名称输出缓冲区（至少IFNAMSIZ字节）

**返回值**:
- 成功: 0
- 失败: -1

#### get_production_mac
**功能**: 使用特定接口名获取硬件MAC地址

**语法**:
```c
int get_production_mac(const char *if_name, char *mac_buf);
```

**参数**:
- `if_name`: 接口名称（如"ens33"）
- `mac_buf`: MAC字符串输出缓冲区（至少18字节）

**返回值**:
- 成功: 0
- 失败: -1

#### get_now_ms
**功能**: 获取当前时间（Unix纪元以来的毫秒数）

**语法**:
```c
uint64_t get_now_ms(void);
```

**参数**: 无

**返回值**: 当前时间（毫秒）

#### ip_pton
**功能**: IPv4地址字符串转二进制

**语法**:
```c
int ip_pton(const char *ip_str, uint32_t *out_ip);
```

**参数**:
- `ip_str`: 输入IPv4地址字符串（如"192.168.1.1"）
- `out_ip`: 输出二进制IPv4地址指针

**返回值**:
- 成功: 0
- 失败: -1

#### ip_ntop
**功能**: 二进制IPv4地址转字符串

**语法**:
```c
int ip_ntop(uint32_t ip_bin, char *out_str, size_t size);
```

**参数**:
- `ip_bin`: 输入二进制IPv4地址
- `out_str`: 输出IPv4地址字符串缓冲区
- `size`: 输出缓冲区大小

**返回值**:
- 成功: 0
- 失败: -1

---

<a name="gap-h"></a>
## gap.h - 隧道数据包接口

### 概述
隧道数据包模块定义红黑隔离网关中隧道数据包的结构和操作。处理嵌套UDP数据包，其中外层UDP载荷包含伪造的以太网/IP/UDP帧。

### 常量定义
```c
#define GAP_METHOD_LEN      6        // 方法名长度
#define GAP_AUTH_LEN        12       // 认证字段长度
#define GAP_URL_LEN         128      // URL长度
#define GAP_MAX_FRAGMENT    1300     // 最大分片大小
#define GAP_IP_HDR_LEN      20       // IP头长度
#define GAP_UDP_HDR_LEN     8        // UDP头长度
```

### 宏定义
```c
#define GAP_PACKET_SIZE(json_len) \
    (offsetof(tunnel_payload_t, inner_data) + offsetof(tunnel_inner_payload_t, data) + (json_len))

#define GAP_INNER_PACKET_SIZE(json_len) \
    (offsetof(tunnel_inner_payload_t, data) + (json_len))
```

### 数据结构

#### tunnel_inner_payload_t
隧道内载荷结构
```c
typedef struct {
    uint16_t dataLen;                   // JSON数据长度（网络字节序）
    uint8_t  num;                       // 当前分片编号（从1开始）
    uint16_t total;                     // 总分片数（网络字节序）
    uint8_t  rcpId;                     // 报告ID
    uint8_t  method[GAP_METHOD_LEN];    // 方法名（固定6字节）
    uint8_t  url[GAP_URL_LEN];          // URL或路径（固定128字节）
    uint8_t  data[];                    // JSON数据
} __attribute__((packed)) tunnel_inner_payload_t;
```

#### tunnel_payload_t
隧道载荷结构
```c
typedef struct {
    uint8_t  auth[GAP_AUTH_LEN];        // 认证字段（12字节）
    uint8_t  ether_header[14];          // 以太网头
    uint8_t  ip_header[GAP_IP_HDR_LEN]; // IPv4头
    uint8_t  udp_header[GAP_UDP_HDR_LEN]; // UDP头
    uint8_t  inner_data[];              // 内部载荷数据
} __attribute__((packed)) tunnel_payload_t;
```

### 函数接口

#### gap_build_tunneled_packets
**功能**: 构建一个或多个隧道数据包（必要时分片）

**语法**:
```c
int gap_build_tunneled_packets(
    const uint8_t *json_data, size_t json_len,
    const uint8_t *src_mac, const uint8_t *dst_mac,
    uint32_t src_ip_nbo, uint32_t dst_ip_nbo,
    uint16_t src_port, uint16_t dst_port,
    uint32_t auth, uint8_t rcpId,
    const char *method, const char *url,
    tunnel_payload_t ***payloads_out, size_t *num_payloads
);
```

**参数**:
- `json_data`: 完整JSON数据缓冲区
- `json_len`: JSON总长度
- `src_mac`: 源MAC地址（6字节）
- `dst_mac`: 目标MAC地址（6字节）
- `src_ip_nbo`: 源IPv4（4字节，网络字节序）
- `dst_ip_nbo`: 目标IPv4（4字节，网络字节序）
- `src_port`: 伪造源端口（主机序）
- `dst_port`: 伪造目标端口（主机序）
- `auth`: 认证字段（GAP_AUTH_LEN字节）
- `rcpId`: 报告/消息ID（所有分片相同）
- `method`: 方法名（共享）
- `url`: URL/路径（共享）
- `payloads_out`: 输出：tunnel_payload_t*数组
- `num_payloads`: 输出：数据包数量（1个或多个）

**返回值**:
- 成功: 0
- 失败: -1

**说明**: 
- 如果JSON数据超过限制，会分割为多个数据包
- 调用者负责释放每个payloads[i]和payloads数组本身

#### gap_free_tunneled_packets
**功能**: 安全释放隧道数据包数组

**语法**:
```c
void gap_free_tunneled_packets(tunnel_payload_t **payloads, size_t num_payloads);
```

**参数**:
- `payloads`: tunnel_payload_t指针数组的指针
- `num_payloads`: 数组中的数据包数量

**返回值**: 无

#### gap_build_control_packet
**功能**: 构建控制数据包

**语法**:
```c
tunnel_payload_t* gap_build_control_packet(
    const uint8_t *real_data, size_t real_len,
    const uint8_t *src_mac, const uint8_t *dst_mac,
    uint32_t src_ip_nbo, uint32_t dst_ip_nbo,
    uint16_t src_port, uint16_t dst_port,
    uint32_t auth, size_t *packet_len
);
```

**参数**:
- `real_data`: 真实载荷数据指针（如JSON）
- `real_len`: 真实载荷长度
- `src_mac`: 要伪造的源MAC地址（6字节）
- `dst_mac`: 目标MAC地址（6字节）
- `src_ip_nbo`: 源IPv4（4字节，网络字节序）
- `dst_ip_nbo`: 目标IPv4（4字节，网络字节序）
- `src_port`: 伪造源UDP端口（主机序）
- `dst_port`: 伪造目标UDP端口（主机序）
- `auth`: 认证字段（4字节）
- `packet_len`: 输出：返回数据包的总长度

**返回值**:
- 成功: 分配的数据包缓冲区指针
- 失败: NULL

**警告**: 调用者必须free()返回的指针

#### gap_send_tunneled_to_target
**功能**: 发送隧道数据包到目标

**语法**:
```c
int gap_send_tunneled_to_target(
    const char *dst_ip, uint16_t dst_port,
    tunnel_payload_t **payloads, size_t num_payloads,
    udp_conn_t *conn
);
```

**参数**:
- `dst_ip`: 下一跳网关的物理目标IP
- `dst_port`: 物理目标UDP端口（如52719）
- `payloads`: tunnel_payload_t指针数组
- `num_payloads`: 数组中的数据包数量
- `conn`: UDP连接套接字

**返回值**:
- 成功: 0
- 失败: -1

#### gap_raw_send_to_target
**功能**: 通过原始套接字批量发送隧道数据包

**语法**:
```c
void gap_raw_send_to_target(const char *if_name, tunnel_payload_t **packets, size_t num);
```

**参数**:
- `if_name`: 目标接口名称（如"eth0"）
- `packets`: tunnel_payload_t结构体指针数组
- `num`: 数组中的数据包数量

**返回值**: 无

**说明**: 
- 为批次持续时间打开原始套接字
- 迭代数据包，计算动态长度并执行传输

#### gap_unpack_packets
**功能**: 解包从黑区接收的隧道数据包

**语法**:
```c
int gap_unpack_packets(unsigned char *tunnel_buf, size_t tunnel_len,
                        uint16_t *proxy_port,
                        unsigned char **business_data, size_t *business_len);
```

**参数**:
- `tunnel_buf`: 从UDP套接字接收的原始缓冲区
- `tunnel_len`: 接收缓冲区的总长度
- `proxy_port`: 输出：提取的内层代理端口（用于NAT查找）
- `business_data`: 输出：实际JSON业务数据指针
- `business_len`: 输出：JSON业务数据长度

**返回值**:
- 成功: 0
- 格式错误: -1
- 长度不匹配: -2

#### get_gap_packet_total_size
**功能**: 计算GAP数据包的总大小

**语法**:
```c
static inline size_t get_gap_packet_total_size(const void *payload_ptr);
```

**参数**:
- `payload_ptr`: tunnel_payload_t结构体指针

**返回值**: 
- 成功: 总大小（字节）
- 失败: 0

#### gap_build_tunneled_packets_ex
**功能**: 从原始数据缓冲区构建一个或多个隧道数据包

**语法**:
```c
int gap_build_tunneled_packets_ex(
    const uint8_t *data, size_t len,
    const uint8_t *src_mac, const uint8_t *dst_mac,
    uint32_t src_ip_nbo, uint32_t dst_ip_nbo,
    uint16_t src_port, uint16_t dst_port,
    uint32_t auth,
    tunnel_payload_t ***payloads_out, size_t *num_payloads
);
```

**参数**:
- `data`: 源缓冲区指针（包含内层头+载荷）
- `len`: 源缓冲区总长度
- `src_mac`: 伪造以太网头的源MAC地址（6字节）
- `dst_mac`: 伪造以太网头的目标MAC地址（6字节）
- `src_ip_nbo`: 源IPv4地址（网络字节序）
- `dst_ip_nbo`: 目标IPv4地址（网络字节序）
- `src_port`: 伪造源UDP端口（主机序）
- `dst_port`: 伪造目标UDP端口（主机序）
- `auth`: 32位认证值
- `payloads_out`: 输出：分配的tunnel_payload_t指针数组
- `num_payloads`: 输出：生成的分片总数

**返回值**:
- 成功: 0
- 失败: -1

**说明**: 
- 如果数据大小超过GAP_MAX_FRAGMENT，会分割为多个分片
- 调用者必须通过gap_free_tunneled_packets()释放

#### gap_build_ctrl54_packet
**功能**: 构建raise数据包（仅包含伪造以太网头和认证字段）

**语法**:
```c
tunnel_payload_t* gap_build_ctrl54_packet(
    const uint8_t *real_data, size_t real_len,
    const uint8_t *src_mac, const uint8_t *dst_mac,
    uint32_t src_ip_nbo, uint32_t dst_ip_nbo,
    uint16_t src_port, uint16_t dst_port,
    uint32_t auth, size_t *packet_len
);
```

**参数**:
- `real_data`: 真实载荷数据指针（如JSON）
- `real_len`: 真实载荷长度
- `src_mac`: 要伪造的源MAC地址（6字节）
- `dst_mac`: 目标MAC地址（6字节）
- `src_ip_nbo`: 源IPv4（4字节，网络字节序）
- `dst_ip_nbo`: 目标IPv4（4字节，网络字节序）
- `src_port`: 伪造源UDP端口（主机序）
- `dst_port`: 伪造目标UDP端口（主机序）
- `auth`: 认证字段（4字节）
- `packet_len`: 输出：返回数据包的总长度

**返回值**:
- 成功: 分配的数据包缓冲区指针
- 失败: NULL

**警告**: 调用者必须使用gap_free_single_payload()释放返回的指针

#### gap_get_inner
**功能**: 获取隧道数据包的内部载荷指针

**语法**:
```c
static inline tunnel_inner_payload_t* gap_get_inner(const uint8_t *payload, size_t len);
```

**参数**:
- `payload`: 原始载荷数据指针
- `len`: 载荷缓冲区长度

**返回值**:
- 成功: tunnel_inner_payload_t指针
- 失败: NULL（数据不足或参数无效）

#### gap_free_single_payload
**功能**: 安全释放单个隧道数据包

**语法**:
```c
static inline void gap_free_single_payload(tunnel_payload_t *pkt);
```

**参数**:
- `pkt`: 要释放的tunnel_payload_t数据包指针

**返回值**: 无

#### gap_assemble_init
**功能**: 初始化分片重组的全局内存池

**语法**:
```c
int gap_assemble_init(void);
```

**参数**: 无

**返回值**:
- 成功: 0
- 失败: -1（分配失败）

#### gap_assemble_destroy
**功能**: 释放全局内存池

**语法**:
```c
void gap_assemble_destroy(void);
```

**参数**: 无

**返回值**: 无

**说明**: 应在应用程序关闭时调用（如SIGTERM处理器），防止内存泄漏

#### gap_assemble_tunnel_payload
**功能**: 将隧道分片重组为完整的JSON缓冲区

**语法**:
```c
uint8_t* gap_assemble_tunnel_payload(const tunnel_inner_payload_t *frag, size_t *out_full_size);
```

**参数**:
- `frag`: 传入的分片结构指针
- `out_full_size`: 输出参数，存储组装后的总长度

**返回值**:
- 成功: 分配的完整缓冲区指针（调用者必须free）
- 失败: NULL

#### gap_assemble_free_packet
**功能**: 释放由gap_assemble_tunnel_payload返回的缓冲区

**语法**:
```c
void gap_assemble_free_packet(uint8_t *complete_pkt);
```

**参数**:
- `complete_pkt`: gap_assemble_tunnel_payload返回的指针

**返回值**: 无

**说明**: 上层逻辑处理完重组数据后调用

#### gap_assemble_cleanup
**功能**: 定期扫描并清理过期的重组会话

**语法**:
```c
void gap_assemble_cleanup(void *user_data);
```

**参数**:
- `user_data`: 用户数据指针（未使用）

**返回值**: 无

**说明**: 应由定时器或主循环调用，防止僵尸会话占用内存池

---

<a name="cmd-h"></a>
## cmd.h - 命令框架接口

### 概述
命令框架模块提供基于AF_UNIX套接字的管理CLI服务。支持Redis风格的命令解析、注册表绑定、彩色终端输出和后台服务器线程管理。

### 常量定义
```c
#define AFUINX_MAGIC    0x56465354    // 协议魔数
#define MAX_ARG_COUNT   16            // 最大参数数量
#define MAX_RESP_BUF    4096          // 最大响应缓冲区大小
#define AFUINX_VERSION  1             // 协议版本
#define SOCKET_PATH     "/tmp/vfast.sock"  // 默认套接字路径
```

### 颜色输出常量
```c
#define C_DIM     "\001\033[2m\002"      // 暗色
#define C_BOLD    "\001\033[1m\002"      // 粗体
#define C_GRAY    "\001\033[90m\002"     // 灰色
#define C_YELLOW  "\001\033[1;33m\002"   // 黄色
#define C_RESET   "\001\033[0m\002"      // 重置
#define C_GREEN   "\001\033[92m\002"     // 绿色（运行/正常）
#define C_BLUE    "\001\033[94m\002"     // 蓝色（信息）
#define C_MAGENTA "\001\033[95m\002"     // 洋红（配置）
#define C_CYAN    "\001\033[96m\002"     // 青色（指标）
#define C_RED     "\001\033[91m\002"     // 红色（错误）
#define C_ORANGE  "\001\033[38;5;208m\002" // 橙色（警告）
```

### 数据结构

#### afuinx_header_t
工业标准协议头结构
```c
typedef struct {
    uint32_t magic;      // 魔数
    uint16_t type;       // 消息类型
    uint16_t version;    // 版本号
    uint32_t length;     // 载荷长度
} __attribute__((packed)) afuinx_header_t;
```

#### cmd_resp_t
响应缓冲区包装结构（防止字符串连接时溢出）
```c
typedef struct {
    char *buf;           // 缓冲区指针
    size_t size;         // 缓冲区总大小
    size_t offset;       // 当前写入偏移
} cmd_resp_t;
```

#### cmd_handler_t
专业命令处理器签名
```c
typedef int (*cmd_handler_t)(void *ctx, int argc, char **argv, cmd_resp_t *resp);
```

#### cmd_entry_t
命令注册表条目
```c
typedef struct {
    const char *group;      // 命令组名
    const char *name;       // 命令名称
    const char *help;      // 帮助文本
    const char *usage;     // 使用说明
    int min_argc;           // 最小参数数量
    cmd_handler_t handler;  // 处理函数
} cmd_entry_t;
```

### 函数接口

#### cmd_transport_listen
**功能**: 初始化并绑定AF_UNIX流套接字进行管理监听

**语法**:
```c
int cmd_transport_listen(const char *path);
```

**参数**:
- `path`: AF_UNIX套接字的文件系统路径

**返回值**:
- 成功: 监听套接字文件描述符
- 失败: -1

**说明**: 
- 清理已存在的套接字文件
- 创建并绑定套接字
- 开始监听传入连接

#### cmd_transport_connect
**功能**: 通过AF_UNIX套接字连接到远程管理服务器

**语法**:
```c
int cmd_transport_connect(const char *path);
```

**参数**:
- `path`: 服务器套接字的路径

**返回值**:
- 成功: 已连接套接字文件描述符
- 失败: -1

#### cmd_transport_recv
**功能**: 从对等端接收协议数据包

**语法**:
```c
int cmd_transport_recv(int fd, afuinx_header_t *hdr, char **payload);
```

**参数**:
- `fd`: 已连接套接字描述符
- `hdr`: 要填充的头结构指针
- `payload`: 输出参数，指向堆分配缓冲区的指针（调用者负责free）

**返回值**:
- 成功: 0
- 失败: -1（协议错误或连接断开）

**说明**: 
- 先读取固定大小头确定载荷大小
- 分配内存读取载荷
- 包含超时保护和缓冲区溢出保护

#### cmd_transport_send
**功能**: 使用VFast封装协议发送数据

**语法**:
```c
int cmd_transport_send(int fd, uint16_t type, const char *data, uint32_t len);
```

**参数**:
- `fd`: 已连接套接字描述符
- `type`: 协议消息类型
- `data`: 载荷数据指针
- `len`: 载荷长度（字节）

**返回值**:
- 成功: 0
- 失败: -1

**说明**: 使用MSG_NOSIGNAL防止管道破裂时进程终止

#### cmd_dispatch
**功能**: 将原始输入字符串分派到对应业务处理器

**语法**:
```c
int cmd_dispatch(void *ctx, char *input, char *output, size_t max_len);
```

**参数**:
- `ctx`: 用户定义的上下文（引擎对象指针）
- `input`: 原始null结尾命令字符串
- `output`: 存储响应的输出缓冲区指针
- `max_len`: 输出缓冲区大小

**返回值**:
- 成功: 处理器返回码
- 失败: -1（命令未知或格式错误）

**说明**: 
- 执行参数标记化（Redis风格）
- 命令表查找
- 参数数量验证
- 执行关联回调函数

#### cmd_register_table
**功能**: 绑定静态命令注册表到框架内部调度器

**语法**:
```c
void cmd_register_table(const cmd_entry_t *table);
```

**参数**:
- `table`: NULL结尾的cmd_entry_t数组指针

**返回值**: 无

#### cmd_resp_printf
**功能**: 线程安全的格式化打印到响应上下文

**语法**:
```c
void cmd_resp_printf(cmd_resp_t *r, const char *fmt, ...);
```

**参数**:
- `r`: 命令响应上下文指针
- `fmt`: printf风格格式字符串
- `...`: 可变参数

**返回值**: 无

**说明**: 追加格式化文本到内部响应缓冲区，确保不超过缓冲区容量

#### cmd_resp_red
**功能**: 错误消息输出（红色）

**语法**:
```c
void cmd_resp_red(cmd_resp_t *r, const char *fmt, ...);
```

**参数**:
- `r`: 命令响应上下文指针
- `fmt`: printf风格格式字符串
- `...`: 可变参数

**返回值**: 无

**说明**: 使用ANSI转义码生成红色输出，确保颜色代码不干扰缓冲区限制

#### cmd_resp_green
**功能**: 成功消息输出（绿色）

**语法**:
```c
void cmd_resp_green(cmd_resp_t *r, const char *fmt, ...);
```

**参数**:
- `r`: 命令响应上下文指针
- `fmt`: printf风格格式字符串
- `...`: 可变参数

**返回值**: 无

**说明**: 与cmd_resp_red类似，使用绿色表示正向状态

#### cmd_resp_cyan
**功能**: 信息消息输出（青色）

**语法**:
```c
void cmd_resp_cyan(cmd_resp_t *r, const char *fmt, ...);
```

**参数**:
- `r`: 命令响应上下文指针
- `fmt`: printf风格格式字符串
- `...`: 可变参数

**返回值**: 无

**说明**: 使用青色区分信息输出与错误和成功消息

#### cmd_group_help
**功能**: 生成特定命令组的格式化帮助消息

**语法**:
```c
int cmd_group_help(const char *group, cmd_resp_t *resp);
```

**参数**:
- `group`: 组名过滤器（NULL显示根命令）
- `resp`: 响应上下文指针

**返回值**:
- 成功: 0
- 失败: -1

#### cmd_handle_help
**功能**: HELP命令的标准处理器

**语法**:
```c
int cmd_handle_help(void *ctx, int argc, char **argv, cmd_resp_t *resp);
```

**参数**:
- `ctx`: 用户上下文
- `argc`: 参数数量
- `argv`: 参数向量
- `resp`: 响应上下文

**返回值**: 处理器返回码

**说明**: 支持通用帮助(HELP)和分组帮助(HELP \<group\>)

#### cmd_server_start
**功能**: 启动后台管理线程处理CLI请求

**语法**:
```c
pthread_t cmd_server_start(void *user_ctx);
```

**参数**:
- `user_ctx`: 主应用程序状态/数据结构指针

**返回值**:
- 成功: 创建的线程ID
- 失败: 0

**说明**: 
- "即发即忘"函数
- 在堆上分配线程参数
- 创建分离态pthread
- 启动套接字接受循环

**注意**: 调用者负责使用cmd_server_stop()清理

#### cmd_server_stop
**功能**: 优雅终止CLI服务器线程

**语法**:
```c
void cmd_server_stop(pthread_t *ptid);
```

**参数**:
- `ptid`: 要加入并重置的线程ID指针

**返回值**: 无

---

<a name="af-unix-h"></a>
## af_unix.h - Unix域服务器接口

### 概述
Unix域服务器模块提供通过AF_UNIX套接字获取Red LRM服务内部状态信息的功能。用于健康服务监控和系统状态收集。

### 数据结构

#### lrm_internal_status_t
内部状态结构
```c
typedef struct {
    uint16_t version_major;    // 主版本号
    uint16_t version_minor;    // 副版本号
    uint32_t mem_usage_kb;    // 内存占用（KB）
    uint16_t cpu_load;        // CPU负载百分比（0-100）
    uint16_t custom_err;      // 内部错误码
} __attribute__((packed)) lrm_internal_status_t;
```

### 函数接口

#### lrm_unix_server_start
**功能**: 初始化并启动AF_UNIX遥测服务器

**语法**:
```c
int lrm_unix_server_start(int interval_ms);
```

**参数**:
- `interval_ms`: 数据采集间隔（毫秒，最小10ms）

**返回值**:
- 成功: 0
- 失败: -1

**说明**:
- 创建后台线程处理来自健康服务的连接
- 定期收集系统状态信息

#### lrm_unix_server_stop
**功能**: 停止服务器并清理资源（取消链接套接字文件）

**语法**:
```c
void lrm_unix_server_stop(void);
```

**参数**: 无

**返回值**: 无

---

<a name="pkteng-h"></a>
## pkteng.h - 数据包引擎接口

### 概述
数据包引擎模块提供红黑区域之间的高性能双向流量处理。包括会话管理、隧道封装/解封装、OPE（操作）数据转发和控制消息处理。

### 常量定义

#### pkt_port_enum
隧道引擎端口枚举
```c
enum pkt_port_enum {
    PKT_OPE_SRC_PORT = 58888U,     // 操作源端口
    PKT_OPE_DST_PORT = 59999U,      // 操作目标端口
    PKT_CTRL_SRC_PORT = 60002U,     // 控制源端口
    PKT_CTRL_DST_PORT = 50002U,     // 控制目标端口
    PKT_ADD_PORT = 6013U,           // 添加端口
};
```

### 函数接口

#### pkt_send_ope_to_black
**功能**: 封装并转发红区数据到黑区

**语法**:
```c
bool pkt_send_ope_to_black(const pkt_info_t *info);
```

**参数**:
- `info`: 解析后的数据包元数据指针（IP、端口、载荷）

**返回值**:
- 成功: true
- 失败: false

**说明**:
- 解析传入的数据包
- 更新会话管理器
- 将载荷封装为隧道格式
- 通过UDP发送到黑区管理节点

#### pkt_reverse_ope_to_red
**功能**: 解封装黑区返回数据并路由回红区

**语法**:
```c
bool pkt_reverse_ope_to_red(const pkt_info_t *info);
```

**参数**:
- `info`: 从隧道接收的数据包信息

**返回值**:
- 成功: true
- 失败: false

**说明**:
- 执行隧道解封装
- 执行会话查找识别原始红区源
- 将原始数据转发给原始请求者

#### pkt_send_ctrl_to_black
**功能**: 发送控制数据包到黑区

**语法**:
```c
bool pkt_send_ctrl_to_black(const pkt_info_t *info);
```

**参数**:
- `info`: 解析后的控制数据包信息

**返回值**:
- 成功: true
- 失败: false

**说明**:
- 处理管理和控制消息
- 如会话更新或配置命令
- 应用必要的系统状态更改

#### pkt_reverse_ctrl_to_red
**功能**: 处理从黑区接收的控制数据包

**语法**:
```c
bool pkt_reverse_ctrl_to_red(const pkt_info_t *info);
```

**参数**:
- `info`: 解析后的控制数据包信息

**返回值**:
- 成功: true
- 失败: false

#### pkt_reverse_raise_to_red
**功能**: 处理从黑区接收的raise消息

**语法**:
```c
bool pkt_reverse_raise_to_red(const pkt_info_t *info);
```

**参数**:
- `info`: 解析后的数据包信息

**返回值**:
- 成功: true
- 失败: false

#### pkt_send_raise_to_black
**功能**: 发送raise消息到黑区

**语法**:
```c
bool pkt_send_raise_to_black(const pkt_info_t *info);
```

**参数**:
- `info`: 解析后的raise消息信息

**返回值**:
- 成功: true
- 失败: false

**说明**: 处理需要升级到红区的关键警报或状态变更

#### pkt_send_ctrl54_to_black
**功能**: 发送CTRL54类型控制数据包到黑区

**语法**:
```c
bool pkt_send_ctrl54_to_black(const pkt_info_t *info);
```

**参数**:
- `info`: 解析后的CTRL54数据包信息

**返回值**:
- 成功: true
- 失败: false

**说明**: 处理CTRL54类型的控制命令或警报消息

#### pkt_reverse_ctrl54_to_red
**功能**: 处理从黑区接收的CTRL54控制数据包

**语法**:
```c
bool pkt_reverse_ctrl54_to_red(const pkt_info_t *info);
```

**参数**:
- `info`: 解析后的CTRL54数据包信息

**返回值**:
- 成功: true
- 失败: false

**说明**: 解封装并路由CTRL54类型的控制响应消息

#### pkt_set_object
**功能**: 配置数据包引擎的系统对象

**语法**:
```c
void pkt_set_object(
    session_manager_t *const sm,       
    auth_t *const auth,                
    gc_probe_processor_t *const gp,    
    udp_conn_t *const conn,            
    raw_sock_t *const rawsock,
    const uint16_t port,                
    const uint32_t localip,
    const uint8_t *const localmac
);
```

**参数**:
- `sm`: 会话管理器指针（线程安全实例）
- `auth`: 认证服务指针
- `gp`: GC探测处理器指针
- `conn`: 共享UDP连接句柄指针
- `rawsock`: 原始套接字指针
- `port`: 目标隧道端口
- `localip`: 用于封装的静态本地IP
- `localmac`: 6字节源MAC地址指针

**返回值**: 无

---

<a name="session-manager-h"></a>
## session_manager.h - 会话管理接口

### 概述
会话管理器模块提供双向网络流跟踪功能，支持隔离网络区域之间的源路由和状态检查。使用uthash实现高效的海象表查找。

### 数据结构

#### session_key_t
会话键结构
```c
typedef struct {
    uint16_t v_port;    // 隧道内分配的唯一虚拟端口/会话ID
    uint8_t  rcp_id;   // 与会话关联的RCP ID
} __attribute__((packed)) session_key_t;
```

#### session_context_t
会话上下文结构
```c
typedef struct {
    uint32_t src_ip;        // 红区原始源IP地址
    uint16_t src_port;     // 红区原始源端口
    uint8_t  src_mac[6];   // 红区原始源MAC地址
    uint32_t dst_ip;        // 红区原始目标IP地址
    uint16_t dst_port;     // 红区原始目标端口
    uint8_t  dst_mac[6];   // 红区原始目标MAC地址
    uint64_t last_seen;    // 最后活动时间（毫秒）
} session_context_t;
```

#### session_entry_t
哈希表条目结构
```c
typedef struct {
    session_key_t key;          // 哈希键（查找条件）
    session_context_t ctx;       // 哈希值（会话数据）
    UT_hash_handle hh;          // uthash句柄
} session_entry_t;
```

#### session_manager_t
会话管理器句柄
```c
typedef struct {
    session_entry_t *table;     // 哈希表头指针
    pthread_rwlock_t rwlock;    // 读写锁（线程安全访问）
    uint32_t timeout_ms;        // 会话超时阈值（毫秒）
} session_manager_t;
```

### 函数接口

#### session_mgr_create
**功能**: 创建新的会话管理器实例

**语法**:
```c
session_manager_t* session_mgr_create(uint32_t timeout_ms);
```

**参数**:
- `timeout_ms`: 会话空闲超时阈值（毫秒）

**返回值**:
- 成功: 初始化后的会话管理器指针
- 失败: NULL

#### session_mgr_destroy
**功能**: 销毁会话管理器并释放所有关联内存

**语法**:
```c
void session_mgr_destroy(session_manager_t *mgr);
```

**参数**:
- `mgr`: 要销毁的会话管理器指针

**返回值**: 无

#### session_mgr_update
**功能**: 更新现有会话或插入新会话

**语法**:
```c
void session_mgr_update(session_manager_t *mgr, const session_key_t *key, const session_context_t *ctx);
```

**参数**:
- `mgr`: 会话管理器指针
- `key`: 会话查找键指针
- `ctx`: 会话上下文数据指针

**返回值**: 无

**说明**: 在红区 -> 黑区转发路径中调用

#### session_mgr_lookup
**功能**: 使用键查找会话上下文

**语法**:
```c
bool session_mgr_lookup(session_manager_t *mgr, const session_key_t *key, session_context_t *out_ctx);
```

**参数**:
- `mgr`: 会话管理器指针
- `key`: 会话查找键指针
- `out_ctx`: 存储找到的会话上下文的输出指针

**返回值**:
- 会话存在: true
- 不存在: false

**说明**: 在黑区返回路径中调用，用于查找原始源

#### session_mgr_aging
**功能**: 过期会话老化处理

**语法**:
```c
void session_mgr_aging(session_manager_t *mgr);
```

**参数**:
- `mgr`: 会话管理器指针

**返回值**: 无

**说明**: 应在工作线程或主循环中定期调用，以清理过期条目

---

## 版本历史

| 版本 | 日期 | 修改内容 |
|------|------|----------|
| v1.2 | 2026-03-06 | 新增 af_unix.h、pkteng.h、session_manager.h 接口 |
| v1.1 | 2026-03-06 | 新增 xdp/xdp_pkt_parser.h 数据包解析接口 |
| v1.0 | 2026-02-06 | 初始版本，包含所有核心接口 |

## 联系信息

- **项目**: Red-LRM
- **作者**: Red-LRM Team
- **版权**: © 2026 Red-LRM. All rights reserved.

---

*本文档基于源代码中的接口定义自动生成，仅包含指定的核心头文件。*