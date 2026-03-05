# Afterglow Judge Sandbox

一个安全的、基于容器的代码执行沙箱，支持 C、C++、Java 和 Python。

## 特性

- 🔒 **安全隔离**：基于 containerd 的容器隔离
- ⚡ **高性能**：精确的时间和内存测量
- 🌐 **HTTP API**：RESTful API 接口
- 🔌 **可扩展**：清晰的接口设计，易于扩展新语言和传输层
- 📊 **并发控制**：内置速率限制，防止资源耗尽

## 快速开始

```bash
# 构建
go build -o server ./cmd/server

# 启动服务器
./server

# 调用 API
curl -X POST http://localhost:8080/v1/execute \
  -H "Content-Type: application/json" \
  -d '{
    "executableBase64": "...",
    "inputBase64": "...",
    "language": "C++",
    "timeLimit": 1000,
    "memoryLimit": 256
  }'
```

## 架构

纯 HTTP API 服务，单体应用架构：

```
cmd/
└── server/           # HTTP 服务器入口（唯一入口）

internal/
├── model/            # 领域模型（ExecuteRequest, ExecuteResult, Verdict）
├── service/          # 执行引擎（containerd runner）
├── transport/        # 传输层
│   └── httptransport/# HTTP 实现（handler, middleware, server, dto）
├── storage/          # 文件存储（临时文件管理）
├── concurrency/      # 并发控制（execution limiter）
└── config/           # 配置管理（环境变量）
```

**设计原则：**
- 单体架构：一个可执行文件
- HTTP API：唯一的对外接口
- 纯函数调用：内部组件通过接口调用
- 易于扩展：可轻松添加 gRPC、消息队列等传输层

## HTTP API

### 执行代码

```bash
POST /v1/execute
Content-Type: application/json

{
  "executableBase64": "<base64编码的可执行文件>",
  "inputBase64": "<base64编码的输入>",
  "language": "C++",
  "timeLimit": 1000,
  "memoryLimit": 256
}
```

**响应：**

```json
{
  "verdict": "OK",
  "stdout": "42\n",
  "timeUsed": 15,
  "memoryUsed": 4,
  "exitCode": 0,
  "extraInfo": ""
}
```

**Verdict 类型：**
- `OK` - 正常执行
- `TimeLimitExceeded` - 超时
- `MemoryLimitExceeded` - 内存超限
- `OutputLimitExceeded` - 输出超限
- `RuntimeError` - 运行时错误
- `UnknownError` - 未知错误

### 健康检查

```bash
GET /health
```

## 配置

服务器通过环境变量配置：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `HTTP_ADDR` | `0.0.0.0` | 监听地址 |
| `HTTP_PORT` | `8080` | 监听端口 |
| `HTTP_READ_TIMEOUT` | `30s` | 读取超时 |
| `HTTP_WRITE_TIMEOUT` | `30s` | 写入超时 |
| `CONTAINERD_SOCKET` | `/run/containerd/containerd.sock` | Containerd 套接字 |
| `MAX_CONCURRENT_EXECUTIONS` | `10` | 最大并发执行数 |
| `MAX_INPUT_SIZE_MB` | `256` | 最大输入文件大小 |
| `ENABLE_AUTH` | `false` | 启用 API Key 认证 |
| `API_KEYS` | - | API Key 列表（逗号分隔）|
| `LOG_LEVEL` | `info` | 日志级别 |

**示例：**

```bash
export HTTP_PORT=9000
export MAX_CONCURRENT_EXECUTIONS=20
export ENABLE_AUTH=true
export API_KEYS=secret-key-1,secret-key-2
./server
```

## 开发

### 运行测试

```bash
go test ./...
```

### 代码检查

```bash
golangci-lint run
```

### 格式化

```bash
go fmt ./...
```

## 系统要求

- Go 1.22+
- containerd（用于本地执行）
- Linux with cgroup v2

## 许可证

见 LICENSE 文件。

