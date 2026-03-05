# Afterglow Judge Sandbox

一个基于 containerd 的代码评测引擎：接收源代码和多组测试数据，完成编译、隔离执行、输出比对和聚合判定。

## 特性

- 安全隔离：基于 containerd 运行用户程序
- 多语言：C / C++ / Java / Python
- 多测试点：逐点评测并返回明细
- 结果聚合：支持 `OK` / `WrongAnswer` / `CompileError` / `TimeLimitExceeded` 等判定
- HTTP API：统一 Web 服务入口

## 快速开始

```bash
# 构建
go build -o server ./cmd/server

# 启动服务
./server

# 调用评测 API
curl -X POST http://localhost:8080/v1/execute \
  -H "Content-Type: application/json" \
  -d '{
    "sourceCode": "import sys\\nn=int(sys.stdin.readline())\\nprint(n*2)",
    "language": "Python",
    "timeLimit": 1000,
    "memoryLimit": 256,
    "testcases": [
      {"name": "case-1", "inputText": "21\\n", "expectedOutputText": "42\\n"},
      {"name": "case-2", "inputText": "7\\n", "expectedOutputText": "14\\n"}
    ]
  }'
```

## 架构

```
cmd/
└── server/                     # HTTP 服务入口

internal/
├── model/                      # 领域模型（JudgeRequest/JudgeResult/Verdict）
├── service/
│   ├── compiler.go             # 源码编译（按语言）
│   ├── judge_service.go        # 编译 + 逐点评测 + 比对 + 聚合
│   └── containerd_runner.go    # 单次容器执行引擎
├── transport/httptransport/    # HTTP handler/dto/server
├── concurrency/                # 并发限制
└── config/                     # 配置
```

## HTTP API

### 评测代码

```http
POST /v1/execute
Content-Type: application/json
```

请求体：

```json
{
  "sourceCode": "<源代码纯文本>",
  "language": "C++",
  "timeLimit": 1000,
  "memoryLimit": 256,
  "testcases": [
    {
      "name": "case-1",
      "inputText": "1 2\n",
      "expectedOutputText": "3\n"
    }
  ]
}
```

响应体：

```json
{
  "verdict": "WrongAnswer",
  "compile": {
    "succeeded": true,
    "log": ""
  },
  "cases": [
    {
      "name": "case-1",
      "verdict": "WrongAnswer",
      "stdout": "4\n",
      "timeUsed": 12,
      "memoryUsed": 8,
      "exitCode": 0,
      "extraInfo": "stdout does not match expected output"
    }
  ],
  "passedCount": 0,
  "totalCount": 1
}
```

### 判定类型

- `OK`
- `WrongAnswer`
- `CompileError`
- `TimeLimitExceeded`
- `MemoryLimitExceeded`
- `OutputLimitExceeded`
- `RuntimeError`
- `UnknownError`

### 健康检查

```http
GET /health
```

## 配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `HTTP_ADDR` | `0.0.0.0` | 监听地址 |
| `HTTP_PORT` | `8080` | 监听端口 |
| `HTTP_READ_TIMEOUT` | `30s` | 读取超时 |
| `HTTP_WRITE_TIMEOUT` | `30s` | 写入超时 |
| `HTTP_SHUTDOWN_TIMEOUT` | `10s` | 关闭超时 |
| `CONTAINERD_SOCKET` | `/run/containerd/containerd.sock` | Containerd 套接字 |
| `MAX_CONCURRENT_EXECUTIONS` | `10` | 最大并发评测任务数 |
| `MAX_INPUT_SIZE_MB` | `256` | 最大请求体限制 |
| `ENABLE_AUTH` | `false` | 启用 API Key 认证 |
| `API_KEYS` | - | API Key 列表（逗号分隔） |
| `ALLOWED_ORIGINS` | `*` | CORS 允许来源 |
| `LOG_LEVEL` | `info` | 日志级别 |

## 开发

```bash
# 单元 + 集成测试
go test -count=1 ./...

# 代码检查
golangci-lint run
```

E2E 测试依赖 root + containerd：

```bash
sudo -n go test -v ./internal/transport/httptransport -run TestE2E
```
