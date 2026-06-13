# Luvv MCPServer — 生产级安全审计 MCP 工具

封装 **semgrep** (SAST) + **gitleaks** (密钥检测)，通过 **MCP stdio 协议** 为 Claude Desktop 提供一键代码安全扫描能力。

## 功能特性

- `run_security_scan` 工具：传入目标目录路径，自动并行执行 semgrep + gitleaks
- 返回合并的结构化 JSON 审计报告（含摘要统计）
- 依赖工具未安装时，报告中自动附带各平台的安装指引
- 所有异常/日志通过 stderr 输出，绝不污染 MCP 协议通道（stdout）
- 内置路径安全校验，拒绝扫描系统敏感目录
- Docker 环境隔离支持，预装全部依赖

## 快速开始

### 1. 环境要求

| 组件 | 版本要求 |
|------|---------|
| Node.js | >= 20.0.0 LTS |
| npm | >= 10.0.0 |
| semgrep | >= 1.0（可选，未安装在报告中提示） |
| gitleaks | >= 8.0（可选，未安装在报告中提示） |

### 2. 安装依赖与编译

```bash
# 克隆项目（或直接进入目录）
cd luvv-mcp-server

# 安装 npm 依赖
npm install

# 编译 TypeScript
npm run build
```

编译产物输出到 `dist/` 目录，入口文件 `dist/main.js`。

### 3. 安装扫描工具（推荐）

```bash
# --- semgrep ---
# macOS
brew install semgrep

# Linux
pipx install semgrep
# 或: pip install semgrep

# --- gitleaks ---
# macOS
brew install gitleaks

# Linux
wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.18.4_linux_x64.tar.gz
tar -xzf gitleaks_*.tar.gz -C /usr/local/bin/ gitleaks
chmod +x /usr/local/bin/gitleaks

# --- 验证安装 ---
semgrep --version
gitleaks version
```

> 如果未安装 semgrep 或 gitleaks，扫描仍可运行，但对应工具的结果中会包含 `available: false` 及安装提示。

### 4. 在 Claude Desktop 中配置

打开 Claude Desktop 配置文件：

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

添加以下配置块：

```json
{
  "mcpServers": {
    "luvv-security-scanner": {
      "command": "node",
      "args": [
        "/Users/你的用户名/luvv-mcp-server/dist/main.js"
      ]
    }
  }
}
```

**实际路径示例**（macOS 用户 `zhangsan`）：

```json
{
  "mcpServers": {
    "luvv-security-scanner": {
      "command": "node",
      "args": [
        "/Users/zhangsan/luvv-mcp-server/dist/main.js"
      ]
    }
  }
}
```

**实际路径示例**（Windows 用户 `Administrator`）：

```json
{
  "mcpServers": {
    "luvv-security-scanner": {
      "command": "node",
      "args": [
        "C:\\Users\\Administrator\\luvv-mcp-server\\dist\\main.js"
      ]
    }
  }
}
```

配置完成后，**重启 Claude Desktop**。在对话中输入"帮我扫描 /path/to/project 的安全问题"，Claude 会自动调用 `run_security_scan` 工具。

### 5. 验证 MCP 连接

启动 Claude Desktop 后，检查工具栏是否出现新工具图标（锤子），或在对话中尝试：

```
请列出你当前可用的 MCP 工具
```

如果看到 `run_security_scan`，说明连接成功。

---

## Docker 运行方式

Docker 镜像已预装 semgrep + gitleaks，适合环境隔离或 CI/CD 集成。

### 构建镜像

```bash
docker compose build
```

### 交互式运行（手动测试）

```bash
# 启动容器并进入交互式 stdio 模式
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | \
  docker compose run --rm -T mcp
```

### 通过管道发送扫描请求

```bash
# 构造一个扫描请求的 MCP 消息
cat <<'JSONRPC' | docker compose run --rm -T mcp
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_security_scan","arguments":{"target_path":"/scan"}}}
JSONRPC
```

### 扫描本地代码

```bash
# 将本地项目挂载为 /scan
SCAN_TARGET=$(pwd) docker compose run --rm mcp
```

---

## 输出示例

```json
{
  "target_path": "/home/user/my-project",
  "resolved_path": "/home/user/my-project",
  "scan_time": "2026-06-13T12:00:00.000Z",
  "duration_ms": 12345,
  "tools": {
    "semgrep": {
      "available": true,
      "results": {
        "results": [
          {
            "check_id": "python.lang.security.audit.dangerous-subprocess-use",
            "path": "src/utils.py",
            "start": { "line": 42 },
            "end": { "line": 42 },
            "extra": {
              "severity": "ERROR",
              "message": "Detected subprocess function without a static string"
            }
          }
        ]
      }
    },
    "gitleaks": {
      "available": true,
      "results": [
        {
          "RuleID": "generic-api-key",
          "Description": "Generic API Key",
          "File": "config.py",
          "StartLine": 15,
          "Secret": "***REDACTED***",
          "Match": "sk_live_xxxxxxxxxxxx"
        }
      ]
    }
  },
  "summary": {
    "total_findings": 2,
    "semgrep_findings": 1,
    "gitleaks_findings": 1
  },
  "environment": {
    "node_version": "v20.14.0",
    "platform": "linux",
    "hostname": "dev-machine"
  }
}
```

当工具未安装时：

```json
{
  "tools": {
    "semgrep": {
      "available": false,
      "error": "semgrep 未安装或不在 PATH 中",
      "install_hint": "# macOS\nbrew install semgrep\n\n# Linux (pip)\npip install semgrep"
    }
  }
}
```

---

## 环境变量

参见 `.env.example`，可复制为 `.env` 后修改：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SEMGREP_CONFIG` | `auto` | semgrep 规则集（`p/security-audit`、`p/owasp-top-ten` 等） |
| `SEMGREP_TIMEOUT` | `300` | semgrep 超时时间（秒） |
| `GITLEAKS_TIMEOUT` | `120` | gitleaks 超时时间（秒） |
| `LOG_LEVEL` | `info` | 日志级别（debug/info/warn/error） |
| `INCLUDE_RAW_OUTPUT` | `false` | 是否返回完整原始输出 |

---

## 项目结构

```
luvv-mcp-server/
├── src/
│   ├── main.ts               # CLI 入口，按参数路由传输模式
│   ├── server.ts              # createServer() 工厂函数
│   ├── tools/
│   │   ├── index.ts           # registerAllTools() 汇总
│   │   └── run-security-scan.ts  # 安全扫描工具定义与处理器
│   ├── transports/
│   │   └── stdio.ts           # stdio 传输启动器（+ 信号处理）
│   └── lib/
│       ├── logger.ts          # 结构化 stderr 日志
│       ├── executor.ts        # spawn 封装 + 路径校验
│       └── scanner.ts         # semgrep + gitleaks 编排
├── tests/
│   └── run-security-scan.test.ts  # 单元测试
├── dist/                      # 编译产物（npm run build）
├── vitest.config.ts
├── package.json
├── tsconfig.json
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

## License

MIT
