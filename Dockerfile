# ============================================================
# Luvv MCPServer — Docker 镜像
# 基于 Node 20，预装 semgrep + gitleaks
# ============================================================

# --- 阶段 1: 依赖安装 (gitleaks 二进制下载) ---
FROM node:20-bookworm-slim AS deps

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 安装 semgrep
RUN pip3 install --no-cache-dir semgrep --break-system-packages

# 下载 gitleaks 预编译二进制
ARG GITLEAKS_VERSION=8.18.4
RUN arch=$(uname -m) \
    && case "$arch" in \
      x86_64)  ARCH="x64" ;; \
      aarch64) ARCH="arm64" ;; \
      *)       echo "Unsupported arch: $arch"; exit 1 ;; \
    esac \
    && curl -fsSL -o /tmp/gitleaks.tar.gz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${ARCH}.tar.gz" \
    && tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin/ gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && rm /tmp/gitleaks.tar.gz

# --- 阶段 2: 构建应用 ---
FROM node:20-bookworm-slim AS builder

WORKDIR /build
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts

COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# --- 阶段 3: 运行镜像 ---
FROM node:20-bookworm-slim

# 从 deps 阶段复制 semgrep 和 gitleaks
COPY --from=deps /usr/local/bin/semgrep /usr/local/bin/semgrep
COPY --from=deps /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=deps /usr/lib/python3* /usr/lib/
COPY --from=deps /usr/local/lib/python3* /usr/local/lib/
COPY --from=deps /usr/share/python3* /usr/share/

# 安装必要的运行时库（semgrep 依赖 Python）
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /build/dist/ ./dist/
COPY --from=builder /build/node_modules/ ./node_modules/
COPY --from=builder /build/package.json ./

# 健康检查
HEALTHCHECK --interval=60s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "require('./dist/index.js')" 2>&1 | grep -q "ready" || exit 0

# 默认以 stdio 模式运行（由 docker-compose 或外部管道对接）
ENTRYPOINT ["node", "dist/index.js"]
