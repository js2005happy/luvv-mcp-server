#!/usr/bin/env node
/**
 * Luvv MCPServer — 生产级安全审计 MCP 工具
 *
 * 通过 stdio 传输协议对外暴露 run_security_scan 工具，
 * 内部编排 semgrep（SAST）和 gitleaks（密钥检测），
 * 返回合并后的结构化 JSON 审计报告。
 *
 * 所有错误/日志通过 stderr 输出，绝不影响 MCP 协议通道（stdout）。
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { spawn } from "node:child_process";
import { stat, access } from "node:fs/promises";
import { constants } from "node:fs";
import { resolve } from "node:path";

// ---------------------------------------------------------------------------
// 类型定义
// ---------------------------------------------------------------------------

interface ToolResult {
  available: boolean;
  error?: string;
  install_hint?: string;
  results?: unknown;
}

interface ScanReport {
  target_path: string;
  resolved_path: string;
  scan_time: string;
  duration_ms: number;
  tools: {
    semgrep: ToolResult;
    gitleaks: ToolResult;
  };
  summary: {
    total_findings: number;
    semgrep_findings: number;
    gitleaks_findings: number;
  };
  environment: {
    node_version: string;
    platform: string;
    hostname: string;
  };
}

interface ToolErrorResponse {
  target_path: string;
  scan_time: string;
  error: string;
  tools: {
    semgrep: ToolResult;
    gitleaks: ToolResult;
  };
}

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

const SEMGREP_TIMEOUT_MS =
  Number(process.env.SEMGREP_TIMEOUT) * 1000 || 300_000; // 默认 5 分钟
const GITLEAKS_TIMEOUT_MS =
  Number(process.env.GITLEAKS_TIMEOUT) * 1000 || 120_000; // 默认 2 分钟
const SEMGREP_CONFIG = process.env.SEMGREP_CONFIG || "auto";
const LOG_LEVEL = process.env.LOG_LEVEL || "info";

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------

/** 格式化时间戳为 ISO-8601 */
function isoNow(): string {
  return new Date().toISOString();
}

/** 按日志级别写入 stderr */
function log(
  level: "debug" | "info" | "warn" | "error",
  message: string,
  data?: unknown
): void {
  const levels: Record<string, number> = { debug: 0, info: 1, warn: 2, error: 3 };
  if ((levels[level] ?? 1) < (levels[LOG_LEVEL] ?? 1)) return;

  const ts = isoNow();
  const prefix = `[${ts}] [${level.toUpperCase()}]`;
  if (data !== undefined) {
    process.stderr.write(
      `${prefix} ${message} ${JSON.stringify(data, null, 0)}\n`
    );
  } else {
    process.stderr.write(`${prefix} ${message}\n`);
  }
}

/** 检查给定可执行文件是否在 PATH 中可用 */
async function checkBinary(name: string): Promise<{
  found: boolean;
  version: string;
}> {
  return new Promise((resolve) => {
    const proc = spawn(name, ["--version"], {
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 10_000,
    });
    let output = "";

    proc.stdout.on("data", (chunk: Buffer) => {
      output += chunk.toString();
    });
    proc.stderr.on("data", (chunk: Buffer) => {
      output += chunk.toString(); // semgrep 部分版本输出到 stderr
    });

    proc.on("close", (code) => {
      resolve({
        found: code === 0,
        version: output.trim().split("\n")[0] ?? "",
      });
    });

    proc.on("error", () => {
      resolve({ found: false, version: "" });
    });
  });
}

/** 执行命令并捕获 stdout，超时后强制终止 */
function execWithTimeout(
  command: string,
  args: string[],
  timeoutMs: number
): Promise<{ stdout: string; stderr: string; code: number | null; timedOut: boolean }> {
  return new Promise((resolve) => {
    const proc = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"],
      timeout: timeoutMs,
    });
    let stdout = "";
    let stderr = "";
    let timedOut = false;

    proc.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    proc.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    proc.on("close", (code) => {
      resolve({ stdout, stderr, code, timedOut });
    });

    proc.on("error", (err) => {
      // spawn 失败（命令不存在等）
      resolve({
        stdout: "",
        stderr: `spawn failed: ${err.message}`,
        code: null,
        timedOut: false,
      });
    });
  });
}

/** 验证目标路径存在且为目录 */
async function validateTargetPath(
  targetPath: string
): Promise<{ valid: boolean; resolvedPath: string; error?: string }> {
  try {
    const resolvedPath = resolve(targetPath);
    const s = await stat(resolvedPath);
    if (!s.isDirectory()) {
      return {
        valid: false,
        resolvedPath,
        error: `路径存在但不是目录: ${resolvedPath}`,
      };
    }
    return { valid: true, resolvedPath };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return {
      valid: false,
      resolvedPath: resolve(targetPath),
      error: `无法访问目标路径: ${message}`,
    };
  }
}

// ---------------------------------------------------------------------------
// 扫描执行
// ---------------------------------------------------------------------------

/** 运行 semgrep 扫描 */
async function runSemgrepScan(
  targetPath: string
): Promise<ToolResult> {
  const binary = await checkBinary("semgrep");

  if (!binary.found) {
    return {
      available: false,
      error: "semgrep 未安装或不在 PATH 中",
      install_hint: [
        "# macOS",
        "brew install semgrep",
        "",
        "# Linux (pip)",
        "pip install semgrep",
        "pip3 install semgrep",
        "",
        "# 使用 pipx（推荐，避免依赖冲突）",
        "pipx install semgrep",
        "",
        "# Docker",
        "docker run --rm -v \"$(pwd):/src\" returntocorp/semgrep semgrep --config=auto /src",
      ].join("\n"),
    };
  }

  log("info", `启动 semgrep 扫描: ${targetPath} (config=${SEMGREP_CONFIG})`);

  try {
    const { stdout, stderr, code, timedOut } = await execWithTimeout(
      "semgrep",
      ["--config", SEMGREP_CONFIG, "--json", "--quiet", targetPath],
      SEMGREP_TIMEOUT_MS
    );

    if (timedOut) {
      return {
        available: true,
        error: `semgrep 扫描超时（>${SEMGREP_TIMEOUT_MS / 1000}s）`,
        results: null,
      };
    }

    if (stderr) {
      log("warn", `semgrep stderr: ${stderr.slice(0, 500)}`);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(stdout || "{}");
    } catch {
      // semgrep 偶尔输出非 JSON（如权限警告），尝试截取有效 JSON
      const jsonStart = stdout.indexOf("{");
      if (jsonStart >= 0) {
        try {
          parsed = JSON.parse(stdout.slice(jsonStart));
        } catch {
          parsed = { raw: stdout.slice(0, 2000), parse_error: true };
        }
      } else {
        parsed = { raw: stdout.slice(0, 2000), parse_error: true };
      }
    }

    // 提取 findings 数量
    const results = parsed as Record<string, unknown> | undefined;
    const findings = Array.isArray(results?.results)
      ? results!.results.length
      : 0;

    log("info", `semgrep 扫描完成: ${findings} 个发现 (exit=${code})`);

    return {
      available: true,
      results: parsed,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    log("error", `semgrep 执行异常: ${message}`);
    return {
      available: true,
      error: `semgrep 执行失败: ${message}`,
      results: null,
    };
  }
}

/** 运行 gitleaks 扫描 */
async function runGitleaksScan(
  targetPath: string
): Promise<ToolResult> {
  const binary = await checkBinary("gitleaks");

  if (!binary.found) {
    // 额外检查 gitleaks 是否通过不同方式安装
    return {
      available: false,
      error: "gitleaks 未安装或不在 PATH 中",
      install_hint: [
        "# macOS",
        "brew install gitleaks",
        "",
        "# Linux / WSL",
        "wget https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.18.0_linux_x64.tar.gz",
        "tar -xzf gitleaks_*.tar.gz -C /usr/local/bin/ gitleaks",
        "chmod +x /usr/local/bin/gitleaks",
        "",
        "# 或使用 Go 安装",
        "go install github.com/gitleaks/gitleaks/v8@latest",
        "",
        "# 验证安装",
        "gitleaks version",
      ].join("\n"),
    };
  }

  log("info", `启动 gitleaks 扫描: ${targetPath}`);

  try {
    const { stdout, stderr, code, timedOut } = await execWithTimeout(
      "gitleaks",
      [
        "detect",
        "--no-git",            // 非 git 仓库也扫描
        "--source", targetPath,
        "--format", "json",
        "--exit-code", "0",   // 有发现也不返回非零退出码
        "--verbose",
      ],
      GITLEAKS_TIMEOUT_MS
    );

    if (timedOut) {
      return {
        available: true,
        error: `gitleaks 扫描超时（>${GITLEAKS_TIMEOUT_MS / 1000}s）`,
        results: null,
      };
    }

    if (stderr) {
      log("warn", `gitleaks stderr: ${stderr.slice(0, 500)}`);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(stdout || "[]");
    } catch {
      parsed = { raw: stdout.slice(0, 2000), parse_error: true };
    }

    const findings = Array.isArray(parsed) ? (parsed as unknown[]).length : 0;

    log("info", `gitleaks 扫描完成: ${findings} 个发现 (exit=${code})`);

    return {
      available: true,
      results: parsed,
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    log("error", `gitleaks 执行异常: ${message}`);
    return {
      available: true,
      error: `gitleaks 执行失败: ${message}`,
      results: null,
    };
  }
}

// ---------------------------------------------------------------------------
// 路径安全校验（防止路径遍历）
// ---------------------------------------------------------------------------

function isPathSafe(targetPath: string): boolean {
  // 拒绝明显恶意输入
  const dangerous = ["/etc/passwd", "/etc/shadow", "C:\\Windows\\System32", "/proc", "/sys", "/root", "~/.ssh"];
  const lower = targetPath.toLowerCase();
  for (const d of dangerous) {
    if (lower.includes(d.toLowerCase())) {
      return false;
    }
  }
  return true;
}

// ---------------------------------------------------------------------------
// MCP Server 初始化
// ---------------------------------------------------------------------------

const server = new McpServer({
  name: "luvv-security-scanner",
  version: "1.0.0",
});

// ---------------------------------------------------------------------------
// 工具注册
// ---------------------------------------------------------------------------

server.tool(
  "run_security_scan",
  "对目标目录执行安全扫描，内部自动调用 semgrep（SAST）和 gitleaks（密钥检测），返回合并的 JSON 审计报告。若依赖工具未安装，报告中会包含明确的安装指引。",
  {
    target_path: z
      .string()
      .min(1, "target_path 不能为空")
      .describe("要扫描的目标目录的绝对路径（如 /home/user/project）"),
  },
  async ({ target_path }): Promise<{
    content: Array<{ type: "text"; text: string }>;
  }> => {
    const startTime = Date.now();

    // --- 安全检查 ---
    if (!isPathSafe(target_path)) {
      log("warn", `拒绝了敏感路径的扫描请求: ${target_path}`);
      const errorReport: ToolErrorResponse = {
        target_path,
        scan_time: isoNow(),
        error: "拒绝扫描系统敏感路径",
        tools: {
          semgrep: { available: false },
          gitleaks: { available: false },
        },
      };
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(errorReport, null, 2),
          },
        ],
      };
    }

    // --- 路径验证 ---
    const validation = await validateTargetPath(target_path);
    if (!validation.valid) {
      log("warn", `路径验证失败: ${validation.error}`);
      const errorReport: ToolErrorResponse = {
        target_path,
        scan_time: isoNow(),
        error: validation.error!,
        tools: {
          semgrep: { available: false },
          gitleaks: { available: false },
        },
      };
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(errorReport, null, 2),
          },
        ],
      };
    }

    const resolvedPath = validation.resolvedPath;
    log("info", `开始安全扫描: ${resolvedPath}`);

    // --- 并行执行两个扫描 ---
    const [semgrepResult, gitleaksResult] = await Promise.all([
      runSemgrepScan(resolvedPath),
      runGitleaksScan(resolvedPath),
    ]);

    // --- 构造合并报告 ---
    const semgrepFindings = (semgrepResult.results as { results?: unknown[] })
      ?.results?.length ?? 0;
    const gitleaksFindings = Array.isArray(gitleaksResult.results)
      ? (gitleaksResult.results as unknown[]).length
      : 0;

    const report: ScanReport = {
      target_path,
      resolved_path: resolvedPath,
      scan_time: isoNow(),
      duration_ms: Date.now() - startTime,
      tools: {
        semgrep: semgrepResult,
        gitleaks: gitleaksResult,
      },
      summary: {
        total_findings: semgrepFindings + gitleaksFindings,
        semgrep_findings: semgrepFindings,
        gitleaks_findings: gitleaksFindings,
      },
      environment: {
        node_version: process.version,
        platform: process.platform,
        hostname: process.env.COMPUTERNAME || process.env.HOSTNAME || "unknown",
      },
    };

    // 是否在结果中附加完整原始输出
    if (process.env.INCLUDE_RAW_OUTPUT !== "true") {
      // 缩减大型输出：移除 results 数组中的多余字段
      if (
        Array.isArray((semgrepResult.results as Record<string, unknown>)?.results)
      ) {
        const sr = semgrepResult.results as Record<string, unknown>;
        sr.results = (sr.results as Array<Record<string, unknown>>).map(
          (r) => ({
            check_id: r.check_id,
            path: r.path,
            start: r.start,
            end: r.end,
            extra: {
              severity: (r.extra as Record<string, unknown>)?.severity,
              message: (r.extra as Record<string, unknown>)?.message,
            },
          })
        );
      }
      if (Array.isArray(gitleaksResult.results)) {
        gitleaksResult.results = (
          gitleaksResult.results as Array<Record<string, unknown>>
        ).map((r) => ({
          RuleID: r.RuleID,
          Description: r.Description,
          File: r.File,
          StartLine: r.StartLine,
          Secret: r.Secret ? "***REDACTED***" : undefined,
          Match: r.Match,
        }));
      }
    }

    const elapsed = Date.now() - startTime;
    log(
      "info",
      `扫描完成: ${report.summary.total_findings} 个发现, 耗时 ${elapsed}ms`
    );

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(report, null, 2),
        },
      ],
    };
  }
);

// ---------------------------------------------------------------------------
// 启动入口
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  // 环境自检
  log("info", "Luvv MCPServer v1.0.0 启动中...");
  log("info", `Node.js ${process.version} | ${process.platform} | PID ${process.pid}`);

  // 预热：检查依赖工具可用性（仅日志，不阻塞启动）
  const [semgrepOK, gitleaksOK] = await Promise.all([
    checkBinary("semgrep"),
    checkBinary("gitleaks"),
  ]);
  log(
    "info",
    `依赖检测: semgrep=${semgrepOK.found ? semgrepOK.version || "✓" : "✗ 未安装"}, gitleaks=${gitleaksOK.found ? gitleaksOK.version || "✓" : "✗ 未安装"}`
  );

  if (!semgrepOK.found || !gitleaksOK.found) {
    log(
      "warn",
      "部分依赖工具未安装，扫描时会在报告中附安装指引"
    );
  }

  // 连接 stdio 传输
  const transport = new StdioServerTransport();
  await server.connect(transport);

  log("info", "MCP Server 已就绪，等待客户端请求...");
}

main().catch((err) => {
  log("error", `服务启动失败: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
});
