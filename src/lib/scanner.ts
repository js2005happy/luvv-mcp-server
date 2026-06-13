/**
 * 扫描编排模块 — 封装 semgrep SAST 和 gitleaks 密钥检测的调用逻辑。
 *
 * 设计原则：
 * - 每个扫描器返回统一结构的 ToolResult（含 available / error / install_hint / results）
 * - 工具未安装时不报错，而是在结果中嵌入各平台安装指引
 * - 所有运行时异常在此层兜底，上层（tool handler）只关心组装报告
 */

import { detectBinary, runCommand } from "./executor.js";
import { logger } from "./logger.js";

// ---------------------------------------------------------------------------
// 类型
// ---------------------------------------------------------------------------

export interface ToolResult {
  available: boolean;
  error?: string;
  installGuide?: string;
  findings?: unknown;
}

interface ScanOutcome {
  semgrep: ToolResult;
  gitleaks: ToolResult;
  elapsedMs: number;
}

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

const TIMEOUT_SEMGREP = (Number(process.env.SEMGREP_TIMEOUT) || 300) * 1000;
const TIMEOUT_GITLEAKS = (Number(process.env.GITLEAKS_TIMEOUT) || 120) * 1000;
const RULESET = process.env.SEMGREP_CONFIG || "auto";

// ---------------------------------------------------------------------------
// 安装指引（纯文本，多平台）
// ---------------------------------------------------------------------------

const INSTALL_SEMGREP = [
  "# macOS",
  "brew install semgrep",
  "",
  "# Linux",
  "pipx install semgrep",
  "",
  "# 或通过 pip",
  "pip3 install semgrep",
  "",
  "# Docker（无需本地安装）",
  "docker run --rm -v \"$(pwd):/src\" returntocorp/semgrep semgrep --config=auto /src",
].join("\n");

const INSTALL_GITLEAKS = [
  "# macOS",
  "brew install gitleaks",
  "",
  "# Linux (预编译二进制)",
  "curl -fsSL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.18.4_linux_x64.tar.gz | tar -xz -C /usr/local/bin/ gitleaks",
  "chmod +x /usr/local/bin/gitleaks",
  "",
  "# 或使用 Go 安装",
  "go install github.com/gitleaks/gitleaks/v8@latest",
].join("\n");

// ---------------------------------------------------------------------------
// 扫描器实现
// ---------------------------------------------------------------------------

async function scanSemgrep(target: string): Promise<ToolResult> {
  const bin = await detectBinary("semgrep");

  if (!bin.found) {
    return {
      available: false,
      error: "semgrep 未安装或不在 PATH 中",
      installGuide: INSTALL_SEMGREP,
    };
  }

  logger.info(`semgrep 扫描启动: ${target} (ruleset=${RULESET})`);

  try {
    const { stdout, stderr, exitCode, killed } = await runCommand(
      "semgrep",
      ["--config", RULESET, "--json", "--quiet", target],
      TIMEOUT_SEMGREP,
    );

    if (killed) {
      return {
        available: true,
        error: `扫描超时（>${TIMEOUT_SEMGREP / 1000}s），建议缩小扫描范围`,
      };
    }

    if (stderr) {
      logger.warn(`semgrep stderr: ${stderr.slice(0, 400)}`);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(stdout || "{}");
    } catch {
      // 尝试从混合输出中截取 JSON 段
      const start = stdout.indexOf("{");
      if (start >= 0) {
        try {
          parsed = JSON.parse(stdout.slice(start));
        } catch {
          parsed = { _raw: stdout.slice(0, 2000), _parseError: true };
        }
      } else {
        parsed = { _raw: stdout.slice(0, 2000), _parseError: true };
      }
    }

    const results = (parsed as Record<string, unknown>)?.results;
    const count = Array.isArray(results) ? results.length : 0;
    logger.info(`semgrep 完成: ${count} 个发现 (exit=${exitCode})`);

    return { available: true, findings: parsed };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`semgrep 异常: ${msg}`);
    return { available: true, error: `semgrep 执行失败: ${msg}` };
  }
}

async function scanGitleaks(target: string): Promise<ToolResult> {
  const bin = await detectBinary("gitleaks");

  if (!bin.found) {
    return {
      available: false,
      error: "gitleaks 未安装或不在 PATH 中",
      installGuide: INSTALL_GITLEAKS,
    };
  }

  logger.info(`gitleaks 扫描启动: ${target}`);

  try {
    const { stdout, stderr, exitCode, killed } = await runCommand(
      "gitleaks",
      [
        "detect",
        "--no-git",
        "--source",
        target,
        "--format",
        "json",
        "--exit-code",
        "0",
        "--verbose",
      ],
      TIMEOUT_GITLEAKS,
    );

    if (killed) {
      return {
        available: true,
        error: `扫描超时（>${TIMEOUT_GITLEAKS / 1000}s）`,
      };
    }

    if (stderr) {
      logger.warn(`gitleaks stderr: ${stderr.slice(0, 400)}`);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(stdout || "[]");
    } catch {
      parsed = { _raw: stdout.slice(0, 2000), _parseError: true };
    }

    const count = Array.isArray(parsed) ? (parsed as unknown[]).length : 0;
    logger.info(`gitleaks 完成: ${count} 个发现 (exit=${exitCode})`);

    return { available: true, findings: parsed };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.error(`gitleaks 异常: ${msg}`);
    return { available: true, error: `gitleaks 执行失败: ${msg}` };
  }
}

// ---------------------------------------------------------------------------
// 并行编排入口
// ---------------------------------------------------------------------------

/**
 * 并行执行 semgrep 和 gitleaks，返回合并结果及耗时。
 * 单个扫描器失败不影响另一方，所有错误封装在 ToolResult 中。
 */
export async function executeScan(target: string): Promise<ScanOutcome> {
  const start = Date.now();
  const [semgrep, gitleaks] = await Promise.all([
    scanSemgrep(target),
    scanGitleaks(target),
  ]);
  return { semgrep, gitleaks, elapsedMs: Date.now() - start };
}
