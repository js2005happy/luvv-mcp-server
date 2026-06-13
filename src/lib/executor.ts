/**
 * 外部命令执行工具 — 提供子进程 spawn、二进制检测、超时控制等基础能力。
 */

import { spawn, type ChildProcess } from "node:child_process";
import { stat } from "node:fs/promises";
import { resolve } from "node:path";
import { logger } from "./logger.js";

// ---------------------------------------------------------------------------
// 类型
// ---------------------------------------------------------------------------

export interface ExecResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  killed: boolean;
}

export interface BinaryInfo {
  found: boolean;
  version: string;
}

// ---------------------------------------------------------------------------
// 二进制可用性检测
// ---------------------------------------------------------------------------

/**
 * 检查可执行文件是否在 PATH 中，并捕获其 --version 输出的首行。
 * semgrep 和部分工具有时将版本信息写入 stderr，因此合并两者。
 */
export function detectBinary(name: string, timeoutMs = 10_000): Promise<BinaryInfo> {
  return new Promise((resolve) => {
    const child: ChildProcess = spawn(name, ["--version"], {
      stdio: ["ignore", "pipe", "pipe"],
      timeout: timeoutMs,
    });

    let merged = "";

    child.stdout?.on("data", (chunk: Buffer) => {
      merged += chunk.toString();
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      merged += chunk.toString();
    });

    child.on("close", (code) => {
      resolve({
        found: code === 0,
        version: merged.trim().split("\n")[0] ?? "",
      });
    });

    child.on("error", () => {
      resolve({ found: false, version: "" });
    });
  });
}

// ---------------------------------------------------------------------------
// 带超时的命令执行
// ---------------------------------------------------------------------------

/**
 * 执行命令，超时后发送 SIGKILL 强制终止。
 * 返回 stdout、stderr、退出码以及是否因超时而被 kill。
 */
export function runCommand(
  command: string,
  args: string[],
  timeoutMs: number,
): Promise<ExecResult> {
  return new Promise((resolve) => {
    const child: ChildProcess = spawn(command, args, {
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let killed = false;

    const timer = setTimeout(() => {
      killed = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, exitCode: code, killed });
    });

    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({
        stdout: "",
        stderr: `spawn(${command}) 失败: ${err.message}`,
        exitCode: null,
        killed: false,
      });
    });
  });
}

// ---------------------------------------------------------------------------
// 路径验证
// ---------------------------------------------------------------------------

export interface PathCheck {
  ok: boolean;
  resolved: string;
  reason?: string;
}

/**
 * 验证路径存在、为目录、且可读。
 */
export async function verifyDirectory(raw: string): Promise<PathCheck> {
  const resolvedPath = resolve(raw);
  try {
    const info = await stat(resolvedPath);
    if (!info.isDirectory()) {
      return { ok: false, resolved: resolvedPath, reason: "路径不是目录" };
    }
    return { ok: true, resolved: resolvedPath };
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return { ok: false, resolved: resolvedPath, reason: `无法访问: ${detail}` };
  }
}

/**
 * 拒绝扫描系统敏感路径，避免误操作。
 */
export function isSensitivePath(target: string): boolean {
  const denyList = [
    "/etc/passwd",
    "/etc/shadow",
    "/proc",
    "/sys",
    "/root",
    "C:\\Windows\\System32",
    "~/.ssh",
  ];
  const lower = target.toLowerCase();
  return denyList.some((entry) => lower.includes(entry.toLowerCase()));
}

// ---------------------------------------------------------------------------
// 预热检测（启动时调用）
// ---------------------------------------------------------------------------

export interface DependencyStatus {
  semgrep: { installed: boolean; version: string };
  gitleaks: { installed: boolean; version: string };
}

export async function checkDependencies(): Promise<DependencyStatus> {
  const [semgrep, gitleaks] = await Promise.all([
    detectBinary("semgrep"),
    detectBinary("gitleaks"),
  ]);

  logger.info(
    `依赖检测: semgrep=${semgrep.found ? semgrep.version || "✓" : "✗"}, gitleaks=${gitleaks.found ? gitleaks.version || "✓" : "✗"}`,
  );

  return {
    semgrep: { installed: semgrep.found, version: semgrep.version },
    gitleaks: { installed: gitleaks.found, version: gitleaks.version },
  };
}
