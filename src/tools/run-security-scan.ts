/**
 * run_security_scan 工具定义与处理器。
 *
 * 接收 target_path，内部编排 semgrep + gitleaks 并行扫描，
 * 返回结构化的安全审计报告。
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { executeScan } from "../lib/scanner.js";
import { verifyDirectory, isSensitivePath } from "../lib/executor.js";
import { logger } from "../lib/logger.js";

// ---------------------------------------------------------------------------
// 输入 Schema（Zod）
// ---------------------------------------------------------------------------

export const SecurityScanInput = z.object({
  target_path: z
    .string()
    .min(1, "target_path 不能为空")
    .describe("要扫描的目标目录的绝对路径，如 /home/user/project"),
});

export type SecurityScanArgs = z.infer<typeof SecurityScanInput>;

// ---------------------------------------------------------------------------
// 工具元数据
// ---------------------------------------------------------------------------

export const TOOL_NAME = "run_security_scan";

export const TOOL_CONFIG = {
  title: "安全审计扫描",
  description:
    "对目标目录执行安全扫描，内部自动并行调用 semgrep（SAST 静态分析）和 gitleaks（硬编码密钥检测），" +
    "返回合并的结构化 JSON 审计报告。若依赖工具未安装，报告中会附带各平台的安装指引。",
  inputSchema: SecurityScanInput,
  annotations: {
    readOnlyHint: true,       // 只读操作，不修改任何文件
    destructiveHint: false,   // 非破坏性
    idempotentHint: true,     // 对同一目录多次扫描结果一致（幂等）
    openWorldHint: false,     // 不依赖外部世界状态
  },
};

// ---------------------------------------------------------------------------
// 结果裁剪（缩减大型输出，保护敏感数据）
// ---------------------------------------------------------------------------

/** 对 semgrep 输出只保留摘要字段 */
function trimSemgrep(findings: unknown): unknown {
  const data = findings as Record<string, unknown> | null | undefined;
  if (!data || !Array.isArray(data.results)) return findings;
  return {
    ...data,
    results: (data.results as Array<Record<string, unknown>>).map((r) => ({
      check_id: r.check_id,
      path: r.path,
      start: r.start,
      end: r.end,
      extra: {
        severity: (r.extra as Record<string, unknown>)?.severity,
        message: (r.extra as Record<string, unknown>)?.message,
      },
    })),
  };
}

/** 对 gitleaks 输出做密钥掩码处理 */
function trimGitleaks(findings: unknown): unknown {
  if (!Array.isArray(findings)) return findings;
  return (findings as Array<Record<string, unknown>>).map((f) => ({
    RuleID: f.RuleID,
    Description: f.Description,
    File: f.File,
    StartLine: f.StartLine,
    Secret: f.Secret ? "***MASKED***" : undefined,
    Match: f.Match,
  }));
}

// ---------------------------------------------------------------------------
// 报告组装
// ---------------------------------------------------------------------------

interface AuditReport {
  target_path: string;
  resolved_path: string;
  scan_time: string;
  duration_ms: number;
  tools: {
    semgrep: Record<string, unknown>;
    gitleaks: Record<string, unknown>;
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

function buildReport(
  targetRaw: string,
  resolved: string,
  elapsed: number,
  semgrepResult: Record<string, unknown>,
  gitleaksResult: Record<string, unknown>,
): AuditReport {
  const semFindings = (semgrepResult.findings as { results?: unknown[] })?.results?.length ?? 0;
  const glFindings = Array.isArray(gitleaksResult.findings)
    ? (gitleaksResult.findings as unknown[]).length
    : 0;

  return {
    target_path: targetRaw,
    resolved_path: resolved,
    scan_time: new Date().toISOString(),
    duration_ms: elapsed,
    tools: {
      semgrep: semgrepResult,
      gitleaks: gitleaksResult,
    },
    summary: {
      total_findings: semFindings + glFindings,
      semgrep_findings: semFindings,
      gitleaks_findings: glFindings,
    },
    environment: {
      node_version: process.version,
      platform: process.platform,
      hostname: process.env.COMPUTERNAME || process.env.HOSTNAME || "unknown",
    },
  };
}

// ---------------------------------------------------------------------------
// 注册入口
// ---------------------------------------------------------------------------

/**
 * 向 McpServer 实例注册 run_security_scan 工具。
 * 采用 server.tool() 高层 API，与官方 server.registerTool() 等价但更简洁。
 */
export function registerRunSecurityScan(server: McpServer): void {
  server.registerTool(TOOL_NAME, TOOL_CONFIG, async (args): Promise<CallToolResult> => {
    const { target_path } = SecurityScanInput.parse(args);

    // --- 1. 敏感路径拦截 ---
    if (isSensitivePath(target_path)) {
      logger.warn(`拒绝敏感路径扫描请求: ${target_path}`);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              target_path,
              scan_time: new Date().toISOString(),
              error: "出于安全原因，拒绝扫描系统敏感目录",
              tools: { semgrep: { available: false }, gitleaks: { available: false } },
            }, null, 2),
          },
        ],
      };
    }

    // --- 2. 路径验证 ---
    const verified = await verifyDirectory(target_path);
    if (!verified.ok) {
      logger.warn(`路径验证失败: ${verified.reason}`);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              target_path,
              scan_time: new Date().toISOString(),
              error: verified.reason ?? "路径不可访问",
              tools: { semgrep: { available: false }, gitleaks: { available: false } },
            }, null, 2),
          },
        ],
      };
    }

    // --- 3. 执行扫描 ---
    logger.info(`开始安全扫描: ${verified.resolved}`);
    const { semgrep, gitleaks, elapsedMs } = await executeScan(verified.resolved);

    // --- 4. 裁剪输出（非原始模式） ---
    const wantRaw = process.env.INCLUDE_RAW_OUTPUT === "true";
    const semgrepOut: Record<string, unknown> = {
      available: semgrep.available,
      ...(semgrep.error ? { error: semgrep.error } : {}),
      ...(semgrep.installGuide ? { install_guide: semgrep.installGuide } : {}),
      findings: wantRaw ? semgrep.findings : trimSemgrep(semgrep.findings),
    };
    const gitleaksOut: Record<string, unknown> = {
      available: gitleaks.available,
      ...(gitleaks.error ? { error: gitleaks.error } : {}),
      ...(gitleaks.installGuide ? { install_guide: gitleaks.installGuide } : {}),
      findings: wantRaw ? gitleaks.findings : trimGitleaks(gitleaks.findings),
    };

    // --- 5. 组装报告 ---
    const report = buildReport(target_path, verified.resolved, elapsedMs, semgrepOut, gitleaksOut);

    logger.info(
      `扫描完成: ${report.summary.total_findings} 个发现, 耗时 ${elapsedMs}ms`,
    );

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(report, null, 2),
        },
      ],
    };
  });
}
