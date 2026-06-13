/**
 * 结构化日志模块 — 所有日志写入 stderr，确保 MCP 协议通道（stdout）不受污染。
 *
 * 输出格式为单行 JSON，便于日志聚合工具解析：
 * {"ts":"2026-06-13T...","level":"info","msg":"...","ctx":{}}
 */

type LogSeverity = "debug" | "info" | "warn" | "error";

const SEVERITY_RANK: Record<LogSeverity, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

/** 从 LOG_LEVEL 环境变量读取阈值，默认 "info" */
function threshold(): LogSeverity {
  const raw = (process.env.LOG_LEVEL ?? "info").toLowerCase();
  return raw in SEVERITY_RANK ? (raw as LogSeverity) : "info";
}

function emit(level: LogSeverity, message: string, context?: unknown): void {
  const current = threshold();
  if (SEVERITY_RANK[level] < SEVERITY_RANK[current]) return;

  const record = {
    ts: new Date().toISOString(),
    level,
    msg: message,
    ...(context !== undefined ? { ctx: context } : {}),
  };

  process.stderr.write(JSON.stringify(record) + "\n");
}

export const logger = {
  debug: (msg: string, ctx?: unknown) => emit("debug", msg, ctx),
  info: (msg: string, ctx?: unknown) => emit("info", msg, ctx),
  warn: (msg: string, ctx?: unknown) => emit("warn", msg, ctx),
  error: (msg: string, ctx?: unknown) => emit("error", msg, ctx),
};
