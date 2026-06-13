/**
 * stdio 传输启动器 — 通过标准输入/输出运行 MCP 服务器。
 *
 * 这是默认的传输模式，适用于 Claude Desktop 本地集成。
 * 进程 stdout 承载 MCP 协议 JSON-RPC 消息，stderr 承载日志。
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "../server.js";
import { checkDependencies } from "../lib/executor.js";
import { logger } from "../lib/logger.js";

/**
 * 启动 stdio 模式服务器。
 *
 * 流程：
 * 1. 预热检测 semgrep / gitleaks 可用性（仅日志，不阻塞）
 * 2. 创建 McpServer 实例并注册工具
 * 3. 连接到 StdioServerTransport
 * 4. 注册 SIGINT / SIGTERM 优雅退出
 */
export async function launchStdio(): Promise<void> {
  logger.info("启动 stdio 传输模式...");

  // --- 1. 预热检测 ---
  const deps = await checkDependencies();
  if (!deps.semgrep.installed || !deps.gitleaks.installed) {
    logger.warn("部分依赖工具未安装，扫描时将在报告中附带安装指引", {
      semgrep: deps.semgrep.installed,
      gitleaks: deps.gitleaks.installed,
    });
  }

  // --- 2. 创建服务器 ---
  const { server, shutdown } = createServer();

  // --- 3. 连接传输 ---
  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.info("服务器已就绪，等待客户端请求...");

  // --- 4. 信号处理 ---
  const handleSignal = async (signal: string) => {
    logger.info(`收到 ${signal} 信号，准备退出`);
    await shutdown();
    process.exit(0);
  };

  // 阻止重复注册（防止多次信号触发重复清理）
  process.once("SIGINT", () => handleSignal("SIGINT"));
  process.once("SIGTERM", () => handleSignal("SIGTERM"));

  // 未捕获异常兜底
  process.on("unhandledRejection", (reason) => {
    logger.error("未处理的 Promise 拒绝", { detail: String(reason) });
  });
  process.on("uncaughtException", (err) => {
    logger.error("未捕获的异常", { detail: err.message });
    shutdown().finally(() => process.exit(1));
  });
}
