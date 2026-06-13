/**
 * MCP Server 工厂 — 负责创建和配置 McpServer 实例。
 *
 * 此模块不关心传输层协议（stdio/SSE/HTTP），只负责：
 * 1. 创建服务器实例（name + version）
 * 2. 注册所有工具 / 资源 / 提示
 * 3. 返回 server 实例及清理函数
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerAllTools } from "./tools/index.js";
import { logger } from "./lib/logger.js";

// ---------------------------------------------------------------------------
// 类型
// ---------------------------------------------------------------------------

export interface ServerContext {
  server: McpServer;
  /** 优雅关闭：依次关闭 server 并执行清理回调 */
  shutdown: () => Promise<void>;
}

// ---------------------------------------------------------------------------
// 工厂函数
// ---------------------------------------------------------------------------

/**
 * 创建并配置一个完整的 MCP Server。
 *
 * 调用方负责将 server 连接到具体传输层（如 StdioServerTransport）。
 */
export function createServer(): ServerContext {
  logger.info("正在初始化 Luvv MCPServer...");

  const server = new McpServer({
    name: "luvv-security-scanner",
    version: "1.1.0",
  });

  // --- 注册能力 ---
  registerAllTools(server);

  // --- 构造清理函数 ---
  const cleanupTasks: Array<() => Promise<void>> = [];

  const shutdown = async (): Promise<void> => {
    logger.info("正在关闭服务器...");
    for (const task of cleanupTasks) {
      try {
        await task();
      } catch (err) {
        logger.error("清理任务失败", { detail: String(err) });
      }
    }
    await server.close();
    logger.info("服务器已关闭");
  };

  logger.info("MCP Server 实例创建完成");

  return { server, shutdown };
}
