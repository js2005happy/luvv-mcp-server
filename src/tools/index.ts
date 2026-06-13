/**
 * 工具注册汇总 — 所有 MCP 工具的集中注册入口。
 *
 * 新增工具时：
 * 1. 在 tools/ 下创建独立文件
 * 2. 导出 registerXxx(server) 函数
 * 3. 在此文件中导入并调用
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerRunSecurityScan } from "./run-security-scan.js";

/**
 * 向 McpServer 实例注册所有工具。
 * 被 server.ts 的 createServer() 工厂调用。
 */
export function registerAllTools(server: McpServer): void {
  registerRunSecurityScan(server);
}
