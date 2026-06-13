#!/usr/bin/env node
/**
 * Luvv MCPServer — 入口路由器
 *
 * 用法：
 *   node dist/main.js           # 默认 stdio 模式
 *   node dist/main.js stdio     # 显式 stdio
 *
 * 未来可扩展：
 *   node dist/main.js sse       # Server-Sent Events
 *   node dist/main.js http      # Streamable HTTP
 */

import { logger } from "./lib/logger.js";

const transport = process.argv[2] || "stdio";

async function main(): Promise<void> {
  switch (transport) {
    case "stdio": {
      const { launchStdio } = await import("./transports/stdio.js");
      await launchStdio();
      break;
    }
    default:
      logger.error(`未知传输模式: ${transport}`);
      process.stderr.write(`用法: node dist/main.js [stdio]\n`);
      process.stderr.write(`可用模式: stdio\n`);
      process.exit(1);
  }
}

main().catch((err) => {
  logger.error("启动失败", {
    detail: err instanceof Error ? err.message : String(err),
  });
  process.exit(1);
});
