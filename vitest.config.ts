import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // 测试文件位于 tests/ 目录
    include: ["tests/**/*.test.ts"],
    // 使用 Node.js 环境（无需 jsdom）
    environment: "node",
    // 单次运行超时 30 秒
    testTimeout: 30000,
    // 覆盖率配置
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/main.ts"],
      reporter: ["text", "lcov"],
    },
  },
});
