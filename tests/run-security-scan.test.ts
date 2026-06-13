/**
 * run_security_scan 工具 — 单元测试
 *
 * 测试覆盖：
 * - Zod schema 校验（合法/非法输入）
 * - 敏感路径拦截逻辑
 * - 路径验证逻辑
 * - 报告结构完整性
 */

import { describe, it, expect } from "vitest";
import { SecurityScanInput } from "../src/tools/run-security-scan.js";
import { isSensitivePath } from "../src/lib/executor.js";

// ---------------------------------------------------------------------------
// Schema 校验测试
// ---------------------------------------------------------------------------

describe("SecurityScanInput Schema", () => {
  it("接受合法的绝对路径", () => {
    const result = SecurityScanInput.safeParse({
      target_path: "/home/user/project",
    });
    expect(result.success).toBe(true);
  });

  it("接受 Windows 风格绝对路径", () => {
    const result = SecurityScanInput.safeParse({
      target_path: "C:\\Users\\test\\project",
    });
    expect(result.success).toBe(true);
  });

  it("拒绝空字符串", () => {
    const result = SecurityScanInput.safeParse({ target_path: "" });
    expect(result.success).toBe(false);
  });

  it("拒绝缺少 target_path 的输入", () => {
    const result = SecurityScanInput.safeParse({});
    expect(result.success).toBe(false);
  });

  it("拒绝非字符串类型", () => {
    const result = SecurityScanInput.safeParse({ target_path: 12345 });
    expect(result.success).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 敏感路径拦截测试
// ---------------------------------------------------------------------------

describe("isSensitivePath", () => {
  it("拦截 /etc/passwd", () => {
    expect(isSensitivePath("/etc/passwd")).toBe(true);
  });

  it("拦截 /proc 路径", () => {
    expect(isSensitivePath("/proc/self/environ")).toBe(true);
  });

  it("拦截 Windows System32", () => {
    expect(isSensitivePath("C:\\Windows\\System32\\config")).toBe(true);
  });

  it("放行普通项目路径", () => {
    expect(isSensitivePath("/home/dev/my-app")).toBe(false);
  });

  it("放行 Windows 用户目录", () => {
    expect(isSensitivePath("C:\\Users\\dev\\code")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 报告结构测试（集成测试 — 需要真实扫描工具，此处仅做结构验证）
// ---------------------------------------------------------------------------

describe("报告输出结构（离线验证）", () => {
  it("工具名称常量正确", async () => {
    const { TOOL_NAME } = await import("../src/tools/run-security-scan.js");
    expect(TOOL_NAME).toBe("run_security_scan");
  });

  it("TOOL_CONFIG 包含必要字段", async () => {
    const { TOOL_CONFIG } = await import("../src/tools/run-security-scan.js");
    expect(TOOL_CONFIG.title).toBeTruthy();
    expect(TOOL_CONFIG.description).toBeTruthy();
    expect(TOOL_CONFIG.annotations.readOnlyHint).toBe(true);
    expect(TOOL_CONFIG.annotations.destructiveHint).toBe(false);
    expect(TOOL_CONFIG.annotations.idempotentHint).toBe(true);
    expect(TOOL_CONFIG.annotations.openWorldHint).toBe(false);
  });

  it("TOOL_CONFIG annotations 符合 MCP 安全审计工具语义", async () => {
    const { TOOL_CONFIG } = await import("../src/tools/run-security-scan.js");
    // 安全扫描必须是只读、非破坏性、幂等的
    expect(TOOL_CONFIG.annotations.readOnlyHint).toBe(true);
    expect(TOOL_CONFIG.annotations.destructiveHint).toBe(false);
    expect(TOOL_CONFIG.annotations.idempotentHint).toBe(true);
  });
});
