import { describe, it, expect } from "vitest";
import { snipeStatusLabel, snipeFailReasonLabel } from "./snipe-status";

describe("snipeStatusLabel", () => {
  it("maps every lifecycle status to its Chinese label", () => {
    expect(snipeStatusLabel("watching")).toBe("观察中");
    expect(snipeStatusLabel("armed")).toBe("已就绪");
    expect(snipeStatusLabel("blocked_balance")).toBe("余额不足");
    expect(snipeStatusLabel("sniping")).toBe("抢注中");
    expect(snipeStatusLabel("succeeded")).toBe("已注册");
    expect(snipeStatusLabel("failed")).toBe("失败");
    expect(snipeStatusLabel("cancelled")).toBe("已取消");
    expect(snipeStatusLabel("paused")).toBe("已暂停");
  });

  it("falls back to the raw value for unknown statuses", () => {
    expect(snipeStatusLabel("mystery")).toBe("mystery");
  });
});

describe("snipeFailReasonLabel", () => {
  it("translates raw engine failure markers", () => {
    expect(snipeFailReasonLabel("create returned no ope id")).toBe("注册接口未返回受理编号，抢注未成功");
    expect(snipeFailReasonLabel("netim operation failed")).toBe("注册商受理失败，抢注未成功");
    expect(snipeFailReasonLabel("ope_unknown")).toBe("注册结果未知，请留意后续通知");
    expect(snipeFailReasonLabel("hold_short")).toBe("余额不足，冻结失败");
  });

  it("maps transient and refusal reasons without leaking raw text", () => {
    expect(snipeFailReasonLabel("transient: timeout after 30s")).toBe("网络波动导致抢注中断，系统将自动重试");
    expect(snipeFailReasonLabel("refused")).toBe("注册商拒绝了本次注册");
    expect(snipeFailReasonLabel("domain is already registered")).toBe("域名已被他人注册");
  });

  it("passes through human-readable messages untouched", () => {
    expect(snipeFailReasonLabel("该域名已被他人抢注成功")).toBe("该域名已被他人抢注成功");
  });

  it("returns a generic friendly message for unknown technical markers", () => {
    expect(snipeFailReasonLabel("ERR_42_UNEXPECTED")).toBe("抢注未成功，如已扣费将自动解冻");
    expect(snipeFailReasonLabel(null)).toBeNull();
    expect(snipeFailReasonLabel(undefined)).toBeNull();
  });
});
