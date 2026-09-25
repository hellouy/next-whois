import { describe, it, expect, vi, beforeEach } from "vitest";

const mocks = vi.hoisted(() => ({
  requireAdmin: vi.fn(),
  many: vi.fn(),
  one: vi.fn(),
  run: vi.fn(),
  recordNotification: vi.fn(),
}));

vi.mock("@/lib/db-query", () => ({
  many: (...a: unknown[]) => mocks.many(...a),
  one: (...a: unknown[]) => mocks.one(...a),
  run: (...a: unknown[]) => mocks.run(...a),
}));

vi.mock("@/lib/admin", () => ({
  requireAdmin: (...a: unknown[]) => mocks.requireAdmin(...a),
}));

vi.mock("@/lib/notifications", () => ({
  recordNotification: (...a: unknown[]) => mocks.recordNotification(...a),
}));

import handler from "./feedback";

function callHandler(method: string, query: Record<string, unknown> = {}, body: Record<string, unknown> = {}) {
  const req = { method, query, body } as any;
  const res: any = {
    setHeader: () => res,
    status: (code: number) => ({
      json: (b: unknown) => { res.lastJson = { code, body: b }; return res; },
    }),
    json: (b: unknown) => { res.lastJson = { code: 200, body: b }; return res; },
  };
  return handler(req, res).then(() => res.lastJson);
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.requireAdmin.mockResolvedValue({ user: { isAdmin: true } });
});

describe("/api/admin/feedback POST reply", () => {
  it("rejects an empty reply", async () => {
    const r = await callHandler("POST", { id: "f1" }, { reply: "   " });
    expect(r.code).toBe(400);
    expect(mocks.run).not.toHaveBeenCalled();
  });

  it("rejects a reply longer than 2000 characters", async () => {
    const r = await callHandler("POST", { id: "f1" }, { reply: "x".repeat(2001) });
    expect(r.code).toBe(400);
  });

  it("returns 404 when the feedback does not exist", async () => {
    mocks.one.mockResolvedValueOnce(null);
    const r = await callHandler("POST", { id: "ghost" }, { reply: "hello" });
    expect(r.code).toBe(404);
  });

  it("persists the reply, marks handled, and notifies when the submitter holds an account", async () => {
    mocks.one
      .mockResolvedValueOnce({ email: "sub@example.com", query: "example.com" }) // feedback lookup
      .mockResolvedValueOnce({ id: "u1" });                                       // user lookup
    const r = await callHandler("POST", { id: "f1" }, { reply: "已修复，感谢反馈" });

    expect(r).toEqual({ code: 200, body: { ok: true } });
    // single UPDATE for reply/handled
    expect(mocks.run).toHaveBeenCalledTimes(1);
    const sql = mocks.run.mock.calls[0][0] as string;
    expect(sql).toContain("reply = $1");
    expect(sql).toContain("handled = true");
    // notification recorded for the matched user
    expect(mocks.recordNotification).toHaveBeenCalledTimes(1);
    const notif = mocks.recordNotification.mock.calls[0][0];
    expect(notif.email).toBe("sub@example.com");
    expect(notif.type).toBe("feedback_reply");
    expect(notif.body).toBe("已修复，感谢反馈");
  });

  it("stores the reply but skips notification when the submitter has no account", async () => {
    mocks.one
      .mockResolvedValueOnce({ email: "anon@example.com", query: "example.com" })
      .mockResolvedValueOnce(null); // no matching user
    const r = await callHandler("POST", { id: "f1" }, { reply: "thanks" });
    expect(r.code).toBe(200);
    expect(mocks.run).toHaveBeenCalledTimes(1);
    expect(mocks.recordNotification).not.toHaveBeenCalled();
  });

  it("stores the reply and skips notification when feedback has no email", async () => {
    mocks.one.mockResolvedValueOnce({ email: null, query: "example.com" });
    const r = await callHandler("POST", { id: "f1" }, { reply: "thanks" });
    expect(r.code).toBe(200);
    expect(mocks.run).toHaveBeenCalledTimes(1);
    expect(mocks.recordNotification).not.toHaveBeenCalled();
  });
});
