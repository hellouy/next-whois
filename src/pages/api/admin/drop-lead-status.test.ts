import { describe, it, expect, vi, beforeEach } from "vitest";

const mocks = vi.hoisted(() => ({
  run: vi.fn(),
  requireAdmin: vi.fn(),
  invalidate: vi.fn(),
}));

vi.mock("@/lib/db-query", () => ({
  run: (...a: unknown[]) => mocks.run(...a),
  isDbReady: () => Promise.resolve(true),
}));

vi.mock("@/lib/admin", () => ({
  requireAdmin: (...a: unknown[]) => mocks.requireAdmin(...a),
}));

vi.mock("@/lib/server/drop-cache", () => ({
  invalidateDropCache: (...a: unknown[]) => mocks.invalidate(...a),
}));

import handler from "./drop-lead-status";

function callHandler(method: string, body: Record<string, unknown> = {}) {
  const req = { method, body } as any;
  const res: any = {
    status: (code: number) => ({
      json: (b: unknown) => { res.lastJson = { code, body: b }; return res; },
    }),
    json: (b: unknown) => { res.lastJson = { code: 200, body: b }; return res; },
  };
  return handler(req, res).then(() => res.lastJson);
}

beforeEach(() => {
  mocks.run.mockReset();
  mocks.requireAdmin.mockReset();
  mocks.invalidate.mockReset();
  mocks.requireAdmin.mockResolvedValue({ user: { isAdmin: true } });
});

describe("/api/admin/drop-lead-status", () => {
  it("rejects non-admin without touching the database", async () => {
    mocks.requireAdmin.mockResolvedValue(null);
    await callHandler("POST", { domain: "a.com", status: "reserved" });
    expect(mocks.run).not.toHaveBeenCalled();
  });

  it("rejects non-POST methods", async () => {
    const res = await callHandler("GET");
    expect(res.code).toBe(405);
    expect(mocks.run).not.toHaveBeenCalled();
  });

  it("rejects an invalid domain", async () => {
    const res = await callHandler("POST", { domain: "not a domain", status: "reserved" });
    expect(res.code).toBe(400);
    expect(mocks.run).not.toHaveBeenCalled();
  });

  it("rejects an invalid status", async () => {
    const res = await callHandler("POST", { domain: "a.com", status: "bogus" });
    expect(res.code).toBe(400);
    expect(mocks.run).not.toHaveBeenCalled();
  });

  it("returns 404 when the lead does not exist", async () => {
    mocks.run.mockResolvedValue(0);
    const res = await callHandler("POST", { domain: "missing.com", status: "reserved" });
    expect(res.code).toBe(404);
    expect(mocks.invalidate).not.toHaveBeenCalled();
  });

  it("updates the lead and invalidates the cache", async () => {
    mocks.run.mockResolvedValue(1);
    const res = await callHandler("POST", { domain: "Example.com", status: "PROHIBITED" });
    expect(res.code).toBe(200);
    expect(res.body).toMatchObject({ ok: true, domain: "example.com", status: "prohibited" });
    expect(mocks.run).toHaveBeenCalledWith(expect.stringContaining("UPDATE expired_domain_leads"), [
      "prohibited",
      "example.com",
    ]);
    expect(mocks.invalidate).toHaveBeenCalledTimes(1);
  });
});
