import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Module mocks (before importing the handler) ──────────────────────────────
const mocks = {
  many: vi.fn(),
};

vi.mock("@/lib/db-query", () => ({
  many: (...a: unknown[]) => mocks.many(...a),
  one: () => null,
  run: () => 0,
  withTransaction: (cb: unknown) => (cb as () => Promise<unknown>)(),
  isDbReady: () => Promise.resolve(true),
}));

vi.mock("next-auth/next", () => ({
  getServerSession: () => Promise.resolve({ user: { email: "buyer@test.dev" } }),
}));

vi.mock("@/pages/api/auth/[...nextauth]", () => ({
  authOptions: {},
}));

import handler, { normalizeSnipeFilter } from "./snipe-targets";

function callHandler(query: Record<string, string | undefined> = {}) {
  const req = { method: "GET", query } as any;
  const res: any = {
    status: (code: number) => {
      res.statusCalled = code;
      return {
        json: (body: unknown) => {
          res.lastJson = { code, body };
          return res;
        },
      };
    },
    end: () => {
      res.lastJson = { code: 405 };
      return res;
    },
  };
  return handler(req, res).then(() => res.lastJson);
}

describe("normalizeSnipeFilter", () => {
  it("maps status values to a storage-safe filter", () => {
    expect(normalizeSnipeFilter(undefined)).toBeNull();
    expect(normalizeSnipeFilter("all")).toBeNull();
    expect(normalizeSnipeFilter("armed")).toBe("armed");
    expect(normalizeSnipeFilter("blocked_balance")).toBe("blocked_balance");
    expect(normalizeSnipeFilter("sniping")).toBe("sniping");
    expect(normalizeSnipeFilter("ended")).toBe("ended");
    expect(normalizeSnipeFilter("bogus")).toBeNull();
  });
});

describe("api/user/snipe-targets GET", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  const row = {
    id: "t1", domain: "dropme.com", tld: "com", status: "armed",
    service_price_cents: 4000, frozen_cents: 4000, fail_reason: null,
    drop_eta: "2026-10-01", hunt_start: null, hunt_end: null,
    registered_at: null, created_at: "2026-09-01T00:00:00Z", has_sub: true,
  };

  it("returns the user's targets scoped to their email", async () => {
    mocks.many.mockResolvedValueOnce([row]);
    const result = await callHandler({});
    const [sql, props] = (mocks.many as any).mock.calls[0];
    expect(sql).toContain("st.user_email = $1");
    expect(props[0]).toBe("buyer@test.dev");
    expect(result.code).toBe(200);
    expect(result.body.targets[0]).toMatchObject({
      domain: "dropme.com",
      status: "armed",
      serviceCents: 4000,
      frozenCents: 4000,
      hasSubscription: true,
    });
  });

  it("narrows by ended status (succeeded/failed/cancelled)", async () => {
    mocks.many.mockResolvedValueOnce([{ ...row, status: "failed", has_sub: false }]);
    await callHandler({ status: "ended" });
    const [sql, props] = (mocks.many as any).mock.calls[0];
    expect(sql).toContain("status = ANY($2::varchar[])");
    expect(props[1]).toEqual(["succeeded", "failed", "cancelled"]);
  });

  it("narrows by concrete status", async () => {
    mocks.many.mockResolvedValueOnce([]);
    await callHandler({ status: "blocked_balance" });
    const [sql, props] = (mocks.many as any).mock.calls[0];
    expect(sql).toContain("st.status = $2");
    expect(props[1]).toBe("blocked_balance");
  });

  it("searches the domain case-insensitively", async () => {
    mocks.many.mockResolvedValueOnce([{ ...row, domain: "DropMe.COM" }]);
    await callHandler({ q: "drop" });
    const [sql, props] = (mocks.many as any).mock.calls[0];
    expect(sql).toContain("ILIKE $2");
    expect(props[1]).toBe("%drop%");
  });

  it("orders active targets before ended ones", async () => {
    mocks.many.mockResolvedValueOnce([row]);
    await callHandler({});
    const sql = (mocks.many as any).mock.calls[0][0];
    expect(sql).toContain("CASE WHEN st.status IN ('armed','blocked_balance','sniping')");
  });

  it("is decoupled from reminders (has_sub is informational only)", async () => {
    mocks.many.mockResolvedValueOnce([{ ...row, has_sub: false }]);
    const result = await callHandler({});
    expect(result.body.targets[0].hasSubscription).toBe(false);
  });
});