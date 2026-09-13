import { describe, it, expect, vi, beforeEach } from "vitest";

const mocks = {
  one: vi.fn(),
  run: vi.fn(),
  withTransaction: vi.fn(),
  snipeServicePrice: vi.fn(),
  createUserSnipeTarget: vi.fn(),
  freezeForSnipe: vi.fn(),
  cancelUserSnipeTarget: vi.fn(),
  SnipeTakenError: vi.fn(),
};

vi.mock("@/lib/db-query", () => ({
  one: (...a: unknown[]) => mocks.one(...a),
  run: (...a: unknown[]) => mocks.run(...a),
  withTransaction: (...a: unknown[]) => mocks.withTransaction(...a),
  isDbReady: () => Promise.resolve(true),
}));

vi.mock("next-auth/next", () => ({
  getServerSession: () => Promise.resolve({ user: { email: "buyer@test.dev" } }),
}));

vi.mock("@/pages/api/auth/[...nextauth]", () => ({
  authOptions: {},
}));

vi.mock("@/lib/server/snipe-pricing", () => ({
  snipeServicePrice: (...a: unknown[]) => mocks.snipeServicePrice(...a),
}));

vi.mock("@/lib/server/snipe-balance", () => {
  class MockSnipeTakenError extends Error {
    constructor(public domain: string) { super(`taken:${domain}`); }
  }
  return {
    createUserSnipeTarget: (...a: unknown[]) => mocks.createUserSnipeTarget(...a),
    freezeForSnipe: (...a: unknown[]) => mocks.freezeForSnipe(...a),
    cancelUserSnipeTarget: (...a: unknown[]) => mocks.cancelUserSnipeTarget(...a),
    SnipeTakenError: MockSnipeTakenError,
  };
});

vi.mock("@/lib/logger", () => ({
  createLogger: () => ({ error: () => {} }),
}));

import handler from "./[domain]";

const TARGET_ROW = {
  id: "t1", domain: "dropme.com", tld: "com", status: "armed",
  service_price_cents: 4000, frozen_cents: 4000, fail_reason: null,
  notes: null, drop_eta: "2026-10-01", hunt_start: null, hunt_end: null,
  registered_at: null, created_at: "2026-09-01T00:00:00Z",
  updated_at: "2026-09-01T00:00:00Z", has_sub: true, reminder_id: "r1",
};

function callHandler(method: string, query: Record<string, string> = {}, body?: unknown) {
  const req = { method, query, body } as any;
  const res: any = {
    status: (code: number) => ({
      json: (b: unknown) => {
        res.lastJson = { code, body: b };
        return res;
      },
    }),
    end: () => {
      res.lastJson = { code: 405 };
      return res;
    },
  };
  return handler(req, res).then(() => res.lastJson);
}

describe("api/user/snipe-targets/[domain]", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("GET", () => {
    it("returns full target + balance for an owned domain", async () => {
      mocks.one
        .mockResolvedValueOnce(TARGET_ROW)
        .mockResolvedValueOnce({ balance_cents: 9000 });
      const result = await callHandler("GET", { domain: "dropme.com" });

      const [sql] = (mocks.one as any).mock.calls[0];
      expect(sql).toContain("t.domain = $2 AND t.user_email = $1");

      expect(result.code).toBe(200);
      expect(result.body.target).toMatchObject({
        domain: "dropme.com",
        status: "armed",
        serviceCents: 4000,
        frozenCents: 4000,
        hasSubscription: true,
        linkedReminderId: "r1",
      });
      expect(result.body.balanceCents).toBe(9000);
    });

    it("returns 404 when the target is not owned by the caller", async () => {
      mocks.one.mockResolvedValueOnce(null);
      const result = await callHandler("GET", { domain: "other.com" });
      expect(result.code).toBe(404);
    });
  });

  describe("PATCH disable", () => {
    it("releases the hold and returns releasedCents", async () => {
      mocks.one.mockResolvedValueOnce(TARGET_ROW);
      mocks.withTransaction.mockImplementationOnce((cb: unknown) =>
        (cb as (tx: unknown) => Promise<number>)({}),
      );
      mocks.cancelUserSnipeTarget.mockResolvedValueOnce(4000);

      const result = await callHandler("PATCH", { domain: "dropme.com" }, { action: "disable" });
      expect(mocks.cancelUserSnipeTarget).toHaveBeenCalledWith(
        expect.anything(),
        { domain: "dropme.com", userEmail: "buyer@test.dev" },
      );
      expect(result.code).toBe(200);
      expect(result.body.snipe).toEqual({ status: "cancelled", releasedCents: 4000 });
    });

    it("404s a disable action on a non-owned domain", async () => {
      mocks.one.mockResolvedValueOnce(null);
      const result = await callHandler("PATCH", { domain: "other.com" }, { action: "disable" });
      expect(result.code).toBe(404);
    });
  });

  describe("PATCH enable", () => {
    it("creates + freezes and marks the target armed", async () => {
      mocks.one.mockResolvedValueOnce(TARGET_ROW);
      mocks.snipeServicePrice.mockResolvedValueOnce({
        domain: "dropme.com", serviceCents: 4000, cnyCost: null, fxRate: 8, markup: 4, isPremium: null,
      });
      mocks.createUserSnipeTarget.mockResolvedValueOnce("t_new");
      mocks.freezeForSnipe.mockResolvedValueOnce({
        ok: true, insufficient: false, frozenCents: 4000, balanceCents: 5000, holdKey: "hk",
      });
      mocks.withTransaction.mockImplementationOnce((cb: unknown) =>
        (cb as (tx: unknown) => Promise<unknown>)({}),
      );

      const result = await callHandler("PATCH", { domain: "dropme.com" }, { action: "enable" });
      expect(mocks.createUserSnipeTarget).toHaveBeenCalledWith(
        expect.anything(),
        expect.objectContaining({ domain: "dropme.com", serviceCents: 4000, userEmail: "buyer@test.dev" }),
      );
      expect(mocks.run).toHaveBeenCalledWith(
        expect.stringContaining("status = $2"),
        ["t_new", "armed"],
      );
      expect(result.code).toBe(200);
      expect(result.body.snipe).toEqual({ status: "armed", serviceCents: 4000 });
    });

    it("reports blocked_balance with shortfall when funds are insufficient", async () => {
      mocks.one.mockResolvedValueOnce(TARGET_ROW);
      mocks.snipeServicePrice.mockResolvedValueOnce({
        domain: "dropme.com", serviceCents: 4000, cnyCost: null, fxRate: 8, markup: 4, isPremium: null,
      });
      mocks.createUserSnipeTarget.mockResolvedValueOnce("t_new");
      mocks.freezeForSnipe.mockResolvedValueOnce({
        ok: false, insufficient: true, frozenCents: 0, balanceCents: 500, holdKey: null,
      });
      mocks.withTransaction.mockImplementationOnce((cb: unknown) =>
        (cb as (tx: unknown) => Promise<unknown>)({}),
      );

      const result = await callHandler("PATCH", { domain: "dropme.com" }, { action: "enable" });
      expect(mocks.run).toHaveBeenCalledWith(
        expect.stringContaining("status = $2"),
        ["t_new", "blocked_balance"],
      );
      expect(result.code).toBe(200);
      expect(result.body.snipe).toEqual({
        status: "blocked_balance",
        serviceCents: 4000,
        balanceCents: 500,
        neededCents: 3500,
      });
    });

    it("maps a taken domain to 409 SNIPE_TAKEN", async () => {
      mocks.one.mockResolvedValueOnce(TARGET_ROW);
      mocks.snipeServicePrice.mockResolvedValueOnce({
        domain: "dropme.com", serviceCents: 4000, cnyCost: null, fxRate: 8, markup: 4, isPremium: null,
      });
      mocks.withTransaction.mockImplementationOnce((cb: unknown) =>
        (cb as (tx: unknown) => Promise<unknown>)({}),
      );
      const { SnipeTakenError } = await import("@/lib/server/snipe-balance");
      mocks.createUserSnipeTarget.mockImplementationOnce(() => {
        throw new (SnipeTakenError as any)("dropme.com");
      });

      const result = await callHandler("PATCH", { domain: "dropme.com" }, { action: "enable" });
      expect(result.code).toBe(409);
      expect(result.body.code).toBe("SNIPE_TAKEN");
    });

    it("rejects a bad action", async () => {
      mocks.one.mockResolvedValueOnce(TARGET_ROW);
      const result = await callHandler("PATCH", { domain: "dropme.com" }, { action: "nuke" });
      expect(result.code).toBe(400);
    });

    it("returns 502 when the price quote is unavailable", async () => {
      mocks.one.mockResolvedValueOnce(TARGET_ROW);
      mocks.snipeServicePrice.mockResolvedValueOnce({
        domain: "dropme.com", serviceCents: null, cnyCost: null, fxRate: 8, markup: 4, isPremium: null, error: "no quote",
      });
      const result = await callHandler("PATCH", { domain: "dropme.com" }, { action: "enable" });
      expect(result.code).toBe(502);
    });
  });
});