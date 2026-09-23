import { describe, it, expect, vi, beforeEach } from "vitest";

const mocks = vi.hoisted(() => ({
  many: vi.fn(),
  session: null as any,
  setting: "1",
}));

vi.mock("@/lib/db-query", () => ({
  many: (...a: unknown[]) => mocks.many(...a),
  one: () => null,
  run: () => 0,
  isDbReady: () => Promise.resolve(true),
}));

vi.mock("next-auth/next", () => ({
  getServerSession: () => Promise.resolve(mocks.session),
}));

vi.mock("@/pages/api/auth/[...nextauth]", () => ({ authOptions: {} }));

vi.mock("@/lib/server/site-settings-server", () => ({
  getSetting: () => Promise.resolve(mocks.setting),
  getSettings: () => Promise.resolve({}),
}));

vi.mock("@/lib/server/lifecycle-overrides", () => ({
  loadLifecycleOverrides: () => Promise.resolve({}),
}));

import handler from "./drops";

const row = {
  domain: "car.com", tld: "com", drop_date: "2026-10-01", date_type: "source",
  source: "expireddomains.net", stage: "pending_delete",
  value_score: 82, value_tier: "top", value_reasons: ["三字符·优质短域"], bl: 100, dp: 5,
};

function callHandler(query: Record<string, string | undefined> = {}) {
  const req = { method: "GET", query } as any;
  const headers: Record<string, string> = {};
  const res: any = {
    _headers: headers,
    setHeader: (k: string, v: string) => { headers[k] = v; },
    status: (code: number) => ({
      json: (body: unknown) => { res.lastJson = { code, body }; return res; },
    }),
    json: (body: unknown) => { res.lastJson = { code: 200, body }; return res; },
    end: () => { res.lastJson = { code: 405 }; return res; },
  };
  return handler(req, res).then(() => ({ ...res.lastJson, headers }));
}

function primePublicQueries() {
  mocks.many
    .mockResolvedValueOnce([row])                                       // main rows
    .mockResolvedValueOnce([{ total: 1, today: 1 }])                    // aggregate
    .mockResolvedValueOnce([{ tld: "com", count: 1 }])                  // tld distribution
    .mockResolvedValueOnce([row])                                       // top value
    .mockResolvedValueOnce([{ source: "expireddomains.net", last_success_at: null, last_error: null }]); // status
}

describe("api/drops GET", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.session = null;
    mocks.setting = "1";
  });

  it("applies the window and filters, then groups and aggregates", async () => {
    primePublicQueries();
    const result = await callHandler({ days: "10", tld: "com,ai", minScore: "50" });

    const [sql, params] = (mocks.many as any).mock.calls[0];
    expect(sql).toContain("drop_date >= $1");
    expect(sql).toContain("drop_date <= $2");
    expect(sql).toContain("tld = ANY($3)");
    expect(sql).toContain("value_score >= $4");
    expect(params[0]).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(params[2]).toEqual(["com", "ai"]);

    expect(result.code).toBe(200);
    expect(result.body.days).toBe(10);
    expect(result.body.drops[0]).toMatchObject({ date: "2026-10-01", total: 1, topTier: "top" });
    expect(result.body.drops[0].domains[0]).toMatchObject({ domain: "car.com", valueScore: 82, dateType: "source" });
    expect(result.body.stats).toMatchObject({ total: 1, today: 1 });
    expect(result.body.sources[0]).toMatchObject({ source: "expireddomains.net", stale: true });
  });

  it("falls back to the default sort for unknown values", async () => {
    primePublicQueries();
    await callHandler({ sort: "bogus" });
    const [sql] = (mocks.many as any).mock.calls[0];
    expect(sql).toContain("value_score DESC NULLS LAST, drop_date ASC");
  });

  it("caches anonymous responses publicly", async () => {
    primePublicQueries();
    const result = await callHandler({});
    expect(result.headers["Cache-Control"]).toContain("public, max-age=300");
  });

  it("marks signed-in responses private and includes user drops", async () => {
    mocks.session = { user: { email: "u@test.dev" } };
    mocks.many
      .mockResolvedValueOnce([row])
      .mockResolvedValueOnce([{ total: 1, today: 1 }])
      .mockResolvedValueOnce([{ tld: "com", count: 1 }])
      .mockResolvedValueOnce([row])
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([]); // reminders

    const result = await callHandler({});
    expect(result.headers["Cache-Control"]).toBe("private, no-store");
    expect(result.body.user_drops).toEqual([]);
  });

  it("exposes the registration status only for restricted leads", async () => {
    const reserved = { ...row, domain: "keep.com", status: "reserved" };
    const prohibited = { ...row, domain: "banned.com", status: "PROHIBITED" };
    const normal = { ...row, status: "available" };
    const legacy = { ...row, domain: "old.com" }; // no status column value at all
    mocks.many
      .mockResolvedValueOnce([reserved, prohibited, normal, legacy])
      .mockResolvedValueOnce([{ total: 4, today: 0 }])
      .mockResolvedValueOnce([{ tld: "com", count: 4 }])
      .mockResolvedValueOnce([reserved])
      .mockResolvedValueOnce([]);

    const result = await callHandler({});
    const leads = result.body.drops[0].domains;
    expect(leads.find((d: any) => d.domain === "keep.com").regStatus).toBe("reserved");
    expect(leads.find((d: any) => d.domain === "banned.com").regStatus).toBe("prohibited");
    expect(leads.find((d: any) => d.domain === "car.com").regStatus).toBeUndefined();
    expect(leads.find((d: any) => d.domain === "old.com").regStatus).toBeUndefined();
  });

  it("locks the calendar when public access is disabled", async () => {
    mocks.setting = "0";
    const result = await callHandler({});
    expect(result.body.public_locked).toBe(true);
    expect(result.body.drops).toEqual([]);
  });
});
