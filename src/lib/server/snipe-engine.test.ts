import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Network / infra mocks (before importing the engine) ─────────────────────
const mocks = {
  one: vi.fn(),
  many: vi.fn(),
  run: vi.fn(),
  lookupWhoisWithCache: vi.fn(),
  netimDomainCheck: vi.fn(),
  netimDomainCreate: vi.fn(),
  netimQueryDomainPrice: vi.fn(),
  netimQueryOpe: vi.fn(),
  netimQueryResellerAccount: vi.fn(),
  sendEmail: vi.fn(),
};

vi.mock("@/lib/db-query", () => ({
  one: (...a: unknown[]) => mocks.one(...a),
  many: (...a: unknown[]) => mocks.many(...a),
  run: (...a: unknown[]) => mocks.run(...a),
}));

vi.mock("@/lib/whois/lookup", () => ({
  lookupWhoisWithCache: (...a: unknown[]) => mocks.lookupWhoisWithCache(...a),
}));

vi.mock("@/lib/server/netim-client", () => ({
  netimDomainCheck: (...a: unknown[]) => mocks.netimDomainCheck(...a),
  netimDomainCreate: (...a: unknown[]) => mocks.netimDomainCreate(...a),
  netimQueryDomainPrice: (...a: unknown[]) => mocks.netimQueryDomainPrice(...a),
  netimQueryOpe: (...a: unknown[]) => mocks.netimQueryOpe(...a),
  netimQueryResellerAccount: (...a: unknown[]) => mocks.netimQueryResellerAccount(...a),
}));

vi.mock("@/lib/server/lifecycle-overrides", () => ({
  loadLifecycleOverrides: vi.fn().mockResolvedValue({}),
}));

vi.mock("@/lib/email", () => ({
  sendEmail: (...a: unknown[]) => mocks.sendEmail(...a),
  snipeNotifyHtml: () => "<html></html>",
}));

vi.mock("@/lib/admin-shared", () => ({
  ADMIN_EMAIL: "admin@test.local",
}));

import { runDailyProbe, runHuntProbe, isSuspectRelease, isDryRun, CREATE_RETRY_BACKOFFS_MS } from "../server/snipe-engine";

// ── In-memory fake DB ────────────────────────────────────────────────────────
interface Target {
  id: string;
  domain: string;
  status: string;
  max_price: number | null;
  est_price: number | null;
  is_premium: boolean | null;
  expiration_date: string | null;
  drop_eta: string | null;
  hunt_start: string | null;
  hunt_end: string | null;
  whois_fails: number;
  probe_lock_at: string | null;
  fail_reason: string | null;
  notes: string | null;
  recharge_alerted_at: string | null;
}

const nowIso = () => new Date().toISOString();

function makeTarget(over: Partial<Target> = {}): Target {
  return {
    id: "11111111-2222-3333-4444-555555555555",
    domain: "example.sb",
    status: "watching",
    max_price: null,
    est_price: null,
    is_premium: null,
    expiration_date: "2026-10-01",
    drop_eta: "2026-11-01",
    hunt_start: "2026-10-31",
    hunt_end: "2026-11-03",
    whois_fails: 0,
    probe_lock_at: null,
    fail_reason: null,
    notes: null,
    recharge_alerted_at: null,
    ...over,
  };
}

/** Wire the db mocks to an in-memory target store. */
function wireDb(targets: Target[]) {
  const store = new Map(targets.map((t) => [t.id, { ...t }]));

  mocks.many.mockImplementation((sql: string, params?: unknown[]) => {
    if (sql.includes("hunt_start IS NOT NULL")) {
      const now = (params?.[0] as string) ?? nowIso();
      return [...store.values()].filter((t) =>
        ["armed", "blocked_balance"].includes(t.status) &&
        t.hunt_start != null && t.hunt_start <= now &&
        t.hunt_end != null && t.hunt_end >= now,
      );
    }
    if (sql.includes("status = ANY")) {
      const statuses = (params?.[0] as string[]) ?? [];
      return [...store.values()].filter((t) => statuses.includes(t.status));
    }
    return [];
  });

  mocks.one.mockImplementation((sql: string, params?: unknown[]) => {
    const id = params?.[0] as string;
    const t = store.get(id);
    if (!t) return null;

    if (sql.includes("probe_lock_at = NOW()") && sql.includes("RETURNING *")) {
      // claim: lock must be free or stale (>120s)
      if (t.probe_lock_at != null) return null;
      t.probe_lock_at = nowIso();
      return { ...t };
    }
    if (sql.includes("status = 'sniping'") && sql.includes("RETURNING *")) {
      if (t.status !== "armed") return null;
      t.status = "sniping";
      return { ...t };
    }
    return { ...t };
  });

  mocks.run.mockImplementation(async (sql: string, params?: unknown[]) => {
    const id = params?.[0] as string;
    const t = store.get(id);
    if (!t) return 0;

    if (sql.includes("probe_lock_at = NULL")) { t.probe_lock_at = null; }
    if (sql.includes("SET status = 'armed'")) { t.status = "armed"; }
    if (sql.includes("status = 'blocked_balance'")) { t.status = "blocked_balance"; }
    if (sql.includes("status = 'sniping'")) { t.status = "sniping"; }
    if (sql.includes("status = 'succeeded'")) { t.status = "succeeded"; t.fail_reason = null; }
    if (sql.includes("status = 'failed'")) { t.status = "failed"; t.fail_reason = String(params?.[1] ?? "failed"); }
    if (sql.includes("whois_fails = $2")) { t.whois_fails = Number(params?.[1]); }
    if (sql.includes("SET drop_eta")) { t.drop_eta = params?.[1] as string | null; }
    if (sql.includes("est_price = $2") && params?.[1] != null) { t.est_price = Number(params?.[1]); }
    if (sql.includes("is_premium = $3")) { t.is_premium = Boolean(params?.[2]); }
    if (sql.includes("recharge_alerted_at = NOW()")) { t.recharge_alerted_at = nowIso(); }
    return 1;
  });

  return { store };
}

function resetAll() {
  for (const m of Object.values(mocks)) m.mockReset();
  mocks.sendEmail.mockResolvedValue(undefined);
  mocks.netimQueryDomainPrice.mockResolvedValue({ isPremium: false, price: 10, renewalPrice: 10, currency: "EUR" });
  mocks.netimQueryResellerAccount.mockResolvedValue({
    balance: 500, defaultOwner: "LJ5552", defaultAdmin: "LJ5551",
    defaultTech: "LJ5551", defaultBilling: "LJ5551", defaultDns1: "ns1.nic.bn", defaultDns2: "ns2.nic.bn",
  });
  mocks.netimDomainCheck.mockResolvedValue({ available: true, reason: "" });
  mocks.netimQueryOpe.mockResolvedValue({ status: "done" });
  CREATE_RETRY_BACKOFFS_MS.splice(0, CREATE_RETRY_BACKOFFS_MS.length, 1000, 4000, 16000);
  delete process.env.SNIPE_DRY_RUN;
}

beforeEach(() => { resetAll(); });

// ── isSuspectRelease (pure) ──────────────────────────────────────────────────
describe("isSuspectRelease", () => {
  it("false for a registered WHOIS hit (has EPP codes)", () => {
    const r = { status: true, result: { status: [{ status: "clientTransferProhibited", url: "" }] } } as never;
    expect(isSuspectRelease(r)).toBe(false);
  });

  it("true when a scraped WHOIS says Available", () => {
    const r = { status: true, result: { status: [{ status: "Available", url: "" }] } } as never;
    expect(isSuspectRelease(r)).toBe(true);
  });

  it("true for an authoritative not-found verdict", () => {
    const r = { status: false, error: "No match for domain", dnsProbe: {} } as never;
    expect(isSuspectRelease(r)).toBe(true);
  });

  it("false on a bare timeout", () => {
    expect(isSuspectRelease(null)).toBe(false);
    const r = { status: false, error: "whois server timeout", dnsProbe: {} } as never;
    expect(isSuspectRelease(r)).toBe(false);
  });
});

// ── State machine via runDailyProbe ──────────────────────────────────────────
describe("daily probe — arming", () => {
  it("arms a watching target when balance and price are fine", async () => {
    const { store } = wireDb([makeTarget({ status: "watching" })]);
    mocks.lookupWhoisWithCache.mockResolvedValue({
      status: true, result: { status: [{ status: "clientTransferProhibited", url: "" }], expirationDate: "2026-10-01" },
    });

    const summary = await runDailyProbe();

    const t = store.get("11111111-2222-3333-4444-555555555555")!;
    expect(t.status).toBe("armed");
    expect(t.est_price).toBe(10);
    expect(summary.results[0].outcome).toBe("still_registered");
  });

  it("moves a target to blocked_balance when balance is insufficient", async () => {
    wireDb([makeTarget({ status: "watching" })]);
    mocks.lookupWhoisWithCache.mockResolvedValue({
      status: true, result: { status: [{ status: "clientTransferProhibited", url: "" }], expirationDate: "2026-10-01" },
    });
    mocks.netimQueryResellerAccount.mockResolvedValue({
      balance: 5, defaultOwner: "LJ5552", defaultAdmin: "LJ5551",
      defaultTech: "LJ5551", defaultBilling: "LJ5551", defaultDns1: "ns1.nic.bn", defaultDns2: "ns2.nic.bn",
    });

    const summary = await runDailyProbe();
    expect(summary.results[0].outcome).toBe("blocked_balance");
    // recharge alert sent once, rate-limited afterwards
    expect(mocks.sendEmail).toHaveBeenCalledTimes(1);
  });
});

describe("hunt probe — release → create", () => {
  it("registers a released domain (create ok + ope done)", async () => {
    const { store } = wireDb([makeTarget({ status: "armed", hunt_start: "2000-01-01", hunt_end: "2999-01-01" })]);
    mocks.lookupWhoisWithCache.mockResolvedValue({
      status: false, error: "No match for domain", dnsProbe: { registrationStatus: "unregistered" },
    });
    mocks.netimDomainCheck.mockResolvedValue({ available: true, reason: "" });
    mocks.netimQueryOpe.mockResolvedValue({ status: "done" });
    mocks.netimDomainCreate.mockResolvedValue({ ok: true, opeId: "OPE-123", transient: false });

    const summary = await runHuntProbe();

    const t = store.get("11111111-2222-3333-4444-555555555555")!;
    expect(t.status).toBe("succeeded");
    expect(mocks.netimDomainCreate).toHaveBeenCalledTimes(1);
    expect(mocks.netimDomainCreate).toHaveBeenCalledWith("example.sb", 1);
    expect(mocks.sendEmail).toHaveBeenCalledTimes(1); // success email
    expect(summary.results[0].outcome).toBe("succeeded");
  });

  it("records a permanent failure when create is deterministically refused", async () => {
    const { store } = wireDb([makeTarget({ status: "armed", hunt_start: "2000-01-01", hunt_end: "2999-01-01" })]);
    mocks.lookupWhoisWithCache.mockResolvedValue({
      status: false, error: "No match for domain", dnsProbe: { registrationStatus: "unregistered" },
    });
    mocks.netimDomainCreate.mockResolvedValue({ ok: false, reason: "E13-M1305 domain syntax", transient: false });

    const summary = await runHuntProbe();

    const t = store.get("11111111-2222-3333-4444-555555555555")!;
    expect(t.status).toBe("failed");
    expect(t.fail_reason).toContain("syntax");
    expect(summary.results[0].outcome).toBe("failed_permanent");
  });

  it("retries transient create failures with backoff, then succeeds", async () => {
    CREATE_RETRY_BACKOFFS_MS.splice(0, CREATE_RETRY_BACKOFFS_MS.length, 0, 0, 0);
    const { store } = wireDb([makeTarget({ status: "armed", hunt_start: "2000-01-01", hunt_end: "2999-01-01" })]);
    mocks.lookupWhoisWithCache.mockResolvedValue({
      status: false, error: "No match for domain", dnsProbe: { registrationStatus: "unregistered" },
    });
    mocks.netimDomainCreate
      .mockResolvedValueOnce({ ok: false, reason: "network", transient: true })
      .mockResolvedValueOnce({ ok: false, reason: "network", transient: true })
      .mockResolvedValueOnce({ ok: true, opeId: "OPE-999", transient: false });

    const summary = await runHuntProbe();

    const t = store.get("11111111-2222-3333-4444-555555555555")!;
    expect(t.status).toBe("succeeded");
    expect(mocks.netimDomainCreate).toHaveBeenCalledTimes(3);
    expect(summary.results[0].outcome).toBe("succeeded");
  });

  it("returns to armed after exhausting transient retries", async () => {
    CREATE_RETRY_BACKOFFS_MS.splice(0, CREATE_RETRY_BACKOFFS_MS.length, 0, 0, 0);
    const { store } = wireDb([makeTarget({ status: "armed", hunt_start: "2000-01-01", hunt_end: "2999-01-01" })]);
    mocks.lookupWhoisWithCache.mockResolvedValue({
      status: false, error: "No match for domain", dnsProbe: { registrationStatus: "unregistered" },
    });
    mocks.netimDomainCreate.mockResolvedValue({ ok: false, reason: "timeout", transient: true });

    const summary = await runHuntProbe();

    const t = store.get("11111111-2222-3333-4444-555555555555")!;
    expect(t.status).toBe("armed");
    expect(summary.results[0].outcome).toBe("failed_transient");
  });

  it("skips registration when the live price exceeds max_price", async () => {
    const { store } = wireDb([makeTarget({ status: "armed", max_price: 8, hunt_start: "2000-01-01", hunt_end: "2999-01-01" })]);
    mocks.lookupWhoisWithCache.mockResolvedValue({
      status: false, error: "No match for domain", dnsProbe: { registrationStatus: "unregistered" },
    });
    mocks.netimQueryDomainPrice.mockResolvedValue({ isPremium: true, price: 60.5, renewalPrice: 60.5, currency: "EUR" });

    const summary = await runHuntProbe();

    const t = store.get("11111111-2222-3333-4444-555555555555")!;
    expect(t.status).toBe("armed"); // stays armed for the next probe
    expect(mocks.netimDomainCreate).not.toHaveBeenCalled();
    expect(summary.results[0].outcome).toBe("budget_skip");
  });

  it("stays on not_available when domainCheck says still registered", async () => {
    const { store } = wireDb([makeTarget({ status: "armed", hunt_start: "2000-01-01", hunt_end: "2999-01-01" })]);
    mocks.lookupWhoisWithCache.mockResolvedValue({
      status: false, error: "No match for domain", dnsProbe: { registrationStatus: "unregistered" },
    });
    mocks.netimDomainCheck.mockResolvedValue({ available: false, reason: "IN_USE" });

    const summary = await runHuntProbe();

    const t = store.get("11111111-2222-3333-4444-555555555555")!;
    expect(t.status).toBe("armed");
    expect(mocks.netimDomainCreate).not.toHaveBeenCalled();
    expect(summary.results[0].outcome).toBe("not_available");
  });

  it("skips a target already owned by another probe (claim lost)", async () => {
    wireDb([makeTarget({ status: "armed", probe_lock_at: nowIso(), hunt_start: "2000-01-01", hunt_end: "2999-01-01" })]);
    mocks.lookupWhoisWithCache.mockResolvedValue({
      status: false, error: "No match for domain", dnsProbe: { registrationStatus: "unregistered" },
    });

    const summary = await runHuntProbe();
    expect(summary.results[0].outcome).toBe("claimed_skipped");
    expect(mocks.netimDomainCreate).not.toHaveBeenCalled();
  });
});

describe("hunt probe — dry run", () => {
  it("runs the pipeline but never issues domainCreate when SNIPE_DRY_RUN=1", async () => {
    process.env.SNIPE_DRY_RUN = "1";
    const { store } = wireDb([makeTarget({ status: "armed", hunt_start: "2000-01-01", hunt_end: "2999-01-01" })]);
    mocks.lookupWhoisWithCache.mockResolvedValue({
      status: false, error: "No match for domain", dnsProbe: { registrationStatus: "unregistered" },
    });

    const summary = await runHuntProbe();

    const t = store.get("11111111-2222-3333-4444-555555555555")!;
    expect(t.status).toBe("armed");
    expect(mocks.netimDomainCreate).not.toHaveBeenCalled();
    expect(summary.results[0].outcome).toBe("dry_run");
    // audit trail still written
    const attemptSql = mocks.run.mock.calls.find((c) => String(c[0]).includes("INSERT INTO snipe_attempts"));
    expect(attemptSql).toBeTruthy();
  });

  it("reports the dry-run flag in the summary", async () => {
    process.env.SNIPE_DRY_RUN = "1";
    wireDb([]);
    mocks.lookupWhoisWithCache.mockResolvedValue({ status: false, error: "No match", dnsProbe: {} });
    const summary = await runHuntProbe();
    expect(summary.dryRun).toBe(true);
    expect(isDryRun()).toBe(true);
  });
});
