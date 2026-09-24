import { describe, it, expect, vi } from "vitest";

const dbMock = vi.hoisted(() => ({ run: vi.fn() }));

vi.mock("@/lib/db-query", () => ({ run: (...a: unknown[]) => dbMock.run(...a) }));

import { runDropPipeline, defaultUpsertLeads, SOURCE_LABELS, type UpsertLeadInput } from "./drop-pipeline";
import type { SourceRunOutcome } from "./drop-sources/types";
import type { CollectedRows } from "./drop-sources/registry";

function harness(rows: CollectedRows["rows"], outcomes: SourceRunOutcome[]) {
  const leads: UpsertLeadInput[] = [];
  const statuses: SourceRunOutcome[] = [];
  let invalidations = 0;

  return {
    leads,
    statuses,
    get invalidations() { return invalidations; },
    deps: {
      collect: async () => ({ rows, outcomes }),
      loadContext: async () => ({ hotPrefixes: new Map([["car", 20]]) }),
      upsertLeads: async (batch: UpsertLeadInput[]) => { leads.push(...batch); },
      recordSourceStatus: async (o: SourceRunOutcome) => { statuses.push(o); },
      invalidateCache: async () => { invalidations++; },
    },
  };
}

describe("runDropPipeline", () => {
  it("de-duplicates by domain, scores leads and maps the source label", async () => {
    const h = harness(
      [
        { domain: "car.com", stage: "deleted", dropDate: "2026-10-01", sourceDateType: "source", source: "expireddomains" },
        { domain: "car.com", stage: "deleted", dropDate: "2026-10-01", sourceDateType: "source", source: "expireddomains" },
        { domain: "nodate.com", stage: "expiring", sourceDateType: "derived", source: "whoisds" },
      ],
      [
        { source: "expireddomains", ok: true, items: 2, skipped: 0, error: null },
        { source: "whoisds", ok: false, items: 0, skipped: 0, error: "boom" },
      ],
    );

    const result = await runDropPipeline(h.deps);

    expect(result.upserted).toBe(1);
    expect(result.skipped).toBe(2);
    expect(h.leads).toHaveLength(1);

    const lead = h.leads[0];
    expect(lead.domain).toBe("car.com");
    expect(lead.tld).toBe("com");
    expect(lead.sld).toBe("car");
    expect(lead.charCount).toBe(3);
    expect(lead.source).toBe("expireddomains.net");
    expect(lead.valueScore).toBeGreaterThan(0);
    expect(typeof lead.valueTier).toBe("string");
    expect(Array.isArray(lead.valueReasons)).toBe(true);
  });

  it("records per-source status and invalidates the cache", async () => {
    const h = harness(
      [{ domain: "a.com", stage: "deleted", dropDate: "2026-10-01", sourceDateType: "source", source: "expireddomains" }],
      [{ source: "whoisds", ok: false, items: 0, skipped: 0, error: "boom" }],
    );

    await runDropPipeline(h.deps);

    expect(h.statuses).toEqual([{ source: "whoisds", ok: false, items: 0, skipped: 0, error: "boom" }]);
    expect(h.invalidations).toBe(1);
  });

  it("persists the registration status onto the lead", async () => {
    const h = harness(
      [
        { domain: "keep.com", stage: "deleted", dropDate: "2026-10-01", sourceDateType: "source", source: "whoisds", regStatus: "reserved" },
        { domain: "free.com", stage: "deleted", dropDate: "2026-10-01", sourceDateType: "source", source: "whoisds" },
      ],
      [{ source: "whoisds", ok: true, items: 2, skipped: 0, error: null }],
    );

    await runDropPipeline(h.deps);

    expect(h.leads.find((l) => l.domain === "keep.com")!.regStatus).toBe("reserved");
    expect(h.leads.find((l) => l.domain === "free.com")!.regStatus).toBe("available");
  });

  it("maps every known adapter id to its persisted label", () => {
    expect(SOURCE_LABELS.expireddomains).toBe("expireddomains.net");
    expect(SOURCE_LABELS["expireddomains-public"]).toBe("expireddomains.net (public)");
    expect(SOURCE_LABELS.whoisds).toBe("whoisds.com");
  });
});

function makeLead(domain: string): UpsertLeadInput {
  return {
    domain, tld: "com", sld: domain.split(".")[0], charCount: 3,
    bl: 1, dp: 2, dropDate: "2026-10-01", expiryDate: null,
    stage: "deleted", dateType: "source", regStatus: "available",
    valueScore: 10, valueTier: "low", valueReasons: ["x"], source: "expireddomains.net",
  };
}

describe("defaultUpsertLeads", () => {
  it("chunks rows into multi-row inserts with flat parameters", async () => {
    dbMock.run.mockReset();
    dbMock.run.mockResolvedValue(1);

    await defaultUpsertLeads(Array.from({ length: 60 }, (_, i) => makeLead(`d${i}.com`)));

    expect(dbMock.run).toHaveBeenCalledTimes(2);
    const [sql0, params0] = dbMock.run.mock.calls[0];
    const [, params1] = dbMock.run.mock.calls[1];
    expect(String(sql0)).toContain("ON CONFLICT (domain) DO UPDATE");
    expect(String(sql0)).toContain("VALUES ($1,");
    expect(params0).toHaveLength(50 * 15);
    expect(params1).toHaveLength(10 * 15);
    expect(params0[0]).toBe("d0.com");
    expect(params0[15]).toBe("d1.com");
  });

  it("does nothing for an empty batch", async () => {
    dbMock.run.mockReset();
    await defaultUpsertLeads([]);
    expect(dbMock.run).not.toHaveBeenCalled();
  });
});
