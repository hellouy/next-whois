import { describe, it, expect } from "vitest";
import { runDropPipeline, SOURCE_LABELS, type UpsertLeadInput } from "./drop-pipeline";
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
      upsertLead: async (lead: UpsertLeadInput) => { leads.push(lead); },
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
    expect(SOURCE_LABELS.whoisds).toBe("whoisds.com");
  });
});
