import { describe, it, expect } from "vitest";
import { hasBlockingEpp, enrichDropRow } from "./drop-lifecycle";
import type { RawDropRow } from "./drop-sources/types";

function row(overrides: Partial<RawDropRow>): RawDropRow {
  return {
    domain: "example.com",
    stage: "expiring",
    sourceDateType: "derived",
    ...overrides,
  };
}

describe("hasBlockingEpp", () => {
  it("detects blocking statuses regardless of formatting", () => {
    expect(hasBlockingEpp(["clientHold"])).toBe(true);
    expect(hasBlockingEpp(["server hold"])).toBe(true);
    expect(hasBlockingEpp(["clientTransferProhibited"])).toBe(true);
    expect(hasBlockingEpp(["disputed"])).toBe(true);
    expect(hasBlockingEpp(["suspicious activity"])).toBe(true);
  });

  it("ignores benign and empty status lists", () => {
    expect(hasBlockingEpp([])).toBe(false);
    expect(hasBlockingEpp(null)).toBe(false);
    expect(hasBlockingEpp(["ok"])).toBe(false);
  });
});

describe("enrichDropRow", () => {
  it("derives the drop date from expiry using the TLD lifecycle", () => {
    const out = enrichDropRow(row({ expiryDate: "2026-10-01" }))!;
    expect(out).not.toBeNull();
    expect(out.dateType).toBe("derived");
    expect(out.dropDate).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(out.confidence).toBe("high");
  });

  it("prefers a source date and records the deviation", () => {
    const out = enrichDropRow(
      row({ stage: "pending_delete", dropDate: "2026-11-01", expiryDate: "2026-10-01", sourceDateType: "source" }),
    )!;
    expect(out.dateType).toBe("source");
    expect(out.dropDate).toBe("2026-11-01");
    expect(out.deviationDays).toBeGreaterThan(0);
    expect(out.confidence).toBe("high");
  });

  it("marks the estimate low-confidence when the TLD has no lifecycle rule", () => {
    const out = enrichDropRow(row({ domain: "example.zzz", expiryDate: "2026-10-01" }))!;
    expect(out.confidence).toBe("low");
  });

  it("drops rows carrying blocking EPP statuses", () => {
    expect(enrichDropRow(row({ expiryDate: "2026-10-01" }), ["clientHold"])).toBeNull();
  });

  it("returns null when no date can be resolved", () => {
    expect(enrichDropRow(row({}))).toBeNull();
  });
});
