import { describe, it, expect } from "vitest";
import {
  parseDropDate,
  classifyStage,
  resolveDropDate,
  diffDays,
  inWindow,
} from "./drop-normalize";

describe("parseDropDate", () => {
  it("parses ISO dates", () => {
    expect(parseDropDate("2026-09-25")).toBe("2026-09-25");
  });

  it("parses slashed ISO dates", () => {
    expect(parseDropDate("2026/09/25")).toBe("2026-09-25");
  });

  it("parses day-first textual dates", () => {
    expect(parseDropDate("25-Sep-2026")).toBe("2026-09-25");
    expect(parseDropDate("25 Sep 2026")).toBe("2026-09-25");
  });

  it("parses month-first textual dates", () => {
    expect(parseDropDate("Sep 25, 2026")).toBe("2026-09-25");
    expect(parseDropDate("Sep 25 2026")).toBe("2026-09-25");
  });

  it("parses US numeric dates", () => {
    expect(parseDropDate("09/25/2026")).toBe("2026-09-25");
  });

  it("returns null for year-only values", () => {
    expect(parseDropDate("2018")).toBeNull();
    expect(parseDropDate("2026")).toBeNull();
  });

  it("returns null for placeholders and empty input", () => {
    expect(parseDropDate("")).toBeNull();
    expect(parseDropDate("-")).toBeNull();
    expect(parseDropDate("n/a")).toBeNull();
    expect(parseDropDate(null)).toBeNull();
    expect(parseDropDate(undefined)).toBeNull();
  });

  it("rejects impossible calendar dates", () => {
    expect(parseDropDate("2026-02-30")).toBeNull();
    expect(parseDropDate("2026-13-01")).toBeNull();
    expect(parseDropDate("2026-00-10")).toBeNull();
  });

  it("normalizes single-digit components", () => {
    expect(parseDropDate("2026-9-5")).toBe("2026-09-05");
  });
});

describe("classifyStage", () => {
  it("classifies pending-delete labels", () => {
    expect(classifyStage("pending delete")).toBe("pending_delete");
    expect(classifyStage("pendingdelete")).toBe("pending_delete");
    expect(classifyStage("redemptionPeriod")).toBe("pending_delete");
  });

  it("classifies expiring labels", () => {
    expect(classifyStage("expired")).toBe("expiring");
    expect(classifyStage("pre-release")).toBe("expiring");
    expect(classifyStage("grace period")).toBe("expiring");
  });

  it("classifies deleted labels", () => {
    expect(classifyStage("deleted")).toBe("deleted");
    expect(classifyStage("dropped")).toBe("deleted");
    expect(classifyStage("available")).toBe("deleted");
  });

  it("returns null for unknown or empty labels", () => {
    expect(classifyStage("weird-status")).toBeNull();
    expect(classifyStage("")).toBeNull();
    expect(classifyStage(null)).toBeNull();
  });
});

describe("resolveDropDate", () => {
  it("prefers the source date and reports deviation", () => {
    const r = resolveDropDate("2026-09-25", "2026-09-20");
    expect(r.dropDate).toBe("2026-09-25");
    expect(r.dateType).toBe("source");
    expect(r.deviationDays).toBe(5);
  });

  it("falls back to the derived date", () => {
    const r = resolveDropDate(null, "2026-10-01");
    expect(r.dropDate).toBe("2026-10-01");
    expect(r.dateType).toBe("derived");
    expect(r.deviationDays).toBeNull();
  });

  it("returns null when neither date exists", () => {
    const r = resolveDropDate(null, null);
    expect(r.dropDate).toBeNull();
    expect(r.deviationDays).toBeNull();
  });
});

describe("diffDays", () => {
  it("computes absolute day difference", () => {
    expect(diffDays("2026-09-25", "2026-09-20")).toBe(5);
    expect(diffDays("2026-09-20", "2026-09-25")).toBe(5);
    expect(diffDays("2026-09-25", "2026-09-25")).toBe(0);
  });

  it("returns 0 for invalid input", () => {
    expect(diffDays("bad", "2026-09-25")).toBe(0);
  });
});

describe("inWindow", () => {
  const today = "2026-09-22";

  it("includes today and the final day", () => {
    expect(inWindow("2026-09-22", today, 30)).toBe(true);
    expect(inWindow("2026-10-22", today, 30)).toBe(true);
  });

  it("excludes past dates and dates past the window", () => {
    expect(inWindow("2026-09-21", today, 30)).toBe(false);
    expect(inWindow("2026-10-23", today, 30)).toBe(false);
  });
});
