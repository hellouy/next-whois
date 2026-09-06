import { describe, it, expect } from "vitest";
import {
  AUTHORITY_ORDER,
  sanitizeTimezone,
  isAllDefaults,
  isProblematic,
  parseAiJson,
  sortByAuthority,
  strategyOf,
  hasRealSource,
} from "../../scripts/lifecycle-parse.mjs";

describe("parseAiJson (multi-channel fields_source)", () => {
  it("parses flat output with fields_source channel refs", () => {
    const r = parseAiJson(`{"grace_period_days":0,"redemption_period_days":30,"pending_delete_days":0,
      "pre_expiry_days":0,"drop_hour":11,"drop_minute":0,"drop_second":null,
      "drop_timezone":"Europe/Copenhagen","reasoning":"denic","fields_source":{"grace_period_days":"registry","redemption_period_days":"registry","pending_delete_days":"registry"}}`);
    expect(r.grace_period_days).toBe(0);
    expect(r.redemption_period_days).toBe(30);
    expect(r.drop_hour).toBe(11);
    expect(r.drop_timezone).toBe("Europe/Copenhagen");
    expect(r.fields_source.grace_period_days).toBe("registry");
  });

  it("normalizes unknown channel refs to industry_default", () => {
    const r = parseAiJson(`{"grace_period_days":30,"redemption_period_days":30,"pending_delete_days":5,
      "fields_source":{"grace_period_days":"hacker","redemption_period_days":"registry"}}`);
    expect(r.fields_source.grace_period_days).toBe("industry_default");
    expect(r.fields_source.redemption_period_days).toBe("registry");
  });

  it("defaults fields_source to industry_default when absent", () => {
    const r = parseAiJson(`{"grace_period_days":30,"redemption_period_days":30,"pending_delete_days":5}`);
    expect(r.fields_source.grace_period_days).toBe("industry_default");
  });

  it("strips code fences and leading prose", () => {
    const r = parseAiJson(`Here is the answer:\n\`\`\`json\n{"grace_period_days":0,"redemption_period_days":30,"pending_delete_days":0}\n\`\`\``);
    expect(r.redemption_period_days).toBe(30);
  });

  it("clamps out-of-range drop values to null", () => {
    const r = parseAiJson(`{"grace_period_days":0,"redemption_period_days":30,"pending_delete_days":0,
      "drop_hour":99,"drop_minute":-1,"drop_second":70}`);
    expect(r.drop_hour).toBeNull();
    expect(r.drop_minute).toBeNull();
    expect(r.drop_second).toBeNull();
  });
});

describe("sanitizeTimezone (whitelist)", () => {
  it("accepts IANA zone names", () => {
    expect(sanitizeTimezone("Europe/Berlin")).toBe("Europe/Berlin");
    expect(sanitizeTimezone("Asia/Shanghai")).toBe("Asia/Shanghai");
    expect(sanitizeTimezone("UTC")).toBe("UTC");
    expect(sanitizeTimezone("Etc/UTC")).toBe("UTC");
  });

  it("rejects garbage, offsets and abbreviations", () => {
    expect(sanitizeTimezone("GMT+2")).toBeNull();
    expect(sanitizeTimezone("CET")).toBeNull();
    expect(sanitizeTimezone("Berlin")).toBeNull();
    expect(sanitizeTimezone("")).toBeNull();
    expect(sanitizeTimezone(null)).toBeNull();
    expect(sanitizeTimezone(123)).toBeNull();
  });
});

describe("isProblematic / isAllDefaults", () => {
  it("flags plain ICANN defaults", () => {
    expect(isAllDefaults({ grace_period_days: 30, redemption_period_days: 30, pending_delete_days: 5 })).toBe(true);
    expect(isProblematic({ grace_period_days: 30, redemption_period_days: 30, pending_delete_days: 5, reasoning: "" })).toBe(true);
  });

  it("flags 0/0/0 unless reasoning mentions instant deletion", () => {
    expect(isProblematic({ grace_period_days: 0, redemption_period_days: 0, pending_delete_days: 0, reasoning: "" })).toBe(true);
    expect(isProblematic({ grace_period_days: 0, redemption_period_days: 0, pending_delete_days: 0, reasoning: "deleted immediately" })).toBe(false);
  });

  it("accepts real registry values", () => {
    expect(isProblematic({ grace_period_days: 0, redemption_period_days: 30, pending_delete_days: 0, reasoning: "denic" })).toBe(false);
  });
});

describe("sortByAuthority / strategyOf", () => {
  const channels = [
    { channel: "search", status: "ok" },
    { channel: "registry", status: "ok" },
    { channel: "wiki", status: "ok" },
    { channel: "registrar", status: "ok" },
  ];
  it("orders channels by authority (registry first, search last)", () => {
    const sorted = sortByAuthority(channels);
    expect(sorted.map(c => c.channel)).toEqual(["registry", "registrar", "wiki", "search"]);
  });

  it("strategyOf concatenates hit channels, single name without plus", () => {
    expect(strategyOf([{ channel: "registry", status: "ok" }])).toBe("registry");
    expect(strategyOf([{ channel: "registry", status: "ok" }, { channel: "wiki", status: "ok" }])).toBe("registry+wiki");
    expect(strategyOf([{ channel: "registry", status: "error" }])).toBe("none");
  });

  it("authority order covers all seven channels", () => {
    expect(AUTHORITY_ORDER).toEqual(["registry","registrar","icann","wiki","search","wayback","iana"]);
  });
});

describe("hasRealSource", () => {
  it("true when any field has a real channel source", () => {
    expect(hasRealSource({ grace_period_days: "registry", redemption_period_days: "industry_default" })).toBe(true);
  });
  it("false when all industry_default or absent", () => {
    expect(hasRealSource({ grace_period_days: "industry_default", redemption_period_days: "industry_default" })).toBe(false);
    expect(hasRealSource(null)).toBe(false);
  });
});
