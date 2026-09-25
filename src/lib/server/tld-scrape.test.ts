import { describe, it, expect, vi, beforeEach } from "vitest";
import { parseAiJson } from "./tld-scrape";

vi.mock("@/lib/db-query", () => ({ run: vi.fn(), one: vi.fn() }));
vi.mock("@/lib/server/redis", () => ({
  isRedisAvailable: vi.fn(),
  getRedisValue: vi.fn(),
  setRedisValue: vi.fn(),
}));
vi.mock("@/lib/server/ai-providers", () => ({ callProviderWithFallback: vi.fn() }));
vi.mock("@/lib/server/lifecycle-overrides", () => ({
  invalidateLifecycleOverridesCache: vi.fn(),
}));

describe("parseAiJson", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("parses a valid lifecycle JSON with explicit field sources", () => {
    const out = parseAiJson(`{"grace_period_days":30,"redemption_period_days":25,"pending_delete_days":5,"pre_expiry_days":0,"drop_hour":10,"drop_minute":0,"drop_second":0,"drop_timezone":"Europe/Berlin","field_sources":{"grace_period_days":"page_explicit","redemption_period_days":"page_explicit","pending_delete_days":"industry_default","pre_expiry_days":"industry_default","drop_hour":"page_explicit"},"reasoning":"test"}`);

    expect(out.grace_period_days).toBe(30);
    expect(out.redemption_period_days).toBe(25);
    expect(out.pending_delete_days).toBe(5);
    expect(out.drop_hour).toBe(10);
    expect(out.drop_timezone).toBe("Europe/Berlin");
    expect(out.field_sources.redemption_period_days).toBe("page_explicit");
    expect(out.field_sources.drop_hour).toBe("page_explicit");
    // grace explicit + redemption explicit → high confidence
    expect(out.confidence).toBe("high");
  });

  it("normalizes legacy/accepted timezone spellings (R8)", () => {
    const out = parseAiJson(`{"grace_period_days":30,"redemption_period_days":30,"pending_delete_days":5,"pre_expiry_days":0,"drop_hour":4,"drop_minute":30,"drop_second":0,"drop_timezone":"JST","field_sources":{},"reasoning":"x"}`);
    expect(out.drop_timezone).toBe("Asia/Tokyo");
    expect(out.drop_hour).toBe(4);
    expect(out.drop_minute).toBe(30);

    const gmt = parseAiJson(`{"grace_period_days":30,"redemption_period_days":30,"pending_delete_days":5,"pre_expiry_days":0,"drop_hour":1,"drop_minute":0,"drop_second":0,"drop_timezone":"UTC+8","field_sources":{},"reasoning":"x"}`);
    expect(gmt.drop_timezone).toBe("UTC+08:00");
  });

  it("nulls the whole drop-time trio when timezone is invalid/absent (R8 AC2)", () => {
    const out = parseAiJson(`{"grace_period_days":30,"redemption_period_days":30,"pending_delete_days":5,"pre_expiry_days":0,"drop_hour":6,"drop_minute":0,"drop_second":0,"drop_timezone":"Mars/Olympus","field_sources":{},"reasoning":"x"}`);
    expect(out.drop_timezone).toBeNull();
    expect(out.drop_hour).toBeNull();
    expect(out.drop_minute).toBeNull();
    expect(out.drop_second).toBeNull();

    const absent = parseAiJson(`{"grace_period_days":30,"redemption_period_days":30,"pending_delete_days":5,"pre_expiry_days":0,"drop_hour":6,"drop_minute":0,"drop_second":0,"drop_timezone":null,"field_sources":{},"reasoning":"x"}`);
    expect(absent.drop_timezone).toBeNull();
    expect(absent.drop_hour).toBeNull();
  });

  it("clamps drop-time values to valid ranges (R8)", () => {
    const out = parseAiJson(`{"grace_period_days":30,"redemption_period_days":30,"pending_delete_days":5,"pre_expiry_days":0,"drop_hour":99,"drop_minute":77,"drop_second":5,"drop_timezone":"UTC","field_sources":{},"reasoning":"x"}`);
    expect(out.drop_hour).toBe(23);
    expect(out.drop_minute).toBe(59);
    expect(out.drop_second).toBe(5);
  });

  it("applies confidence=ai when only one of grace/redemption is explicit (R7)", () => {
    const out = parseAiJson(`{"grace_period_days":30,"redemption_period_days":30,"pending_delete_days":5,"pre_expiry_days":0,"drop_hour":null,"drop_minute":null,"drop_second":null,"drop_timezone":null,"field_sources":{"grace_period_days":"page_explicit","redemption_period_days":"industry_default","pending_delete_days":"industry_default","pre_expiry_days":"industry_default","drop_hour":"industry_default"},"reasoning":"x"}`);
    expect(out.confidence).toBe("ai");
  });

  it("defaults field sources to industry_default when values match defaults", () => {
    const out = parseAiJson(`{"grace_period_days":30,"redemption_period_days":30,"pending_delete_days":5,"pre_expiry_days":0,"drop_hour":null,"drop_minute":null,"drop_second":null,"drop_timezone":null,"field_sources":{},"reasoning":"x"}`);
    expect(out.field_sources.grace_period_days).toBe("industry_default");
    expect(out.field_sources.redemption_period_days).toBe("industry_default");
    expect(out.field_sources.pending_delete_days).toBe("industry_default");
    expect(out.field_sources.pre_expiry_days).toBe("industry_default");
  });

  it("strips markdown fences around the JSON", () => {
    const out = parseAiJson("```json\n{\"grace_period_days\":30,\"redemption_period_days\":30,\"pending_delete_days\":5,\"pre_expiry_days\":0,\"drop_hour\":null,\"drop_minute\":null,\"drop_second\":null,\"drop_timezone\":null,\"field_sources\":{},\"reasoning\":\"x\"}\n```");
    expect(out.grace_period_days).toBe(30);
  });
});