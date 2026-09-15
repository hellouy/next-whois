import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  liveCheckDomain,
  needsLiveCheck,
  classifyLive,
  type LiveStatus,
} from "./subscription-live";

vi.mock("@/lib/whois/lookup", () => ({
  lookupWhoisWithCache: vi.fn(),
}));

import { lookupWhoisWithCache } from "@/lib/whois/lookup";

const mockLookup = vi.mocked(lookupWhoisWithCache);

describe("needsLiveCheck", () => {
  it("skips in-range subscriptions", () => {
    expect(needsLiveCheck(null, true)).toBe(false);
    expect(needsLiveCheck("active", true)).toBe(false);
    expect(needsLiveCheck("active", false)).toBe(false);
  });

  it("re-checks grace and post-expiry / dropped phases", () => {
    expect(needsLiveCheck("grace", true)).toBe(true);
    expect(needsLiveCheck("grace", false)).toBe(true);
    expect(needsLiveCheck("dropped", true)).toBe(true);
    expect(needsLiveCheck("pendingDelete", true)).toBe(true);
    expect(needsLiveCheck("redemption", true)).toBe(true);
    expect(needsLiveCheck("dropped", false)).toBe(true);
  });
});

describe("classifyLive", () => {
  it("marks a still-occupied name on a cancelled subscription as re-registered", () => {
    expect(classifyLive("occupied", false)).toBe("re_registered");
  });

  it("passes through other combinations", () => {
    expect(classifyLive("occupied", true)).toBe("occupied");
    expect(classifyLive("released", false)).toBe("released");
    expect(classifyLive("released", true)).toBe("released");
    expect(classifyLive("unknown", false)).toBe("unknown");
  });
});

describe("liveCheckDomain", () => {
  function buildRes(statuses: string[], error = "") {
    return {
      result: { status: statuses.map((status) => ({ status })) },
      error,
    };
  }

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("classifies a name with EPP statuses as occupied", async () => {
    mockLookup.mockResolvedValue(buildRes(["clientHold", "serverHold"]) as never);
    const check = await liveCheckDomain("occupied.example");
    expect(check.live).toBe("occupied");
    expect(check.eppStatuses).toEqual(["clientHold", "serverHold"]);
    expect(check.recheckedAt).toBeTruthy();
  });

  it("classifies a name with no registration data as released", async () => {
    mockLookup.mockResolvedValue(buildRes([], "No match for RELEASED.EXAMPLE") as never);
    const check = await liveCheckDomain("released.example");
    expect(check.live).toBe("released");
    expect(check.eppStatuses).toEqual([]);
  });

  it("stays unknown on an ambiguous non-registration error", async () => {
    mockLookup.mockResolvedValue(buildRes([], "connect ETIMEDOUT 1.2.3.4:43") as never);
    const check = await liveCheckDomain("unknown.example");
    expect(check.live).toBe("unknown");
  });

  it("stays unknown when the lookup fails", async () => {
    mockLookup.mockRejectedValue(new Error("boom") as never);
    const check = await liveCheckDomain("fail.example");
    expect(check.live).toBe("unknown");
    expect(check.eppStatuses).toEqual([]);
  });

  it("throttles repeated lookups for the same domain", async () => {
    mockLookup.mockResolvedValue(buildRes(["pendingDelete"]) as never);
    await liveCheckDomain("throttle.example");
    await liveCheckDomain("throttle.example");
    const calls = mockLookup.mock.calls.filter((c) => c[0] === "throttle.example");
    expect(calls.length).toBe(1);
  });

  it("caches released status for later distribution", async () => {
    mockLookup.mockResolvedValue(buildRes([], "No match") as never);
    const first = await liveCheckDomain("cached.example");
    const second = await liveCheckDomain("cached.example");
    expect(second.live).toBe("released");
    expect(first.live).toBe(second.live);
    expect(mockLookup.mock.calls.filter((c) => c[0] === "cached.example").length).toBe(1);
  });
});