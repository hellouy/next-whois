import { describe, it, expect } from "vitest";
import { nextReminderFiring } from "@/lib/lifecycle";

const DAY = 86_400_000;
const expiry = (daysAhead: number) => new Date(Date.now() + daysAhead * DAY);
const DEFAULTS = [60, 30, 10, 5, 1];

function days(firing: { at: Date } | null, nowMs: number): number | null {
  if (!firing) return null;
  return Math.round((firing.at.getTime() - nowMs) / DAY);
}

describe("nextReminderFiring (interval semantics)", () => {
  it("far future: fires the largest unsent threshold at expiry - t", () => {
    const now = new Date();
    const f = nextReminderFiring(DEFAULTS, 100, expiry(100), [], now);
    expect(f?.days).toBe(60);
    expect(f && Math.round((f.at.getTime() - now.getTime()) / DAY)).toBe(40); // expiry(100) - 60
  });

  it("exactly at a boundary (30 days) fires the 30-day tier, not 60", () => {
    const now = new Date();
    const f = nextReminderFiring(DEFAULTS, 30, expiry(30), [], now);
    expect(f?.days).toBe(30);
    // already inside (10, 30] → fires on the next processing run
    expect(f && Math.round((f.at.getTime() - now.getTime()) / DAY)).toBe(0);
  });

  it("late subscription (3 days left) fires tier 5 immediately, then tier 1 later", () => {
    const now = new Date();
    const f1 = nextReminderFiring(DEFAULTS, 3, expiry(3), [], now);
    expect(f1?.days).toBe(5); // interval (1, 5]
    expect(f1 && Math.round((f1.at.getTime() - now.getTime()) / DAY)).toBe(0);

    // after tier 5 sent, remaining = 2 days → tier 1 fires tomorrow (expiry - 1)
    const f2 = nextReminderFiring(DEFAULTS, 2, expiry(2), [5], now);
    expect(f2?.days).toBe(1);
    expect(f2 && Math.round((f2.at.getTime() - now.getTime()) / DAY)).toBe(1);

    // at 1 day left, tier 1 interval [0, 1] → fires next run
    const f3 = nextReminderFiring(DEFAULTS, 1, expiry(1), [5], now);
    expect(f3?.days).toBe(1);
  });

  it("skips sent tiers and respects windows", () => {
    const now = new Date();
    // 60 and 30 already sent, now 20 days left → tier 10 interval (5, 10] not yet,
    // firing date is expiry - 10
    const f = nextReminderFiring(DEFAULTS, 20, expiry(20), [60, 30], now);
    expect(f?.days).toBe(10);
    expect(f && Math.round((f.at.getTime() - now.getTime()) / DAY)).toBe(10);
  });

  it("returns null when all tiers were sent", () => {
    const now = new Date();
    expect(nextReminderFiring(DEFAULTS, 2, expiry(2), [60, 30, 10, 5, 1], now)).toBeNull();
  });

  it("handles custom out-of-order thresholds by sorting descending", () => {
    const now = new Date();
    const f = nextReminderFiring([1, 60, 5], 3, expiry(3), [], now);
    expect(f?.days).toBe(5); // (1, 5] contains 3
  });

  it("does not misfire a threshold whose window passed (daysToExpiry <= lower)", () => {
    const now = new Date();
    // custom tiers [30, 10], 12 days left, 30 sent → tier 30 window (10, 30] still
    // contains 12 but is sent; tier 10 window (0, 10] fires in the future at expiry-10
    const f = nextReminderFiring([30, 10], 12, expiry(12), [30], now);
    expect(f?.days).toBe(10);
    expect(f && Math.round((f.at.getTime() - now.getTime()) / DAY)).toBe(2);
  });
});
