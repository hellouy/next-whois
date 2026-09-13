import { describe, it, expect } from "vitest";
import {
  PARKING_PLATFORMS,
  detectParkingProvider,
  detectParkingPlatformEntry,
} from "./parking-platforms";

describe("PARKING_PLATFORMS", () => {
  it("contains 20+ curated platforms", () => {
    expect(PARKING_PLATFORMS.length).toBeGreaterThanOrEqual(20);
  });

  it("every platform has at least one suffix and a valid kind", () => {
    for (const p of PARKING_PLATFORMS) {
      expect(p.suffixes.length).toBeGreaterThan(0);
      expect(["parking", "aftermarket", "both"]).toContain(p.kind);
    }
  });
});

describe("detectParkingProvider", () => {
  it("returns null for empty or missing nameservers", () => {
    expect(detectParkingProvider([])).toBeNull();
    expect(detectParkingProvider(undefined as unknown as string[])).toBeNull();
  });

  it("matches a bare suffix (exact match)", () => {
    expect(detectParkingProvider(["sedoparking.com"])).toBe("Sedo");
    expect(detectParkingProvider(["bodis.com"])).toBe("Bodis");
  });

  it("matches a subdomain NS against the suffix", () => {
    expect(detectParkingProvider(["ns1.sedoparking.com"])).toBe("Sedo");
    expect(detectParkingProvider(["parking01.afternic.com"])).toBe("Afternic");
  });

  it("is case-insensitive and tolerant of trailing dots", () => {
    expect(detectParkingProvider(["NS1.HUGEDOMAINS.COM."])).toBe("HugeDomains");
  });

  it("returns null when no NS matches a parking platform", () => {
    expect(detectParkingProvider(["ns1.cloudflare.com", "ns2.cloudflare.com"])).toBeNull();
    expect(detectParkingProvider(["ns1.google.com"])).toBeNull();
    expect(detectParkingProvider(["ns1.domaincontrol.com"])).toBeNull();
  });

  it("returns the first matching provider for a mixed NS set", () => {
    // Both are parking platforms; order of PARKING_PLATFORMS decides the winner.
    const provider = detectParkingProvider(["ns1.sedoparking.com", "ns2.bodis.com"]);
    expect(provider).toBeTruthy();
  });
});

describe("detectParkingPlatformEntry", () => {
  it("returns the full entry (kind + sales page) for a match", () => {
    const entry = detectParkingPlatformEntry(["ns1.sedoparking.com"]);
    expect(entry).not.toBeNull();
    expect(entry!.provider).toBe("Sedo");
    expect(entry!.kind).toBe("aftermarket");
    expect(entry!.salesPageDomain).toBe("sedo.com");
  });

  it("returns null for non-parking NS", () => {
    expect(detectParkingPlatformEntry(["ns1.hetzner.com"])).toBeNull();
  });
});
