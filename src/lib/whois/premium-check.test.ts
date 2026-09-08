import { describe, it, expect } from "vitest";
import { detectParkingProvider } from "./dns-check";
import { heuristicPremium } from "../server/premium-check";

describe("detectParkingProvider", () => {
  it("returns null for empty or non-parking nameservers", () => {
    expect(detectParkingProvider([])).toBeNull();
    expect(detectParkingProvider(["ns1.google.com", "ns2.google.com"])).toBeNull();
  });

  it("detects Sedo parking via sedoparking.com", () => {
    expect(detectParkingProvider(["ns1.sedoparking.com"])).toBe("Sedo");
    expect(detectParkingProvider(["NS2.SEDOPARKING.COM"])).toBe("Sedo");
  });

  it("detects Afternic and Bodis", () => {
    expect(detectParkingProvider(["ns1.afternic.com", "ns2.afternic.com"])).toBe("Afternic");
    expect(detectParkingProvider(["ns1.bodis.com"])).toBe("Bodis");
  });

  it("detects HugeDomains and Dan", () => {
    expect(detectParkingProvider(["ns1.hugedomains.com"])).toBe("HugeDomains");
    expect(detectParkingProvider(["ns1.dan.com"])).toBe("Dan.com");
  });

  it("does not flag GoDaddy's generic DNS hosting as parking", () => {
    expect(detectParkingProvider(["ns1.domaincontrol.com"])).toBeNull();
  });

  it("matches parking NS even when mixed with normal NS", () => {
    expect(detectParkingProvider(["ns1.example.com", "ns2.sedoparking.com"])).toBe("Sedo");
  });
});

describe("heuristicPremium", () => {
  it("flags short SLDs as premium", () => {
    expect(heuristicPremium("ab.com")?.isPremium).toBe(true);
    expect(heuristicPremium("abc.io")?.isPremium).toBe(true);
  });

  it("flags all-numeric SLDs as premium", () => {
    expect(heuristicPremium("12345.com")?.isPremium).toBe(true);
    expect(heuristicPremium("2024.net")?.isPremium).toBe(true);
  });

  it("does not flag ordinary word SLDs", () => {
    expect(heuristicPremium("example.com")).toBeNull();
    expect(heuristicPremium("mywebsite.io")).toBeNull();
  });
});
