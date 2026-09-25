import { describe, it, expect } from "vitest";
import {
  normalizeDemoTlds,
  extractTld,
  isDemoTldMatch,
  buildDemoWhois,
} from "@/lib/demo-whois";

describe("normalizeDemoTlds", () => {
  it("parses dot-separated suffixes, drops leading dots and lowercases", () => {
    expect(normalizeDemoTlds(".xx, jb, .XYZ")).toEqual(["xx", "jb", "xyz"]);
  });

  it("dedupes repeated suffixes", () => {
    expect(normalizeDemoTlds("xx, xx ,XX")).toEqual(["xx"]);
  });

  it("returns empty array for empty/whitespace/null input", () => {
    expect(normalizeDemoTlds("")).toEqual([]);
    expect(normalizeDemoTlds(null)).toEqual([]);
    expect(normalizeDemoTlds("  ,  ")).toEqual([]);
  });

  it("supports multi-label custom suffixes", () => {
    expect(normalizeDemoTlds("com.demo, a.b")).toEqual(["com.demo", "a.b"]);
  });
});

describe("extractTld", () => {
  it("returns the last dot-separated label", () => {
    expect(extractTld("Example.XX")).toBe("xx");
    expect(extractTld("a.b.c")).toBe("c");
  });

  it("returns empty string when no dot", () => {
    expect(extractTld("examplecom")).toBe("");
  });
});

describe("isDemoTldMatch", () => {
  it("matches any prefix for a configured suffix", () => {
    expect(isDemoTldMatch("abc.xx", ["xx"])).toBe(true);
    expect(isDemoTldMatch("xx.xx", ["xx"])).toBe(true);
    expect(isDemoTldMatch("sub.deep.xx", ["xx"])).toBe(true);
  });

  it("is case-insensitive", () => {
    expect(isDemoTldMatch("EXAMPLE.XX", ["xx"])).toBe(true);
  });

  it("does not match when suffix not configured", () => {
    expect(isDemoTldMatch("example.com", ["xx"])).toBe(false);
    expect(isDemoTldMatch("abc.xx", ["jb"])).toBe(false);
  });

  it("does not match IPs, IPv6, ASN, or bare words", () => {
    expect(isDemoTldMatch("192.168.1.1", ["168"])).toBe(false);
    expect(isDemoTldMatch("2001:db8::1", ["db8"])).toBe(false);
    expect(isDemoTldMatch("AS12.xx", ["xx"])).toBe(true); // AS12.xx is a domain name
    expect(isDemoTldMatch("examplecom", ["examplecom"])).toBe(false); // no dot
    expect(isDemoTldMatch(".xx", ["xx"])).toBe(false); // leading-dot single label
  });

  it("returns false when the TLD list is empty", () => {
    expect(isDemoTldMatch("example.xx", [])).toBe(false);
  });
});

describe("buildDemoWhois", () => {
  const now = new Date("2026-09-25T12:00:00Z");
  const built = buildDemoWhois("Demo.XX", now);

  it("derives creation/expiry/updated relative to the query time", () => {
    const created = new Date(built.result.creationDate);
    const expiry  = new Date(built.result.expirationDate);
    const updated = new Date(built.result.updatedDate);
    expect(created.getTime()).toBe(now.getTime() - 60 * 60 * 1000); // now − 1h
    expect(expiry.getTime()).toBe(created.getTime() + 365 * 24 * 60 * 60 * 1000); // +1y
    expect(updated.getTime()).toBe(now.getTime());
  });

  it("fills the fixed demo credentials", () => {
    expect(built.result.registrantName).toBe("不讲李");
    expect(built.result.registrantCountry).toBe("中国");
    expect(built.result.registrantEmail).toBe("domain@nic.rw");
    expect(built.result.registrantPhone).toBe("+86.15801580158");
    expect(built.result.registrar).toBe("NIC.RW");
    expect(built.result.nameServers).toEqual(["NS1.NIC.RW", "NS2.NIC.RW"]);
    expect(built.result.status.map(s => s.status)).toContain("ok");
    expect(built.result.status.map(s => s.status)).toContain("clientTransferProhibited");
  });

  it("exposes a realistic raw WHOIS payload that contains the credentials", () => {
    expect(built.result.rawWhoisContent).toContain("Domain Name: demo.xx");
    expect(built.result.rawWhoisContent).toContain("Registrar: NIC.RW");
    expect(built.result.rawWhoisContent).toContain("domain@nic.rw");
    expect(built.result.rawWhoisContent).toContain("15801580158");
    expect(built.result.rawWhoisContent).toContain("Name Server: NS1.NIC.RW");
    expect(built.result.rawWhoisContent).toContain("Name Server: NS2.NIC.RW");
  });

  it("reports a registered DNS probe", () => {
    expect(built.dnsProbe.registrationStatus).toBe("registered");
    expect(built.dnsProbe.nameservers).toEqual(["NS1.NIC.RW", "NS2.NIC.RW"]);
  });

  it("declares whois source", () => {
    expect(built.source).toBe("whois");
  });
});