import { describe, it, expect } from "vitest";
import {
  classifyNs,
  attributeNameservers,
  attributeWhoisServer,
  detectForSale,
  sanityCheckDates,
  enrichDomainInfo,
} from "./domain-enrichment";
import { WhoisAnalyzeResult, initialWhoisAnalyzeResult } from "@/lib/whois/types";

function baseResult(overrides: Partial<WhoisAnalyzeResult> = {}): WhoisAnalyzeResult {
  return { ...initialWhoisAnalyzeResult, ...overrides };
}

describe("classifyNs", () => {
  it("classifies parking NS as parking with the platform brand", () => {
    const c = classifyNs("ns1.sedoparking.com");
    expect(c.kind).toBe("parking");
    expect(c.brand).toBe("Sedo");
  });

  it("classifies known dns-hosting brands", () => {
    const c = classifyNs("ns1.cloudflare.com");
    expect(c.kind).toBe("dns-hosting");
    expect(c.brand).toBe("Cloudflare");
  });

  it("classifies registrar-kind brands", () => {
    const c = classifyNs("dns1.dynadot.com");
    expect(c.kind).toBe("registrar");
    expect(c.brand).toBe("Dynadot");
  });

  it("returns unknown for unrecognised nameservers", () => {
    const c = classifyNs("ns1.example-random-xyz.net");
    expect(c.kind).toBe("unknown");
    expect(c.brand).toBeNull();
  });
});

describe("attributeNameservers", () => {
  it("builds one attribution per nameserver", () => {
    const attrs = attributeNameservers(["ns1.sedoparking.com", "ns1.cloudflare.com", "ns1.mystery.com"]);
    expect(attrs).toHaveLength(3);
    expect(attrs[0]).toMatchObject({ ns: "ns1.sedoparking.com", brand: "Sedo", kind: "parking" });
    expect(attrs[1]).toMatchObject({ ns: "ns1.cloudflare.com", brand: "Cloudflare", kind: "dns-hosting" });
    expect(attrs[2]).toMatchObject({ ns: "ns1.mystery.com", brand: null, kind: "unknown" });
  });

  it("returns [] for empty input", () => {
    expect(attributeNameservers([])).toEqual([]);
  });
});

describe("attributeWhoisServer", () => {
  it("attributes VeriSign GRS hosts", () => {
    expect(attributeWhoisServer("whois.verisign-grs.com")).toBe("VeriSign");
  });

  it("attributes whois.godaddy.com", () => {
    expect(attributeWhoisServer("whois.godaddy.com")).toBe("GoDaddy");
  });

  it("returns null for Unknown and unrecognised hosts", () => {
    expect(attributeWhoisServer("Unknown")).toBeNull();
    expect(attributeWhoisServer("whois.example-tld-xyz")).toBeNull();
  });
});

describe("detectForSale", () => {
  it("detects for-sale phrasing in WHOIS text", () => {
    const hit = detectForSale({
      rawWhoisContent: "The domain is for sale. Contact broker@example.com",
      rawRdapContent: "",
      parkingProvider: undefined,
    });
    expect(hit).toEqual({ forSale: true, source: "whois-text" });
  });

  it("detects 'listed on Sedo' phrasing", () => {
    const hit = detectForSale({
      rawWhoisContent: "This domain is listed on Sedo",
      rawRdapContent: "",
      parkingProvider: undefined,
    });
    expect(hit).not.toBeNull();
    expect(hit!.forSale).toBe(true);
  });

  it("detects explicit aftermarket phrasing in RDAP JSON", () => {
    const hit = detectForSale({
      rawWhoisContent: "",
      rawRdapContent: '{"ldhName":"foo.com","remark":"for sale by owner"}',
      parkingProvider: undefined,
    });
    expect(hit).toEqual({ forSale: true, source: "rdap-text" });
  });

  it("treats a parking NS provider as a for-sale signal", () => {
    const hit = detectForSale({
      rawWhoisContent: "",
      rawRdapContent: "",
      parkingProvider: "Sedo",
    });
    expect(hit).toEqual({ forSale: true, source: "ns-parking" });
  });

  it("returns null when no signal is present", () => {
    const hit = detectForSale({
      rawWhoisContent: "registrar: GoDaddy\ncreated: 2020-01-01",
      rawRdapContent: "",
      parkingProvider: undefined,
    });
    expect(hit).toBeNull();
  });
});

describe("sanityCheckDates", () => {
  const now = Date.now();
  const day = 24 * 3600 * 1000;
  const iso = (ms: number) => new Date(ms).toISOString().slice(0, 10);
  const future2y = iso(now + 730 * day);
  const future1y = iso(now + 365 * day);
  const nowIso = iso(now);
  const past1y = iso(now - 365 * day);
  const past2y = iso(now - 730 * day);

  it("returns valid for a consistent triplet", () => {
    const s = sanityCheckDates(past2y, past1y, future1y);
    expect(s.valid).toBe(true);
    expect(s.issues).toEqual([]);
  });

  it("flags creation after updated", () => {
    const s = sanityCheckDates(future1y, past1y, future2y);
    expect(s.valid).toBe(false);
    expect(s.issues).toContain("creation > updated");
  });

  it("flags creation after expiration", () => {
    const s = sanityCheckDates(future2y, past1y, future1y);
    expect(s.valid).toBe(false);
    expect(s.issues).toContain("creation > expiration");
  });

  it("flags updated after expiration", () => {
    const s = sanityCheckDates(past2y, future1y, nowIso);
    expect(s.valid).toBe(false);
    expect(s.issues).toContain("updated > expiration");
  });

  it("flags long-expired domains", () => {
    const s = sanityCheckDates(past2y, past1y, iso(now - 5 * 365 * day));
    expect(s.valid).toBe(false);
    expect(s.issues).toContain("expired > 1 year");
  });

  it("tolerates Unknown values", () => {
    const s = sanityCheckDates("Unknown", "Unknown", "Unknown");
    expect(s.valid).toBe(true);
  });
});

describe("enrichDomainInfo", () => {
  it("populates ns attributions and parking provider", () => {
    const res = baseResult({
      nameServers: ["ns1.sedoparking.com"],
      rawWhoisContent: "",
    });
    enrichDomainInfo(res);
    expect(res.nsAttributions?.[0]).toMatchObject({ brand: "Sedo", kind: "parking" });
    expect(res.parkingProvider).toBe("Sedo");
    expect(res.parkingKind).toBe("aftermarket");
    expect(res.forSale).toBe(true);
    expect(res.forSaleSource).toBe("ns-parking");
  });

  it("attributes the whois server", () => {
    const res = baseResult({
      whoisServer: "whois.verisign-grs.com",
      nameServers: [],
    });
    enrichDomainInfo(res);
    expect(res.whoisServerAttribution).toBe("VeriSign");
  });

  it("computes date sanity", () => {
    const res = baseResult({
      creationDate: "2026-01-01",
      updatedDate: "2024-01-01",
      expirationDate: "2025-01-01",
      nameServers: [],
    });
    enrichDomainInfo(res);
    expect(res.dateSanity?.valid).toBe(false);
    expect(res.dateSanity?.issues).toContain("creation > updated");
  });

  it("does not crash on an empty result", () => {
    const res = baseResult();
    enrichDomainInfo(res);
    expect(res.dateSanity?.valid).toBe(true);
  });
});
