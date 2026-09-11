import { describe, it, expect } from "vitest";
import { parseSpf, parseDmarc } from "./dns-email";

describe("parseSpf", () => {
  it("parses v=spf1 with ip4/include and -all as fail", () => {
    const r = parseSpf("v=spf1 ip4:192.0.2.1/24 include:_spf.example.com -all");
    expect(r.allDirective).toBe("-all");
    expect(r.mechanisms.map(m => m.type)).toEqual(["ip4", "include"]);
    expect(r.mechanisms[0].value).toBe("192.0.2.1/24");
    expect(r.dnsLookupCount).toBe(1);
    expect(r.tooManyLookups).toBe(false);
  });

  it("parses ~all as softfail", () => {
    const r = parseSpf("v=spf1 mx ~all");
    expect(r.allDirective).toBe("~all");
  });

  it("parses +all as pass", () => {
    const r = parseSpf("v=spf1 +all");
    expect(r.allDirective).toBe("+all");
  });

  it("flags too many lookups", () => {
    const mechanisms = Array.from({ length: 12 }, (_, i) => `include:_spf${i}.example.com`).join(" ");
    const r = parseSpf(`v=spf1 ${mechanisms} ~all`);
    expect(r.tooManyLookups).toBe(true);
    expect(r.dnsLookupCount).toBe(12);
  });

  it("treats record without all directive as neutral", () => {
    const r = parseSpf("v=spf1 ip4:192.0.2.1");
    expect(r.allDirective).toBeNull();
  });

  it("handles redirect lookups", () => {
    const r = parseSpf("v=spf1 redirect:_spf.example.com");
    expect(r.dnsLookupCount).toBe(1);
    expect(r.mechanisms[0].type).toBe("redirect");
  });

  it("parses RFC-canonical redirect= syntax and counts it", () => {
    const r = parseSpf("v=spf1 redirect=_spf.example.com");
    expect(r.dnsLookupCount).toBe(1);
    expect(r.mechanisms[0].type).toBe("redirect");
    expect(r.mechanisms[0].value).toBe("_spf.example.com");
  });

  it("counts ptr toward DNS lookups", () => {
    const r = parseSpf("v=spf1 mx ptr -all");
    expect(r.dnsLookupCount).toBe(2);
  });
});

describe("parseDmarc", () => {
  it("parses p=reject as strong with rua/ruf", () => {
    const r = parseDmarc("v=DMARC1; p=reject; sp=quarantine; pct=100; rua=mailto:agg@example.com,mailto:alt@example.com; ruf=mailto:fr@example.com; adkim=s; aspf=s");
    expect(r.strength).toBe("strong");
    expect(r.p).toBe("reject");
    expect(r.sp).toBe("quarantine");
    expect(r.pct).toBe("100");
    expect(r.rua).toEqual(["agg@example.com", "alt@example.com"]);
    expect(r.ruf).toEqual(["fr@example.com"]);
    expect(r.adkim).toBe("s");
    expect(r.aspf).toBe("s");
  });

  it("parses p=quarantine as weak", () => {
    const r = parseDmarc("v=DMARC1; p=quarantine");
    expect(r.strength).toBe("weak");
  });

  it("parses p=none as none", () => {
    const r = parseDmarc("v=DMARC1; p=none");
    expect(r.strength).toBe("none");
  });

  it("treats missing p as none", () => {
    const r = parseDmarc("v=DMARC1; rua=mailto:a@example.com");
    expect(r.strength).toBe("none");
    expect(r.p).toBeNull();
  });

  it("returns empty arrays when no report URIs", () => {
    const r = parseDmarc("v=DMARC1; p=reject");
    expect(r.rua).toEqual([]);
    expect(r.ruf).toEqual([]);
  });

  it("normalizes uppercase tag values and keeps full mailto with = inside", () => {
    const r = parseDmarc("v=DMARC1; p=QUARANTINE; adkim=S; aspf=R; rua=mailto:user=name@example.com");
    expect(r.strength).toBe("weak");
    expect(r.adkim).toBe("s");
    expect(r.aspf).toBe("r");
    expect(r.rua).toEqual(["user=name@example.com"]);
  });
});
