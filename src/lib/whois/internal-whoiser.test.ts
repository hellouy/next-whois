import { describe, it, expect } from "vitest";
import { extractNextWhoisServer, parseSimpleWhoisLines, getKnownDiscoveryServer } from "./internal-whoiser";

describe("getKnownDiscoveryServer", () => {
  it("maps IANA-omitted servers locally without a network round-trip", () => {
    expect(getKnownDiscoveryServer("mil")).toBe("whois.nic.mil");
  });

  it("returns null for unknown TLDs", () => {
    expect(getKnownDiscoveryServer("com")).toBeNull();
    expect(getKnownDiscoveryServer("definitely-not-a-tld")).toBeNull();
  });
});

describe("extractNextWhoisServer", () => {
  it("follows Registrar WHOIS Server referrals", () => {
    const raw = "Domain Name: google.com\nRegistrar WHOIS Server: whois.markmonitor.com\n";
    expect(extractNextWhoisServer(raw, new Set())).toEqual({ host: "whois.markmonitor.com", port: 43 });
  });

  it("supports all referral field spellings", () => {
    const fields = [
      "Registry WHOIS Server: whois.reg.example",
      "ReferralServer: whois://whois.ref.example",
      "Registrar Whois: whois.who.example",
      "Whois Server: whois.ws.example",
      "WHOIS Server: whois.WS2.example",
    ];
    for (const line of fields) {
      expect(extractNextWhoisServer(line + "\n", new Set())?.host).toMatch(/example/i);
    }
  });

  it("strips protocol from URL referrals and keeps non-43 ports", () => {
    expect(extractNextWhoisServer("ReferralServer: rwhois://rwhois.example.net:4321\n", new Set()))
      .toEqual({ host: "rwhois.example.net", port: 4321 });
    expect(extractNextWhoisServer("ReferralServer: https://whois.example.com\n", new Set()))
      .toEqual({ host: "whois.example.com", port: 43 });
  });

  it("normalizes known misspelled referrals", () => {
    expect(extractNextWhoisServer("Whois Server: who.godaddy.com/\n", new Set())?.host)
      .toBe("whois.godaddy.com");
  });

  it("falls back to whois.google.com for Google Registrar URLs", () => {
    expect(extractNextWhoisServer("Registrar URL: https://domains.google\n", new Set())?.host)
      .toBe("whois.google.com");
  });

  it("returns null when the server was already queried", () => {
    const raw = "Registrar WHOIS Server: whois.markmonitor.com\n";
    expect(extractNextWhoisServer(raw, new Set(["whois.markmonitor.com"]))).toBeNull();
  });

  it("returns null when no referral field is present", () => {
    expect(extractNextWhoisServer("Domain Name: example.com\nStatus: active\n", new Set())).toBeNull();
  });

  it("matches indented referral lines", () => {
    const raw = "  Registrar WHOIS Server: whois.markmonitor.com\n";
    expect(extractNextWhoisServer(raw, new Set())).toEqual({ host: "whois.markmonitor.com", port: 43 });
  });
});

describe("parseSimpleWhoisLines", () => {
  it("parses Key: Value pairs and collects repeats as arrays", () => {
    const parsed = parseSimpleWhoisLines("NetName: GOOGLE\nNetRange: 8.8.8.0 - 8.8.8.255\nOriginAS: AS15169\n");
    expect(parsed.NetName).toBe("GOOGLE");
    expect(parsed.NetRange).toBe("8.8.8.0 - 8.8.8.255");
    expect(parsed.OriginAS).toBe("AS15169");
  });

  it("drops %/# comment lines and keeps unparseable lines in text", () => {
    const parsed = parseSimpleWhoisLines("% IANA WHOIS server\n# hash comment\nsome free text\nKey: value\n");
    expect(parsed.Key).toBe("value");
    expect(parsed.text).toEqual(["some free text"]);
    expect(JSON.stringify(parsed)).not.toContain("IANA");
  });
});
