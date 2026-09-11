import { describe, it, expect } from "vitest";
import { getDomainRegistrationStatus } from "./DomainStatusHelpers";
import { initialWhoisAnalyzeResult, type WhoisAnalyzeResult } from "@/lib/whois/types";

function makeResult(overrides: Partial<WhoisAnalyzeResult>): WhoisAnalyzeResult {
  return {
    ...initialWhoisAnalyzeResult,
    domain: "china.tn",
    ...overrides,
  };
}

describe("getDomainRegistrationStatus", () => {
  it("treats a domain with registrar + creation date (no expiry) as registered", () => {
    const r = makeResult({
      registrar: "SAFOZI",
      creationDate: "2023-01-25T17:42:02.000Z",
      expirationDate: "Unknown",
      status: [{ status: "TRANSFER_PROHIBITED", url: "" }],
      rawWhoisContent: "Domain Name: china.tn\nRegistrar: SAFOZI\nCreation Date: 2023-01-25",
    });

    const s = getDomainRegistrationStatus(r, "zh");
    expect(s.type).toBe("registered");
  });

  it("treats a domain with only name servers as registered even when raw text mentions reserved", () => {
    const r = makeResult({
      registrar: "Unknown",
      creationDate: "Unknown",
      expirationDate: "Unknown",
      nameServers: ["ns1.example.com", "ns2.example.com"],
      status: [{ status: "registry-reserved", url: "" }],
      rawWhoisContent: "Domain Name: foo.ro\nThis domain is reserved by the registry",
    });

    const s = getDomainRegistrationStatus(r, "en");
    expect(s.type).toBe("registered");
  });

  it("keeps reserved when registrar exists but registry-reserved status is present without dates or name servers", () => {
    const r = makeResult({
      registrar: "GM-NIC (CYPDOM) — Gambia ccTLD Registry",
      creationDate: "Unknown",
      expirationDate: "Unknown",
      nameServers: [],
      status: [{ status: "registry-reserved", url: "" }],
      rawWhoisContent: "Domain Name: china.gm\nStatus: registry-reserved\n>>> Source: nic.gm web WHOIS <<<",
    });

    const s = getDomainRegistrationStatus(r, "zh");
    expect(s.type).toBe("reserved");
  });

  it("keeps reserved when there is no registration evidence at all", () => {
    const r = makeResult({
      registrar: "Unknown",
      creationDate: "Unknown",
      expirationDate: "Unknown",
      nameServers: [],
      status: [{ status: "registry-reserved", url: "" }],
      rawWhoisContent: "Domain Name: china.gm\nThis domain is reserved by the registry",
    });

    const s = getDomainRegistrationStatus(r, "zh");
    expect(s.type).toBe("reserved");
  });

  it("keeps prohibited when there is no registration evidence at all", () => {
    const r = makeResult({
      registrar: "Unknown",
      creationDate: "Unknown",
      expirationDate: "Unknown",
      nameServers: [],
      status: [{ status: "prohibited", url: "" }],
      rawWhoisContent: "Domain Name: blocked.tld\nDomain not available for registration",
    });

    const s = getDomainRegistrationStatus(r, "zh");
    expect(s.type).toBe("prohibited");
  });
});
