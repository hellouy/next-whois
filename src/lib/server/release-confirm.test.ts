import { describe, it, expect, vi, beforeEach } from "vitest";

const mocks = {
  lookupWhoisWithCache: vi.fn(),
  probeDomain: vi.fn(),
};

vi.mock("@/lib/whois/lookup", () => ({
  lookupWhoisWithCache: (...a: unknown[]) => mocks.lookupWhoisWithCache(...a),
}));

vi.mock("@/lib/whois/dns-check", () => ({
  probeDomain: (...a: unknown[]) => mocks.probeDomain(...a),
}));

import { confirmDomainReleased } from "@/lib/server/release-confirm";

function notFoundResult(): Awaited<ReturnType<typeof mocks.lookupWhoisWithCache>> {
  return { time: 0, status: false, error: "No match for domain", result: undefined };
}

function registeredResult(statuses: string[]): Awaited<ReturnType<typeof mocks.lookupWhoisWithCache>> {
  return {
    time: 0,
    status: true,
    result: {
      domain: "f.sb", registrar: "Registry Hold - Suspicious Activity", registrarURL: "Unknown",
      ianaId: "N/A", whoisServer: "whois.nic.sb", registryDomainId: "N/A", updatedDate: "Unknown",
      creationDate: "Unknown", expirationDate: "Unknown", status: statuses.map((status) => ({ status, url: "" })),
      nameServers: [], registrantName: "Unknown", registrantOrganization: "Unknown", registrantCountry: "Unknown",
      registrantProvince: "Unknown", registrantCity: "Unknown", registrantAddress: "Unknown",
      registrantPostalCode: "Unknown", registrantPhone: "Unknown", registrantFax: "Unknown",
      registrantEmail: "Unknown", adminName: "Unknown", adminOrganization: "Unknown", adminCountry: "Unknown",
      adminEmail: "Unknown", adminPhone: "Unknown", techName: "Unknown", techOrganization: "Unknown",
      techEmail: "Unknown", techPhone: "Unknown", abuseEmail: "Unknown", abusePhone: "Unknown",
      dnssec: "", rawWhoisContent: "", domainAge: null, remainingDays: null, registerPrice: null,
      renewPrice: null, negotiable: null, cidr: "Unknown", inetNum: "Unknown", inet6Num: "Unknown",
      netRange: "Unknown", netName: "Unknown", netType: "Unknown", originAS: "Unknown",
    },
  };
}

function dnsRegistered(): NonNullable<Awaited<ReturnType<typeof mocks.probeDomain>>> {
  return {
    domain: "f.sb", registrationStatus: "registered", confidence: "high", signals: [],
    nameservers: ["ns1.example.com"], ipv4: [], ipv6: [], mx: [], hasSsl: null,
  };
}

function dnsFree(): NonNullable<Awaited<ReturnType<typeof mocks.probeDomain>>> {
  return {
    domain: "f.sb", registrationStatus: "unregistered", confidence: "medium", signals: [],
    nameservers: [], ipv4: [], ipv6: [], mx: [], hasSsl: null,
  };
}

describe("confirmDomainReleased (three-source release check)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useRealTimers();
  });

  it("confirms release only when registry ×2 + DNS all report the name is free", async () => {
    mocks.lookupWhoisWithCache.mockResolvedValue(notFoundResult());
    mocks.probeDomain.mockResolvedValue(dnsFree());

    const c = await confirmDomainReleased("gone.example.com");
    expect(c.released).toBe(true);
    expect(mocks.lookupWhoisWithCache).toHaveBeenCalledTimes(2);
    expect(mocks.probeDomain).toHaveBeenCalledTimes(1);
  });

  it("refuses to release when the registry still returns registration data", async () => {
    mocks.lookupWhoisWithCache.mockResolvedValue(registeredResult(["inactive", "client hold", "server hold"]));

    const c = await confirmDomainReleased("f.sb");
    expect(c.released).toBe(false);
    expect(c.eppStatuses).toEqual(["inactive", "client hold", "server hold"]);
    // DNS never consulted — registry data already blocks the release
    expect(mocks.probeDomain).not.toHaveBeenCalled();
  });

  it("refuses to release when DNS still resolves the name (registry says free)", async () => {
    mocks.lookupWhoisWithCache.mockResolvedValue(notFoundResult());
    mocks.probeDomain.mockResolvedValue(dnsRegistered());

    const c = await confirmDomainReleased("f.sb");
    expect(c.released).toBe(false);
    expect(c.reason).toContain("DNS still resolves");
  });

  it("refuses to release when the second registry lookup disagrees", async () => {
    mocks.lookupWhoisWithCache
      .mockResolvedValueOnce(notFoundResult())
      .mockResolvedValueOnce(registeredResult(["inactive"]));
    mocks.probeDomain.mockResolvedValue(dnsFree());

    const c = await confirmDomainReleased("f.sb");
    expect(c.released).toBe(false);
    expect(c.reason).toContain("second registry lookup");
  });

  it("refuses to release on a generic lookup error (not a real not-registered signal)", async () => {
    mocks.lookupWhoisWithCache.mockResolvedValue({
      time: 0, status: false, error: "connected but returned no data", result: undefined,
    });

    const c = await confirmDomainReleased("f.sb");
    expect(c.released).toBe(false);
    expect(c.reason).toContain("not definitively free");
  });

  it("fails conservative when the first lookup times out", async () => {
    mocks.lookupWhoisWithCache.mockResolvedValue(null);

    const c = await confirmDomainReleased("slow.tld");
    expect(c.released).toBe(false);
    expect(c.reason).toContain("timed out");
  });
});