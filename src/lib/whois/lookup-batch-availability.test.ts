import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock network-boundary modules BEFORE importing lookup.ts.
vi.mock("@/lib/server/redis", () => ({
  getJsonRedisValueWithTtl: vi.fn().mockResolvedValue(null),
  setJsonRedisValue: vi.fn().mockResolvedValue(undefined),
  isRedisAvailable: vi.fn().mockReturnValue(false),
  getWhoisDbCache: vi.fn().mockResolvedValue(null),
  setWhoisDbCache: vi.fn().mockResolvedValue(undefined),
  setWhoisRateLimit: vi.fn().mockResolvedValue(undefined),
  checkWhoisRateLimit: vi.fn().mockResolvedValue(false),
}));

vi.mock("@/lib/server/premium-check", () => ({
  checkDomainPremium: vi.fn().mockResolvedValue(null),
}));

vi.mock("@/lib/pricing/client", () => ({
  getDomainPricing: vi.fn().mockResolvedValue(null),
  getDomainTransferNegotiable: vi.fn().mockResolvedValue(null),
}));

vi.mock("@/lib/whois/dns-check", async () => {
  const actual = await vi.importActual<typeof import("./dns-check")>("./dns-check");
  return {
    ...actual,
    probeDomain: vi.fn().mockResolvedValue(undefined),
    probeDomainFast: vi.fn(),
  };
});

vi.mock("@/lib/whois/dns-resolver", () => ({
  warmupDnsCache: vi.fn(),
}));

vi.mock("@/lib/db", () => ({
  recordTldLookupFailure: vi.fn().mockResolvedValue(undefined),
  getTldApiSource: vi.fn().mockResolvedValue(null),
  clearTldFailureStats: vi.fn().mockResolvedValue(undefined),
}));

vi.mock("@/lib/whois/whois-generic", async () => {
  const actual = await vi.importActual<typeof import("./whois-generic")>("./whois-generic");
  return {
    ...actual,
    // Never hit the network in tests: WHOIS returns nothing.
    tryGenericWhoisForDomain: vi.fn().mockResolvedValue(null),
    lookupIpOrAsn: vi.fn().mockResolvedValue(null),
  };
});

vi.mock("@/lib/whois/custom-servers", async () => {
  const actual = await vi.importActual<typeof import("./custom-servers")>("./custom-servers");
  return {
    ...actual,
    queryManualServerRacing: vi.fn().mockResolvedValue(null),
  };
});

vi.mock("@/lib/whois/rdap_client", async () => {
  const actual = await vi.importActual<typeof import("./rdap_client")>("./rdap_client");
  return {
    ...actual,
    // Default: no RDAP service for this TLD (throws). Tests override per-case.
    lookupRdap: vi.fn().mockRejectedValue(new Error("No RDAP server found")),
  };
});

vi.mock("./third-party-api", () => ({
  lookupViaThirdPartyApi: vi.fn().mockResolvedValue({ status: false }),
}));

const { lookupBatchAvailability } = await import("./lookup");
const dnsCheck = await import("./dns-check");
const rdapClient = await import("./rdap_client");

type FastProbe = Awaited<ReturnType<typeof import("./dns-check").probeDomainFast>>;

function probe(overrides: Partial<FastProbe> = {}): FastProbe {
  return {
    domain: "example.com",
    registrationStatus: "registered",
    confidence: "high",
    nameservers: [],
    ipv4: [],
    ipv6: [],
    mx: [],
    isWildcardA: false,
    parked: false,
    parkingProvider: null,
    allTimedOut: false,
    ...overrides,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  (dnsCheck.probeDomainFast as ReturnType<typeof vi.fn>).mockResolvedValue(probe());
  (rdapClient.lookupRdap as ReturnType<typeof vi.fn>).mockRejectedValue(new Error("No RDAP server found"));
});

describe("lookupBatchAvailability — DNS-first stage", () => {
  it("returns registered via DNS when NS records exist (skips RDAP/WHOIS)", async () => {
    (dnsCheck.probeDomainFast as ReturnType<typeof vi.fn>).mockResolvedValue(
      probe({ nameservers: ["ns1.example.com"] }),
    );
    const r = await lookupBatchAvailability("example.com");
    expect(r.registration).toBe("registered");
    expect(r.source).toBe("dns");
    expect(r.confidence).toBe("high");
    // RDAP must not be consulted on a strong DNS verdict.
    expect(rdapClient.lookupRdap).not.toHaveBeenCalled();
  });

  it("returns registered via DNS when parked NS detected", async () => {
    (dnsCheck.probeDomainFast as ReturnType<typeof vi.fn>).mockResolvedValue(
      probe({ nameservers: ["ns1.bodis.com"], parked: true, parkingProvider: "Bodis" }),
    );
    const r = await lookupBatchAvailability("premium-name.com");
    expect(r.registration).toBe("registered");
    expect(r.source).toBe("dns");
    expect(rdapClient.lookupRdap).not.toHaveBeenCalled();
  });

  it("does not mark available when DNS times out (falls back to full lookup)", async () => {
    (dnsCheck.probeDomainFast as ReturnType<typeof vi.fn>).mockResolvedValue(
      probe({ registrationStatus: "unknown", confidence: "low", allTimedOut: true }),
    );
    const r = await lookupBatchAvailability("slow-name.com");
    expect(r.registration).toBe("unknown");
    expect(r.registration).not.toBe("available");
  });
});

describe("lookupBatchAvailability — RDAP confirmation stage", () => {
  it("marks available when DNS says unregistered and RDAP returns 404", async () => {
    (dnsCheck.probeDomainFast as ReturnType<typeof vi.fn>).mockResolvedValue(
      probe({ registrationStatus: "unregistered", confidence: "medium" }),
    );
    (rdapClient.lookupRdap as ReturnType<typeof vi.fn>).mockResolvedValue({ errorCode: 404, title: "Object Not Found" });
    const r = await lookupBatchAvailability("free-name.com");
    expect(r.registration).toBe("available");
    expect(r.source).toBe("rdap");
  });

  it("marks reserved when RDAP confirms a registry-reserved status", async () => {
    (dnsCheck.probeDomainFast as ReturnType<typeof vi.fn>).mockResolvedValue(
      probe({ registrationStatus: "unregistered", confidence: "medium" }),
    );
    (rdapClient.lookupRdap as ReturnType<typeof vi.fn>).mockResolvedValue({
      ldhName: "reserved-name.com",
      status: ["reserved by registrar"],
    });
    // Surface registry-reserved via the RDAP status list. convertRdapToWhoisResult
    // is retained from the real module (vi.importActual), so we simply rely on
    // it mapping the RDAP "status" array into WhoisAnalyzeResult.status.
    const r = await lookupBatchAvailability("reserved-name.com");
    expect(r.registration).toBe("reserved");
    expect(r.source).toBe("rdap");
  });

  it("falls back to WHOIS guard when the TLD has no RDAP service", async () => {
    (dnsCheck.probeDomainFast as ReturnType<typeof vi.fn>).mockResolvedValue(
      probe({ registrationStatus: "unregistered", confidence: "medium" }),
    );
    // lookupRdap throws "No RDAP server found" (default) → WHOIS guard path.
    const r = await lookupBatchAvailability("no-rdap-name.com");
    // With WHOIS mocked to return nothing and DNS saying unregistered, the
    // fallback returns unknown rather than fabricating availability.
    expect(r.registration).toBe("unknown");
  });
});
