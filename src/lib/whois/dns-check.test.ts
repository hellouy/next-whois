import { describe, it, expect, vi, beforeEach } from "vitest";
import dns from "dns/promises";
import { probeDomainFast, detectWildcardA, detectParkingProvider } from "./dns-check";

vi.mock("dns/promises", () => ({
  default: {
    resolveNs: vi.fn(),
    resolve4: vi.fn(),
    resolve6: vi.fn(),
    resolveMx: vi.fn(),
  },
}));

const mockDns = dns as unknown as {
  resolveNs: ReturnType<typeof vi.fn>;
  resolve4: ReturnType<typeof vi.fn>;
  resolve6: ReturnType<typeof vi.fn>;
  resolveMx: ReturnType<typeof vi.fn>;
};

function resolveOk(value: string[]) {
  return Promise.resolve(value);
}

function nxdomain() {
  const e = new Error("ENOTFOUND") as NodeJS.ErrnoException;
  e.code = "ENOTFOUND";
  return Promise.reject(e);
}

function servfail() {
  const e = new Error("ESERVFAIL") as NodeJS.ErrnoException;
  e.code = "ESERVFAIL";
  return Promise.reject(e);
}

function timeout() {
  return new Promise<never>((_resolve, reject) => {
    setTimeout(() => reject(new Error("ETIMEOUT")), 3000);
  });
}

beforeEach(() => {
  mockDns.resolveNs.mockReset();
  mockDns.resolve4.mockReset();
  mockDns.resolve6.mockReset();
  mockDns.resolveMx.mockReset();
});

describe("detectParkingProvider", () => {
  it("returns null for normal nameservers", () => {
    expect(detectParkingProvider(["ns1.example.com", "ns2.example.com"])).toBeNull();
  });

  it("detects parking platforms by NS suffix", () => {
    expect(detectParkingProvider(["parkingcrew.net"])).toBe("ParkingCrew");
    expect(detectParkingProvider(["dns1.sedoparking.com"])).toBe("Sedo");
    expect(detectParkingProvider(["ns1.bodis.com"])).toBe("Bodis");
  });

  it("handles empty NS input", () => {
    expect(detectParkingProvider([])).toBeNull();
    expect(detectParkingProvider(null as unknown as string[])).toBeNull();
  });
});

describe("probeDomainFast", () => {
  it("marks registered/high when NS records exist", async () => {
    mockDns.resolveNs.mockReturnValue(resolveOk(["ns1.example.com"]));
    mockDns.resolve4.mockReturnValue(resolveOk(["1.2.3.4"]));
    mockDns.resolve6.mockReturnValue(resolveOk([]));
    mockDns.resolveMx.mockReturnValue(resolveOk([]));

    const r = await probeDomainFast("example.com");
    expect(r.registrationStatus).toBe("registered");
    expect(r.confidence).toBe("high");
    expect(r.nameservers).toEqual(["ns1.example.com"]);
    expect(r.isWildcardA).toBe(false);
  });

  it("detects parked domain via NS", async () => {
    mockDns.resolveNs.mockReturnValue(resolveOk(["ns1.bodis.com"]));
    mockDns.resolve4.mockReturnValue(resolveOk(["1.2.3.4"]));
    mockDns.resolve6.mockReturnValue(resolveOk([]));
    mockDns.resolveMx.mockReturnValue(resolveOk([]));

    const r = await probeDomainFast("premium-name.com");
    expect(r.registrationStatus).toBe("registered");
    expect(r.parked).toBe(true);
    expect(r.parkingProvider).toBe("Bodis");
  });

  it("marks unregistered on NXDOMAIN for all record types", async () => {
    mockDns.resolveNs.mockReturnValue(nxdomain());
    mockDns.resolve4.mockReturnValue(nxdomain());
    mockDns.resolve6.mockReturnValue(nxdomain());
    mockDns.resolveMx.mockReturnValue(nxdomain());

    const r = await probeDomainFast("free-name.com");
    expect(r.registrationStatus).toBe("unregistered");
    expect(r.confidence).toBe("medium");
    expect(r.allTimedOut).toBe(false);
  });

  it("marks unregistered when all records are empty (ENODATA-style)", async () => {
    mockDns.resolveNs.mockReturnValue(resolveOk([]));
    mockDns.resolve4.mockReturnValue(resolveOk([]));
    mockDns.resolve6.mockReturnValue(resolveOk([]));
    mockDns.resolveMx.mockReturnValue(resolveOk([]));

    const r = await probeDomainFast("empty-name.com");
    expect(r.registrationStatus).toBe("unregistered");
    expect(r.confidence).toBe("medium");
  });

  it("marks unknown when every lookup times out", async () => {
    mockDns.resolveNs.mockReturnValue(timeout());
    mockDns.resolve4.mockReturnValue(timeout());
    mockDns.resolve6.mockReturnValue(timeout());
    mockDns.resolveMx.mockReturnValue(timeout());

    const r = await probeDomainFast("slow-name.com");
    expect(r.registrationStatus).toBe("unknown");
    expect(r.confidence).toBe("low");
    expect(r.allTimedOut).toBe(true);
  });

  it("marks unknown on ESERVFAIL (resolver error, not a no-records answer)", async () => {
    mockDns.resolveNs.mockReturnValue(servfail());
    mockDns.resolve4.mockReturnValue(servfail());
    mockDns.resolve6.mockReturnValue(servfail());
    mockDns.resolveMx.mockReturnValue(servfail());

    const r = await probeDomainFast("flaky-name.com");
    expect(r.registrationStatus).toBe("unknown");
    // ESERVFAIL is a resolver error, so every lookup yields "no info" (null) —
    // same allTimedOut semantics as a timeout, but it must NEVER become
    // "unregistered".
    expect(r.allTimedOut).toBe(true);
  });
});

describe("detectWildcardA", () => {
  it("returns true when the random subdomain shares the target A record", async () => {
    mockDns.resolve4.mockResolvedValueOnce(["203.0.113.7"]);
    mockDns.resolve6.mockResolvedValueOnce([]);
    mockDns.resolve4.mockResolvedValueOnce(["203.0.113.7"]);
    mockDns.resolve6.mockResolvedValueOnce([]);

    const r = await detectWildcardA("wl-example.com");
    expect(r).toBe(true);
  });

  it("returns false when the random subdomain has no A record", async () => {
    mockDns.resolve4.mockResolvedValueOnce(["203.0.113.7"]);
    mockDns.resolve6.mockResolvedValueOnce([]);
    mockDns.resolve4.mockResolvedValueOnce([]);
    mockDns.resolve6.mockResolvedValueOnce([]);

    const r = await detectWildcardA("real-example.com");
    expect(r).toBe(false);
  });

  it("returns false when the target itself has no A/AAAA records", async () => {
    mockDns.resolve4.mockResolvedValueOnce([]);
    mockDns.resolve6.mockResolvedValueOnce([]);

    const r = await detectWildcardA("empty-example.com");
    expect(r).toBe(false);
  });

  it("is not tripped when target and subdomain share no overlapping IPs", async () => {
    mockDns.resolve4.mockResolvedValueOnce(["198.51.100.10"]);
    mockDns.resolve6.mockResolvedValueOnce([]);
    mockDns.resolve4.mockResolvedValueOnce(["198.51.100.99"]);
    mockDns.resolve6.mockResolvedValueOnce([]);

    const r = await detectWildcardA("distinct-example.com");
    expect(r).toBe(false);
  });
});
