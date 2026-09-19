import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock all network + DB-backed dependencies so the pure scheduling/race logic
// in tryGenericWhoisForDomain can be tested deterministically.
vi.mock("@/lib/whois/whois-transport", () => ({
  queryWhoisTcp: vi.fn(),
}));
vi.mock("@/lib/whois/custom-servers", () => ({
  tryBuiltinServerForDomain: vi.fn(),
  tryManualServerForDomain: vi.fn(),
  getStaticWhoisServer: vi.fn(),
}));
vi.mock("@/lib/whois/whoiser-bypass", () => ({
  isWhoiserBypassed: vi.fn(),
  recordWhoiserFailure: vi.fn(() => Promise.resolve()),
  resetWhoiserFailureCounter: vi.fn(() => Promise.resolve()),
}));
vi.mock("@/lib/whois/internal-whoiser", () => ({
  getIanaWhoisServer: vi.fn(),
  whoisDomainInternal: vi.fn(),
  whoisIpInternal: vi.fn(),
  whoisAsnInternal: vi.fn(),
}));

import { queryWhoisTcp } from "@/lib/whois/whois-transport";
import {
  tryBuiltinServerForDomain,
  tryManualServerForDomain,
  getStaticWhoisServer,
} from "@/lib/whois/custom-servers";
import {
  isWhoiserBypassed,
  resetWhoiserFailureCounter,
} from "@/lib/whois/whoiser-bypass";
import { getIanaWhoisServer } from "@/lib/whois/internal-whoiser";
import { tryGenericWhoisForDomain } from "@/lib/whois/whois-generic";

const mQuery = queryWhoisTcp as unknown as ReturnType<typeof vi.fn>;
const mBuiltin = tryBuiltinServerForDomain as unknown as ReturnType<typeof vi.fn>;
const mManual = tryManualServerForDomain as unknown as ReturnType<typeof vi.fn>;
const mStatic = getStaticWhoisServer as unknown as ReturnType<typeof vi.fn>;
const mBypass = isWhoiserBypassed as unknown as ReturnType<typeof vi.fn>;
const mIana = getIanaWhoisServer as unknown as ReturnType<typeof vi.fn>;
const mReset = resetWhoiserFailureCounter as unknown as ReturnType<typeof vi.fn>;

function setupCommon() {
  mBuiltin.mockResolvedValue(null);
  mManual.mockResolvedValue(null);
  mBypass.mockResolvedValue(false);
  mIana.mockResolvedValue(null);
  mReset.mockResolvedValue(undefined);
}

describe("tryGenericWhoisForDomain — scheduling & race logic", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setupCommon();
  });

  it("short-circuits via builtin scraper before anything else", async () => {
    mBuiltin.mockResolvedValue({ raw: "builtin data", structured: {}, server: "nic-ba" });
    const r = await tryGenericWhoisForDomain("foo.ba", "ba", "ba", 5000, 1);
    expect(r.raw).toBe("builtin data");
    expect(mQuery).not.toHaveBeenCalled();
    expect(mManual).not.toHaveBeenCalled();
  });

  it("prefers admin manual server when configured", async () => {
    mManual.mockResolvedValue({ raw: "manual data", structured: {}, server: "whois.custom" });
    const r = await tryGenericWhoisForDomain("foo.com", "com", "com", 5000, 1);
    expect(r.raw).toBe("manual data");
    expect(mQuery).not.toHaveBeenCalled();
  });

  it("races static TCP first when a static server exists and not bypassed", async () => {
    mStatic.mockReturnValue("whois.verisign-grs.com");
    mQuery.mockResolvedValue("Domain Name: google.com\nRegistrar: MarkMonitor Inc.\n");
    const r = await tryGenericWhoisForDomain("google.com", "com", "com", 5000, 1);
    expect(r.raw).toContain("Domain Name:");
    expect(mQuery).toHaveBeenCalledWith(
      "whois.verisign-grs.com", 43, "google.com", expect.any(Number),
    );
    expect(mReset).toHaveBeenCalled(); // success resets failure counter
  });

  it("hits IANA fallback when static fails and chain is empty", async () => {
    mStatic.mockReturnValue(null); // no static server
    mIana.mockResolvedValue("whois.iana-host.example");
    mQuery.mockResolvedValue("Registry Data:\n");
    const r = await tryGenericWhoisForDomain("foo.io", "io", "io", 5000, 1);
    expect(r.raw).toContain("Registry Data:");
  });

  it("rejects a TCP result that is actually a connection-error string", async () => {
    mStatic.mockReturnValue("whois.nic.google");
    mQuery.mockResolvedValue("error: getaddrinfo ENOTFOUND whois.nic.google");
    await expect(tryGenericWhoisForDomain("foo.google", "google", "google", 5000, 1))
      .rejects.toThrow();
  });
});