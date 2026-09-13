import { describe, it, expect, vi, beforeEach } from "vitest";
import { saveEnrichment, readEnrichment, ENRICHMENT_TTL_MS } from "./domain-enrichment-db";

vi.mock("@/lib/db-query", () => ({
  one: vi.fn(),
  run: vi.fn(),
}));

vi.mock("@/lib/server/redis", () => ({
  getJsonRedisValueWithTtl: vi.fn(),
  setJsonRedisValue: vi.fn(),
}));

import { one, run } from "@/lib/db-query";
import { getJsonRedisValueWithTtl, setJsonRedisValue } from "@/lib/server/redis";

const mockOne = one as unknown as ReturnType<typeof vi.fn>;
const mockRun = run as unknown as ReturnType<typeof vi.fn>;
const mockRedisGet = getJsonRedisValueWithTtl as unknown as ReturnType<typeof vi.fn>;
const mockRedisSet = setJsonRedisValue as unknown as ReturnType<typeof vi.fn>;

const sample = {
  registrar: "GoDaddy",
  registrarIanaId: "146",
  whoisServer: "whois.godaddy.com",
  whoisServerAttribution: "GoDaddy",
  parkingProvider: "Sedo",
  parkingKind: "aftermarket" as const,
  forSale: true,
  forSaleSource: "ns-parking",
  dateSanity: { valid: true, issues: [] },
  registrantPrivacy: false,
  nsAttributions: [{ ns: "ns1.sedoparking.com", brand: "Sedo", kind: "parking" as const }],
  dnssec: "unsigned",
};

describe("saveEnrichment", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("persists via UPSERT and warms Redis", async () => {
    mockRun.mockResolvedValue(1);
    mockRedisSet.mockResolvedValue(true);
    const ok = await saveEnrichment("Example.COM", sample);
    expect(ok).toBe(true);
    expect(mockRun).toHaveBeenCalledTimes(1);
    expect(mockRun.mock.calls[0][0]).toContain("INSERT INTO domain_enrichments");
    expect(mockRun.mock.calls[0][0]).toContain("ON CONFLICT (domain) DO UPDATE");
    expect(mockRedisSet).toHaveBeenCalledTimes(1);
  });

  it("degrades gracefully when the DB throws", async () => {
    mockRun.mockRejectedValue(new Error("connection refused"));
    const ok = await saveEnrichment("example.com", sample);
    expect(ok).toBe(false);
  });

  it("degrades gracefully when DB is unavailable (run returns -1)", async () => {
    mockRun.mockRejectedValue(new Error("no db"));
    const ok = await saveEnrichment("example.com", sample);
    expect(ok).toBe(false);
  });
});

describe("readEnrichment", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("reads from Redis L2 when present and fresh", async () => {
    mockRedisGet.mockResolvedValue({
      value: { ...sample, domain: "example.com", updatedAt: new Date().toISOString() },
      remainingTtl: 3600,
    });
    const hit = await readEnrichment("example.com");
    expect(hit).not.toBeNull();
    expect(hit!.stale).toBe(false);
    expect(hit!.row.registrar).toBe("GoDaddy");
    expect(mockOne).not.toHaveBeenCalled();
  });

  it("reads from PG when Redis misses", async () => {
    mockRedisGet.mockResolvedValue(null);
    mockOne.mockResolvedValue({
      domain: "example.com",
      registrar: "Sedo",
      registrar_iana_id: null,
      whois_server: "whois.sedo.com",
      whois_server_attribution: "Sedo",
      parking_provider: "Sedo",
      parking_kind: "aftermarket",
      for_sale: true,
      for_sale_source: "ns-parking",
      date_sanity: JSON.stringify({ valid: true, issues: [] }),
      registrant_privacy: false,
      ns_attributions: JSON.stringify([{ ns: "ns1.sedoparking.com", brand: "Sedo", kind: "parking" }]),
      dnssec: "unsigned",
      updated_at: new Date().toISOString(),
    });
    const hit = await readEnrichment("example.com");
    expect(hit).not.toBeNull();
    expect(hit!.stale).toBe(false);
    expect(hit!.row.parkingProvider).toBe("Sedo");
    expect(mockRedisSet).toHaveBeenCalledTimes(1);
  });

  it("marks rows older than TTL as stale", async () => {
    mockRedisGet.mockResolvedValue(null);
    mockOne.mockResolvedValue({
      domain: "example.com",
      registrar: "GoDaddy",
      registrar_iana_id: null,
      whois_server: null,
      whois_server_attribution: null,
      parking_provider: null,
      parking_kind: null,
      for_sale: null,
      for_sale_source: null,
      date_sanity: null,
      registrant_privacy: null,
      ns_attributions: null,
      dnssec: null,
      updated_at: new Date(Date.now() - ENRICHMENT_TTL_MS - 60_000).toISOString(),
    });
    const hit = await readEnrichment("example.com");
    expect(hit).not.toBeNull();
    expect(hit!.stale).toBe(true);
  });

  it("returns null when no row exists and Redis misses", async () => {
    mockRedisGet.mockResolvedValue(null);
    mockOne.mockResolvedValue(null);
    const hit = await readEnrichment("never-looked-up.com");
    expect(hit).toBeNull();
  });

  it("returns null when the DB throws", async () => {
    mockRedisGet.mockResolvedValue(null);
    mockOne.mockRejectedValue(new Error("db down"));
    const hit = await readEnrichment("example.com");
    expect(hit).toBeNull();
  });
});
