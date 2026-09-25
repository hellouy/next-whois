/**
 * Persistence layer for domain-enrichment results.
 *
 * Enriched domain intelligence is UPSERTed into the `domain_enrichments` table
 * keyed by domain, so repeat queries can reuse the result instead of
 * recomputing. Everything here is best-effort: a DB outage must never block or
 * fail the query path, so every call degrades to no-op / null on error.
 *
 * Read strategy (called from the lookup cache path):
 *   1. `getEnrichment` — fresh row (TTL window) → reuse
 *   2. row present but stale (older than TTL) → return it AND kick off a
 *      background refresh (`refreshEnrichment`) so the next visitor gets fresh
 *      data without paying the wait.
 *   3. no row → recompute in the main path and persist via `saveEnrichment`.
 */

import { NsAttribution, DateSanity } from "@/lib/whois/types";

/** Freshness window for stored enrichment rows. */
export const ENRICHMENT_TTL_MS = 7 * 24 * 3600 * 1000; // 7 days

/** Row shape as stored in the domain_enrichments table. */
export type StoredEnrichment = {
  domain: string;
  registrar: string | null;
  registrarIanaId: string | null;
  whoisServer: string | null;
  whoisServerAttribution: string | null;
  parkingProvider: string | null;
  parkingKind: "parking" | "aftermarket" | "both" | null;
  forSale: boolean | null;
  forSaleSource: string | null;
  dateSanity: DateSanity | null;
  registrantPrivacy: boolean | null;
  nsAttributions: NsAttribution[] | null;
  dnssec: string | null;
  /** DS records in presentation format ("keyTag algorithm digestType digest"). */
  dsRecords: string[] | null;
  updatedAt: string;
};

const ENRICHMENT_PREFIX = "enrich:";

function rowToStored(row: Record<string, unknown>): StoredEnrichment {
  const parseJson = <T,>(v: unknown, fallback: T): T => {
    if (v == null) return fallback;
    try { return JSON.parse(String(v)) as T; } catch { return fallback; }
  };
  return {
    domain: String(row.domain ?? ""),
    registrar: row.registrar ? String(row.registrar) : null,
    registrarIanaId: row.registrar_iana_id ? String(row.registrar_iana_id) : null,
    whoisServer: row.whois_server ? String(row.whois_server) : null,
    whoisServerAttribution: row.whois_server_attribution ? String(row.whois_server_attribution) : null,
    parkingProvider: row.parking_provider ? String(row.parking_provider) : null,
    parkingKind: (row.parking_kind as StoredEnrichment["parkingKind"]) ?? null,
    forSale: row.for_sale == null ? null : Boolean(row.for_sale),
    forSaleSource: row.for_sale_source ? String(row.for_sale_source) : null,
    dateSanity: parseJson<DateSanity | null>(row.date_sanity, null),
    registrantPrivacy: row.registrant_privacy == null ? null : Boolean(row.registrant_privacy),
    nsAttributions: parseJson<NsAttribution[] | null>(row.ns_attributions, null),
    dnssec: row.dnssec ? String(row.dnssec) : null,
    dsRecords: parseJson<string[] | null>(row.ds_records, null),
    updatedAt: String(row.updated_at ?? new Date().toISOString()),
  };
}

/**
 * Read a stored enrichment for a domain. Returns `{ row, stale }` where
 * `stale` is true when the row exists but is older than the TTL window.
 * Returns null when no row exists or the DB is unavailable.
 */
export async function readEnrichment(
  domain: string,
): Promise<{ row: StoredEnrichment; stale: boolean } | null> {
  try {
    const { getJsonRedisValueWithTtl } = await import("@/lib/server/redis");
    const cached = await getJsonRedisValueWithTtl<StoredEnrichment>(
      `${ENRICHMENT_PREFIX}${domain.toLowerCase()}`,
    );
    if (cached) {
      const row = cached.value;
      const stale = cached.remainingTtl == null || cached.remainingTtl <= 0;
      return { row, stale };
    }
  } catch { /* fall through to DB */ }

  try {
    const { one } = await import("@/lib/db-query");
    const row = await one<Record<string, unknown>>(
      `SELECT domain, registrar, registrar_iana_id, whois_server,
              whois_server_attribution, parking_provider, parking_kind,
              for_sale, for_sale_source, date_sanity, registrant_privacy,
              ns_attributions, dnssec, ds_records, updated_at
       FROM domain_enrichments
       WHERE domain = $1`,
      [domain.toLowerCase()],
    );
    if (!row) return null;
    const stored = rowToStored(row);
    const updated = new Date(stored.updatedAt).getTime();
    const stale = Date.now() - updated > ENRICHMENT_TTL_MS;
    // Warm the Redis L2 from PG so repeat reads avoid a DB round-trip.
    try {
      const { setJsonRedisValue } = await import("@/lib/server/redis");
      void setJsonRedisValue(
        `${ENRICHMENT_PREFIX}${domain.toLowerCase()}`,
        stored,
        Math.ceil(ENRICHMENT_TTL_MS / 1000),
      );
    } catch { /* ignore */ }
    return { row: stored, stale };
  } catch {
    return null;
  }
}

/**
 * Persist (UPSERT) an enrichment row. Best-effort — returns boolean success
 * but never throws.
 */
export async function saveEnrichment(
  domain: string,
  data: Omit<StoredEnrichment, "domain" | "updatedAt">,
): Promise<boolean> {
  const key = domain.toLowerCase();
  const stored: StoredEnrichment = {
    domain: key,
    ...data,
    updatedAt: new Date().toISOString(),
  };
  try {
    const { run } = await import("@/lib/db-query");
    await run(
      `INSERT INTO domain_enrichments (
         domain, registrar, registrar_iana_id, whois_server,
         whois_server_attribution, parking_provider, parking_kind,
         for_sale, for_sale_source, date_sanity, registrant_privacy,
         ns_attributions, dnssec, ds_records, updated_at
       ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW())
       ON CONFLICT (domain) DO UPDATE SET
         registrar = EXCLUDED.registrar,
         registrar_iana_id = EXCLUDED.registrar_iana_id,
         whois_server = EXCLUDED.whois_server,
         whois_server_attribution = EXCLUDED.whois_server_attribution,
         parking_provider = EXCLUDED.parking_provider,
         parking_kind = EXCLUDED.parking_kind,
         for_sale = EXCLUDED.for_sale,
         for_sale_source = EXCLUDED.for_sale_source,
         date_sanity = EXCLUDED.date_sanity,
         registrant_privacy = EXCLUDED.registrant_privacy,
         ns_attributions = EXCLUDED.ns_attributions,
         dnssec = EXCLUDED.dnssec,
         ds_records = EXCLUDED.ds_records,
         updated_at = NOW()`,
      [
        key,
        data.registrar,
        data.registrarIanaId,
        data.whoisServer,
        data.whoisServerAttribution,
        data.parkingProvider,
        data.parkingKind,
        data.forSale,
        data.forSaleSource,
        data.dateSanity ? JSON.stringify(data.dateSanity) : null,
        data.registrantPrivacy,
        data.nsAttributions ? JSON.stringify(data.nsAttributions) : null,
        data.dnssec,
        data.dsRecords && data.dsRecords.length > 0 ? JSON.stringify(data.dsRecords) : null,
      ],
    );
  } catch {
    return false;
  }
  try {
    const { setJsonRedisValue } = await import("@/lib/server/redis");
    void setJsonRedisValue(
      `${ENRICHMENT_PREFIX}${key}`,
      stored,
      Math.ceil(ENRICHMENT_TTL_MS / 1000),
    );
  } catch { /* ignore */ }
  return true;
}

/**
 * Fire-and-forget refresh: re-read the stored row's staleness state without
 * blocking the caller. Kept as a small wrapper so the lookup path reads
 * clearly (see readEnrichment — a stale row already triggers a recompute).
 */
export function refreshEnrichment(domain: string): Promise<StoredEnrichment | null> {
  return readEnrichment(domain).then((r) => r?.row ?? null).catch(() => null);
}
