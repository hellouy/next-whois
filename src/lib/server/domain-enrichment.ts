/**
 * Domain-info enrichment service.
 *
 * Takes a parsed WhoisAnalyzeResult (+ optional DNS probe) and augments it with
 * derived domain intelligence:
 *   - NS brand attribution + kind classification (parking / dns-hosting / registrar)
 *   - authoritative WHOIS-server attribution
 *   - parking / for-sale detection (three-signal merge)
 *   - date-triplet sanity checks
 *
 * All additions are OPTIONAL fields on WhoisAnalyzeResult, so existing
 * consumers are unaffected when enrichment data is absent. This module is pure
 * (no I/O) — the DB layer that persists enriched results lives in
 * `domain-enrichment-db.ts`.
 */

import { NsAttribution, DateSanity, WhoisAnalyzeResult } from "@/lib/whois/types";
import { resolveNsBrand, NsBrandKind } from "@/data/query-page/ns-brands";
import {
  detectParkingPlatformEntry,
  ParkingPlatformKind,
} from "@/data/query-page/parking-platforms";

/**
 * Built-in mapping of well-known WHOIS / RDAP authoritative server hostnames
 * to their owner brand. Used to attribute `whoisServer` values that don't
 * resolve through NS-brand matching (e.g. IANA bootstrap hosts).
 */
const WHOIS_SERVER_OWNERS: Array<{ owner: string; hostSuffixes: string[] }> = [
  { owner: "VeriSign", hostSuffixes: ["verisign-grs.com", "verisign.com"] },
  { owner: "ICANN", hostSuffixes: ["icann.org"] },
  { owner: "Afilias", hostSuffixes: ["afilias.net"] },
  { owner: "Neustar", hostSuffixes: ["neustar.com", "neustar.biz"] },
  { owner: "Nominet", hostSuffixes: ["nominet.uk"] },
  { owner: "CNNIC", hostSuffixes: ["cnnic.cn"] },
  { owner: "PIR", hostSuffixes: ["pir.org"] },
  { owner: "Identity Digital", hostSuffixes: ["identitydigital.services"] },
  { owner: "Gandi", hostSuffixes: ["gandi.net"] },
  { owner: "GoDaddy", hostSuffixes: ["godaddy.com"] },
  { owner: "MarkMonitor", hostSuffixes: ["markmonitor.com"] },
  { owner: "Sedo", hostSuffixes: ["sedo.com", "sedoparking.com"] },
  { owner: "RegistryGate", hostSuffixes: ["registrygate.com"] },
];

/** Map a WHOIS server hostname to a brand, or null when unrecognised. */
export function attributeWhoisServer(whoisServer: string): string | null {
  if (!whoisServer || whoisServer === "Unknown") return null;
  const lower = whoisServer.toLowerCase().replace(/^whois\./, "").trim();
  for (const entry of WHOIS_SERVER_OWNERS) {
    if (entry.hostSuffixes.some((s) => lower === s || lower.endsWith(`.${s}`) || lower.includes(s))) {
      return entry.owner;
    }
  }
  return null;
}

/**
 * Classify an individual nameserver:
 *   - parking platform NS (from the curated parking list) → "parking"
 *   - known NS brand with explicit kind → that kind
 *   - known NS brand without kind → "dns-hosting"
 *   - otherwise → "unknown"
 */
export function classifyNs(ns: string): {
  brand: string | null;
  kind: "dns-hosting" | "parking" | "registrar" | "unknown";
} {
  const parkingEntry = detectParkingPlatformEntry([ns]);
  if (parkingEntry) {
    return {
      brand: parkingEntry.provider,
      kind: "parking" as const,
    };
  }
  const brand = resolveNsBrand(ns);
  if (brand) {
    return { brand: brand.brand, kind: brand.kind };
  }
  return { brand: null, kind: "unknown" };
}

/** Build per-nameserver attributions from a result's nameServers array. */
export function attributeNameservers(nameServers: string[]): NsAttribution[] {
  if (!nameServers || nameServers.length === 0) return [];
  return nameServers.map((ns) => {
    const { brand, kind } = classifyNs(ns);
    return { ns, brand, kind };
  });
}

/**
 * Detect for-sale signals using three independent sources, in priority order:
 *   1. RDAP JSON — explicit listing fields (e.g. "termsAndConditions" is NOT a
 *      signal; only obvious aftermarket hints like epp statuses rarely appear,
 *      so we scan the RDAP body for explicit "for sale / listed" phrasing).
 *   2. WHOIS free-text — phrases like "for sale", "buy this domain", "listed on Sedo".
 *   3. NS attribution — NS pointing at a parking/aftermarket platform.
 * Returns the strongest signal found, or null when none applies.
 */
export function detectForSale(
  result: Pick<
    WhoisAnalyzeResult,
    "rawWhoisContent" | "rawRdapContent" | "parkingProvider"
  >,
): { forSale: boolean; source: string } | null {
  const salePhrases = [
    /\bfor sale\b/i,
    /\bbuy this domain\b/i,
    /\bdomain is for sale\b/i,
    /\bvisit .{0,40}(sedo|afternic|buydomains|dan\.com)\b/i,
    /\blisted on (sedo|afternic|hugedomains|dan\.com)\b/i,
  ];

  // Signal 1: RDAP body — scans JSON for explicit aftermarket phrasing.
  const rdapText = result.rawRdapContent ?? "";
  const rdapHit = rdapText ? salePhrases.find((re) => re.test(rdapText)) : undefined;
  if (rdapHit) return { forSale: true, source: "rdap-text" };

  // Signal 2: WHOIS free-text.
  const text = result.rawWhoisContent ?? "";
  const textHit = text ? salePhrases.find((re) => re.test(text)) : undefined;
  if (textHit) return { forSale: true, source: "whois-text" };

  // Signal 3: NS attribution to a parking/aftermarket platform.
  // parkingProvider is only ever set from the curated parking list, so its
  // presence is itself a strong for-sale signal.
  if (result.parkingProvider) {
    return { forSale: true, source: "ns-parking" };
  }
  return null;
}

/** Date sanity check: creation <= updated <= expiration (when all are known). */
export function sanityCheckDates(
  creationDate: string,
  updatedDate: string,
  expirationDate: string,
): DateSanity {
  const parse = (s: string): Date | null => {
    if (!s || s === "Unknown") return null;
    const d = new Date(s);
    return Number.isNaN(d.getTime()) ? null : d;
  };

  const creation = parse(creationDate);
  const updated = parse(updatedDate);
  const expiration = parse(expirationDate);
  const issues: string[] = [];

  if (creation && updated && creation.getTime() > updated.getTime()) {
    issues.push("creation > updated");
  }
  if (creation && expiration && creation.getTime() > expiration.getTime()) {
    issues.push("creation > expiration");
  }
  if (updated && expiration && updated.getTime() > expiration.getTime()) {
    issues.push("updated > expiration");
  }
  // Expired long ago (more than 1 year) while WHOIS still shows it — often
  // signals a stale record, but not necessarily an error worth flagging hard.
  if (expiration && expiration.getTime() < Date.now() - 365 * 24 * 3600 * 1000) {
    issues.push("expired > 1 year");
  }
  return { valid: issues.length === 0, issues };
}

/**
 * Merge all enrichment signals into the optional fields of a result.
 * Mutates and returns the same object (caller owns the instance).
 */
export function enrichDomainInfo(
  result: WhoisAnalyzeResult,
): WhoisAnalyzeResult {
  // NS attribution
  const nsAttributions = attributeNameservers(result.nameServers);
  if (nsAttributions.length > 0) {
    result.nsAttributions = nsAttributions;
  }

  // Parking / aftermarket via NS
  if (!result.parkingProvider && result.nameServers.length > 0) {
    const entry = detectParkingPlatformEntry(result.nameServers);
    if (entry) {
      result.parkingProvider = entry.provider;
      result.parkingKind = entry.kind;
    }
  }

  // WHOIS server attribution
  result.whoisServerAttribution = attributeWhoisServer(result.whoisServer) ?? undefined;

  // For-sale detection (depends on parkingProvider above)
  const forSaleSignal = detectForSale(result);
  if (forSaleSignal) {
    result.forSale = forSaleSignal.forSale;
    result.forSaleSource = forSaleSignal.source;
  }

  // Date sanity
  result.dateSanity = sanityCheckDates(
    result.creationDate,
    result.updatedDate,
    result.expirationDate,
  );

  return result;
}

export type { ParkingPlatformKind };
