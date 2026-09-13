/**
 * Static knowledge base of well-known domain parking / aftermarket listing
 * platforms, keyed by authoritative nameserver suffix.
 *
 * A domain whose NS records point at one of these platforms is very likely
 * parked or listed for sale (a "premium" aftermarket name). The list is
 * deliberately static and curated — we do NOT heuristically infer parking
 * from arbitrary NS names, because that would produce false positives for
 * ordinary DNS hosting providers.
 *
 * `kind` classifies each platform so callers can distinguish:
 *   - "parking"     — pure monetised parking (Bodis, ParkingCrew, ...)
 *   - "aftermarket" — marketplace listing / premium sales (Sedo, Afternic, ...)
 *   - "both"        — serves both roles (HugeDomains, Dan.com, ...)
 *
 * `domaincontrol.com` is deliberately excluded: it is GoDaddy's generic DNS
 * hosting and is used by countless normal, non-parked websites.
 */

export type ParkingPlatformKind = "parking" | "aftermarket" | "both";

export type ParkingPlatform = {
  /** Display name of the platform. */
  provider: string;
  /** Authoritative NS suffixes. Matching is suffix-based (equals or endsWith ".suffix"). */
  suffixes: string[];
  kind: ParkingPlatformKind;
  /** Optional canonical sales-page domain used for "listed on ..." labels. */
  salesPageDomain?: string;
};

/**
 * Curated list of 20+ domain parking / aftermarket platforms. Ordered roughly
 * by prominence; `detectParkingProvider` returns the FIRST provider that
 * matches, so ordering is only meaningful when a single NS set could match
 * multiple entries (rare in practice).
 */
export const PARKING_PLATFORMS: ParkingPlatform[] = [
  // ── Global marketplaces ────────────────────────────────────────────────
  { provider: "Sedo", suffixes: ["sedoparking.com", "sedo.com", "sedopark.com"], kind: "aftermarket", salesPageDomain: "sedo.com" },
  { provider: "Afternic", suffixes: ["afternic.com", "afternicparking.com"], kind: "aftermarket", salesPageDomain: "afternic.com" },
  { provider: "Dan.com", suffixes: ["dan.com"], kind: "both", salesPageDomain: "dan.com" },
  { provider: "HugeDomains", suffixes: ["hugedomains.com", "hugedomains.net"], kind: "both", salesPageDomain: "hugedomains.com" },
  { provider: "BuyDomains", suffixes: ["buydomains.com", "buydomains.net"], kind: "aftermarket", salesPageDomain: "buydomains.com" },
  { provider: "GoDaddy Auctions", suffixes: ["gddomainpark.com", "domainparking.com"], kind: "aftermarket", salesPageDomain: "godaddy.com" },
  { provider: "Flippa", suffixes: ["flippa.com"], kind: "aftermarket", salesPageDomain: "flippa.com" },
  { provider: "Squadhelp", suffixes: ["squadhelp.com", "shparking.com"], kind: "both", salesPageDomain: "squadhelp.com" },
  { provider: "BrandBucket", suffixes: ["brandbucket.com"], kind: "aftermarket", salesPageDomain: "brandbucket.com" },
  { provider: "DAN Marketplace", suffixes: ["dan.digital"], kind: "aftermarket", salesPageDomain: "dan.com" },

  // ── Monetised parking platforms ─────────────────────────────────────────
  { provider: "Bodis", suffixes: ["bodis.com"], kind: "parking", salesPageDomain: "bodis.com" },
  { provider: "ParkingCrew", suffixes: ["parkingcrew.net"], kind: "parking", salesPageDomain: "parkingcrew.com" },
  { provider: "Above.com", suffixes: ["above.com"], kind: "parking", salesPageDomain: "above.com" },
  { provider: "ParkLogic", suffixes: ["parklogic.com"], kind: "parking", salesPageDomain: "parklogic.com" },
  { provider: "DomainSponsor", suffixes: ["domainsponsor.com"], kind: "parking", salesPageDomain: "domains.com" },
  { provider: "Voodoo.com", suffixes: ["voodoo.com", "voodooparking.com"], kind: "parking", salesPageDomain: "voodoo.com" },
  { provider: "Park.io", suffixes: ["park.io", "parkio.com"], kind: "parking", salesPageDomain: "park.io" },
  { provider: "PCNAMES", suffixes: ["pcnames.com"], kind: "parking", salesPageDomain: "pcnames.com" },
  { provider: "SmartName", suffixes: ["smartname.com"], kind: "parking", salesPageDomain: "smartname.com" },
  { provider: "CatchTiger", suffixes: ["catchtiger.com"], kind: "parking", salesPageDomain: "catchtiger.com" },
  { provider: "ParkingPanel", suffixes: ["parkingpanel.com"], kind: "parking", salesPageDomain: "parkingpanel.com" },
  { provider: "Dike Parking", suffixes: ["dike.com", "dikeparking.com"], kind: "parking", salesPageDomain: "dike.com" },
  { provider: "Moniker Parking", suffixes: ["moniker.com"], kind: "parking", salesPageDomain: "moniker.com" },
  { provider: "ParkingDude", suffixes: ["parkingdude.com"], kind: "parking", salesPageDomain: "parkingdude.com" },
  { provider: "Voodoo", suffixes: ["vdooh.com"], kind: "parking", salesPageDomain: "voodoo.com" },

  // ── Regional / ccTLD-focused ───────────────────────────────────────────
  { provider: "4.cn (金名网)", suffixes: ["4.cn"], kind: "aftermarket", salesPageDomain: "4.cn" },
  { provider: "Uniregistry", suffixes: ["uniregistrymarket.link"], kind: "both", salesPageDomain: "uniregistry.com" },
  { provider: "Sedoparking EU", suffixes: ["sedoparking.eu"], kind: "parking", salesPageDomain: "sedo.de" },
  { provider: "NIC.biz Parked", suffixes: ["businessparking.com"], kind: "parking", salesPageDomain: "businessparking.com" },
  { provider: "Alterpark", suffixes: ["alterpark.com"], kind: "parking", salesPageDomain: "alterpark.com" },
  { provider: "Fabulous.com", suffixes: ["fabulous.com"], kind: "parking", salesPageDomain: "fabulous.com" },
  { provider: "Skenzo", suffixes: ["skenzo.com"], kind: "parking", salesPageDomain: "skenzo.com" },
  { provider: "Rook Media", suffixes: ["rookdns.com"], kind: "parking", salesPageDomain: "rookmedia.com" },
  { provider: "Gold Key", suffixes: ["goldkey.com"], kind: "parking", salesPageDomain: "goldkey.com" },
  { provider: "ASPParking", suffixes: ["asp.dk"], kind: "parking", salesPageDomain: "asp.dk" },
  { provider: "Tag Domain", suffixes: ["tagbrand.com"], kind: "aftermarket", salesPageDomain: "tagdomains.com" },
];

/**
 * Match a list of nameserver hostnames against the parking platform map.
 * Returns the first matching provider name, otherwise null.
 */
export function detectParkingProvider(nameservers: string[]): string | null {
  if (!nameservers || nameservers.length === 0) return null;
  const lower = nameservers.map((ns) => ns.toLowerCase().trim().replace(/\.$/, ""));
  for (const entry of PARKING_PLATFORMS) {
    for (const suffix of entry.suffixes) {
      const s = suffix.toLowerCase();
      const matched = lower.some(
        (ns) => ns === s || ns.endsWith(`.${s}`),
      );
      if (matched) return entry.provider;
    }
  }
  return null;
}

/**
 * Same matching as detectParkingProvider but returns the full platform entry
 * (kind + sales page), used by the enrichment service.
 */
export function detectParkingPlatformEntry(
  nameservers: string[],
): ParkingPlatform | null {
  if (!nameservers || nameservers.length === 0) return null;
  const lower = nameservers.map((ns) => ns.toLowerCase().trim().replace(/\.$/, ""));
  for (const entry of PARKING_PLATFORMS) {
    for (const suffix of entry.suffixes) {
      const s = suffix.toLowerCase();
      const matched = lower.some(
        (ns) => ns === s || ns.endsWith(`.${s}`),
      );
      if (matched) return entry;
    }
  }
  return null;
}
