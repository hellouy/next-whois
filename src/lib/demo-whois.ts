/**
 * Demo-data mode (admin-configurable).
 *
 * When enabled, domains whose TLD matches the configured demo suffix(es) are
 * NEVER looked up against real WHOIS/RDAP registries.  Instead the query
 * returns a fixed, realistic-looking record generated from demo credentials
 * (created/updated/expiry are derived from the current query time).  This is
 * used to demo the results page in controlled environments.
 *
 * This module is client-safe (no server-only imports) so both the SSR page and
 * the client-side "invalid TLD" guard can share the same matching logic.
 */
import { initialWhoisAnalyzeResult, type WhoisAnalyzeResult } from "@/lib/whois/types";
import type { DnsProbeResult } from "@/lib/whois/dns-check";

export const DEMO_ENABLED_KEY = "demo_mode_enabled";
export const DEMO_TLD_KEY     = "demo_tld";
export const DEFAULT_DEMO_TLD = "xx";

/** Demo credentials — all fixed, provided by the site operator. */
export const DEMO_REGISTRANT_NAME  = "不讲李";
export const DEMO_REGISTRANT_COUNTRY = "中国";
export const DEMO_REGISTRANT_EMAIL = "domain@nic.rw";
export const DEMO_REGISTRANT_PHONE = "15801580158";
export const DEMO_REGISTRAR        = "NIC.RW";
export const DEMO_REGISTRAR_URL    = "https://www.nic.rw";
export const DEMO_WHOIS_SERVER     = "whois.nic.rw";
export const DEMO_NAMESERVERS      = ["NS1.NIC.RW", "NS2.NIC.RW"];
export const DEMO_STATUS           = "ok";

/**
 * Parse a raw admin setting string into a list of normalized TLDs.
 * Accepts dots as separators and a leading dot per entry.  Everything is
 * lowercased; empty/invalid tokens are dropped.
 *
 *   ".xx, jb, .XYZ" → ["xx", "jb", "xyz"]
 */
export function normalizeDemoTlds(raw: string | undefined | null): string[] {
  if (!raw) return [];
  const out = new Set<string>();
  for (const part of raw.split(/[\s,，、，]+/)) {
    const cleaned = part.trim().toLowerCase().replace(/^\.+/, "");
    if (cleaned && /^[a-z0-9\u00a1-\uffff][a-z0-9.\-\u00a1-\uffff]*$/.test(cleaned)) {
      out.add(cleaned);
    }
  }
  return [...out];
}

/** Extract the TLD (last dot-separated label) of a query target. */
export function extractTld(target: string): string {
  const parts = target.toLowerCase().split(".");
  return parts.length >= 2 ? parts[parts.length - 1] : "";
}

/**
 * True when `target` is a domain ending in one of the given TLDs.
 * Only domain-shaped inputs (contains a dot, doesn't start with a dot) match —
 * IPs, ASNs and bare words never do, so normal lookups are unaffected.
 */
export function isDemoTldMatch(target: string, tlds: string[]): boolean {
  if (!target || target.startsWith(".") || !target.includes(".")) return false;
  if (/^(\d{1,3}\.){3}\d{1,3}/.test(target)) return false;
  if (/^([0-9a-fA-F]{0,4}:){1,7}/.test(target)) return false;
  if (/^AS\d+$/i.test(target)) return false;
  if (tlds.length === 0) return false;
  const tld = extractTld(target);
  return tlds.includes(tld);
}

function fmtDate(d: Date): string {
  return d.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
}

/**
 * Build a complete, realistic-looking WhoisAnalyzeResult + DnsProbeResult for
 * the demo TLD.  Timestamps derive from `now`:
 *   creation  = now − 1 h
 *   expiry    = creation + 1 y
 *   updated   = now
 * Every other field is the fixed demo credential set above.
 */
export function buildDemoWhois(domain: string, now: Date = new Date()): {
  source: "whois";
  result: WhoisAnalyzeResult;
  dnsProbe: DnsProbeResult;
  rawWhois: string;
} {
  const lower = domain.toLowerCase();
  const created = new Date(now.getTime() - 60 * 60 * 1000);
  const expiry  = new Date(created.getTime() + 365 * 24 * 60 * 60 * 1000);

  const createdStr = fmtDate(created);
  const expiryStr  = fmtDate(expiry);
  const updatedStr = fmtDate(now);

  const rawWhois = [
    `Domain Name: ${lower}`,
    "Registry Domain ID: D-RW-DEMO-0001",
    "Registrar WHOIS Server: whois.nic.rw",
    "Registrar URL: https://www.nic.rw",
    `Updated Date: ${updatedStr}`,
    `Creation Date: ${createdStr}`,
    `Registrar Registration Expiration Date: ${expiryStr}`,
    "Registrar: NIC.RW",
    "Registrar IANA ID: 33035",
    `Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited`,
    `Domain Status: ${DEMO_STATUS} https://icann.org/epp#${DEMO_STATUS}`,
    "Registry Registrant ID: REDACTED FOR PRIVACY",
    `Registrant Name: ${DEMO_REGISTRANT_NAME}`,
    "Registrant Organization: NIC.RW",
    "Registrant Street: 北京市海淀区中关村大街",
    "Registrant City: 北京",
    "Registrant State/Province: 北京市",
    "Registrant Postal Code: 100080",
    `Registrant Country: ${DEMO_REGISTRANT_COUNTRY}`,
    `Registrant Phone: +86.${DEMO_REGISTRANT_PHONE}`,
    `Registrant Email: ${DEMO_REGISTRANT_EMAIL}`,
    "Registry Admin ID: REDACTED FOR PRIVACY",
    `Admin Name: ${DEMO_REGISTRANT_NAME}`,
    `Admin Email: ${DEMO_REGISTRANT_EMAIL}`,
    `Admin Phone: +86.${DEMO_REGISTRANT_PHONE}`,
    "Registry Tech ID: REDACTED FOR PRIVACY",
    `Tech Name: ${DEMO_REGISTRANT_NAME}`,
    `Tech Email: ${DEMO_REGISTRANT_EMAIL}`,
    `Tech Phone: +86.${DEMO_REGISTRANT_PHONE}`,
    `Name Server: ${DEMO_NAMESERVERS[0]}`,
    `Name Server: ${DEMO_NAMESERVERS[1]}`,
    "DNSSEC: unsigned",
    ">>> Last update of WHOIS database:",
    ">>> Please use this demo data for product demonstration only <<<",
    "",
  ].join("\n");

  const common: WhoisAnalyzeResult = {
    ...initialWhoisAnalyzeResult,
    domain: lower,
    registrar: DEMO_REGISTRAR,
    registrarURL: DEMO_REGISTRAR_URL,
    ianaId: "33035",
    whoisServer: DEMO_WHOIS_SERVER,
    registryDomainId: "D-RW-DEMO-0001",
    updatedDate: updatedStr,
    creationDate: createdStr,
    expirationDate: expiryStr,
    status: [
      { status: "clientTransferProhibited", url: "https://icann.org/epp#clientTransferProhibited" },
      { status: DEMO_STATUS, url: `https://icann.org/epp#${DEMO_STATUS}` },
    ],
    nameServers: DEMO_NAMESERVERS,
    registrantName: DEMO_REGISTRANT_NAME,
    registrantOrganization: "NIC.RW",
    registrantCountry: DEMO_REGISTRANT_COUNTRY,
    registrantProvince: "北京市",
    registrantCity: "北京",
    registrantAddress: "北京市海淀区中关村大街",
    registrantPostalCode: "100080",
    registrantPhone: `+86.${DEMO_REGISTRANT_PHONE}`,
    registrantFax: "Unknown",
    registrantEmail: DEMO_REGISTRANT_EMAIL,
    adminName: DEMO_REGISTRANT_NAME,
    adminOrganization: "NIC.RW",
    adminCountry: DEMO_REGISTRANT_COUNTRY,
    adminEmail: DEMO_REGISTRANT_EMAIL,
    adminPhone: `+86.${DEMO_REGISTRANT_PHONE}`,
    techName: DEMO_REGISTRANT_NAME,
    techOrganization: "NIC.RW",
    techEmail: DEMO_REGISTRANT_EMAIL,
    techPhone: `+86.${DEMO_REGISTRANT_PHONE}`,
    abuseEmail: DEMO_REGISTRANT_EMAIL,
    abusePhone: `+86.${DEMO_REGISTRANT_PHONE}`,
    dnssec: "unsigned",
    rawWhoisContent: rawWhois,
    domainAge: 0,
    remainingDays: 364,
    registerPrice: null,
    renewPrice: null,
    negotiable: null,
  };

  const dnsProbe: DnsProbeResult = {
    domain: lower,
    registrationStatus: "registered",
    confidence: "high",
    signals: [
      { type: "ns", value: DEMO_NAMESERVERS[0], label: "Authority NS" },
      { type: "ns", value: DEMO_NAMESERVERS[1], label: "Authority NS" },
    ],
    nameservers: DEMO_NAMESERVERS,
    ipv4: ["127.0.0.1"],
    ipv6: [],
    mx: [],
    hasSsl: null,
  };

  return { source: "whois", result: common, dnsProbe, rawWhois };
}