/**
 * Third-party WHOIS API adapters.
 * Converts tianhu / yisi responses into a normalised WhoisResult so they
 * can be returned from the main lookup flow transparently.
 */
import { WhoisResult, WhoisAnalyzeResult, initialWhoisAnalyzeResult } from "./types";
import { many } from "@/lib/db-query";

// Keep well under Vercel's 10s Hobby-plan function limit.
const TIMEOUT_MS = 9_000;

function makeAbortSignal(): AbortSignal {
  // AbortSignal.timeout() is Node 17.3+ / modern browsers.  Fall back to
  // AbortController + setTimeout so the code works everywhere.
  if (typeof AbortSignal !== "undefined" && "timeout" in AbortSignal) {
    return (AbortSignal as any).timeout(TIMEOUT_MS);
  }
  const ac = new AbortController();
  setTimeout(() => ac.abort(), TIMEOUT_MS);
  return ac.signal;
}

// ── Shared helpers ─────────────────────────────────────────────────────────────

function daysBetween(a: string, b: string): number | null {
  try {
    const ms = new Date(b).getTime() - new Date(a).getTime();
    return isNaN(ms) ? null : Math.round(ms / 86_400_000);
  } catch {
    return null;
  }
}

function remainingDays(expiry: string): number | null {
  return daysBetween(new Date().toISOString(), expiry);
}

function domainAge(created: string): number | null {
  return daysBetween(created, new Date().toISOString());
}

// ── Tianhu adapter ─────────────────────────────────────────────────────────────

async function lookupViaTianhu(domain: string): Promise<WhoisResult> {
  const start = Date.now();
  const r = await fetch(
    `https://api.tian.hu/whois/${encodeURIComponent(domain)}`,
    { signal: makeAbortSignal(), headers: { Accept: "application/json" } },
  );
  if (!r.ok) return { status: false, time: (Date.now() - start) / 1000, error: `天虎 HTTP ${r.status}`, source: "tian.hu" };

  const j = await r.json();
  if (j.code !== 200 || !j.data) {
    return { status: false, time: (Date.now() - start) / 1000, error: j.message || "天虎查询失败", source: "tian.hu" };
  }

  const d = j.data?.formatted ?? {};
  const domainInfo = d.domain ?? {};
  const registrarInfo = d.registrar ?? {};
  const contactInfo = d.contact ?? {};
  const raw = j.data?.raw_data ?? JSON.stringify(j.data);

  const expirationDate = domainInfo.expiration_date ?? "Unknown";
  const creationDate   = domainInfo.creation_date   ?? "Unknown";

  const statuses: string[] = Array.isArray(domainInfo.status)
    ? domainInfo.status
    : typeof domainInfo.status === "string" ? [domainInfo.status] : [];

  const result: WhoisAnalyzeResult = {
    ...initialWhoisAnalyzeResult,
    domain,
    registrar:          registrarInfo.registrar_name ?? "Unknown",
    registrarURL:       registrarInfo.registrar_url  ?? "Unknown",
    ianaId:             registrarInfo.iana_id        ?? "N/A",
    whoisServer:        "tian.hu",
    updatedDate:        domainInfo.updated_date      ?? "Unknown",
    creationDate,
    expirationDate,
    nameServers:        Array.isArray(domainInfo.name_servers) ? domainInfo.name_servers : [],
    status:             statuses.map(s => ({ status: s, url: "" })),
    registrantName:     contactInfo.registrant_name  ?? "Unknown",
    registrantEmail:    contactInfo.registrant_email ?? "Unknown",
    registrantOrganization: contactInfo.registrant_org ?? "Unknown",
    registrantCountry:  contactInfo.registrant_country ?? "Unknown",
    dnssec:             domainInfo.dnssec ?? "Unknown",
    rawWhoisContent:    typeof raw === "string" ? raw : JSON.stringify(raw, null, 2),
    remainingDays:      expirationDate !== "Unknown" ? remainingDays(expirationDate) : null,
    domainAge:          creationDate   !== "Unknown" ? domainAge(creationDate)       : null,
    registerPrice: null, renewPrice: null, negotiable: null,
    cidr: "", inetNum: "", inet6Num: "", netRange: "", netName: "", netType: "", originAS: "",
    registryDomainId: "Unknown",
    registrantProvince: "Unknown", registrantCity: "Unknown",
    registrantAddress: "Unknown", registrantPostalCode: "Unknown",
    registrantPhone: "Unknown", registrantFax: "Unknown",
    adminName: "Unknown", adminOrganization: "Unknown",
    adminCountry: "Unknown", adminEmail: "Unknown", adminPhone: "Unknown",
    techName: "Unknown", techOrganization: "Unknown",
    techEmail: "Unknown", techPhone: "Unknown",
    abuseEmail: "Unknown", abusePhone: "Unknown",
  };

  return {
    status: true,
    time: (Date.now() - start) / 1000,
    source: "tian.hu",
    result,
  };
}

// ── Yisi adapter ───────────────────────────────────────────────────────────────

async function getYisiKey(): Promise<string> {
  const rows = await many<{ value: string }>(
    "SELECT value FROM site_settings WHERE key = 'api_yisi_key'",
  ).catch(() => []);
  return rows[0]?.value || process.env.YISI_API_KEY || "";
}

async function lookupViaYisi(domain: string): Promise<WhoisResult> {
  const start = Date.now();
  const apiKey = await getYisiKey();
  if (!apiKey) return { status: false, time: 0, error: "亿思云未配置 API Key", source: "YISI.YUN" };

  const r = await fetch(
    `https://yisi.yun/api/lookup?query=${encodeURIComponent(domain)}`,
    {
      signal: makeAbortSignal(),
      headers: { Accept: "application/json", "x-api-key": apiKey },
    },
  );
  if (!r.ok) return { status: false, time: (Date.now() - start) / 1000, error: `亿思云 HTTP ${r.status}`, source: "YISI.YUN" };
  const j = await r.json();
  if (!j.status) {
    return { status: false, time: (Date.now() - start) / 1000, error: j.error || "亿思云查询失败", source: "YISI.YUN" };
  }

  const d = j.result ?? {};
  const expirationDate = d.expiration_date ?? "Unknown";
  const creationDate   = d.creation_date   ?? "Unknown";

  const statuses: string[] = Array.isArray(d.status)
    ? d.status
    : typeof d.status === "string" ? [d.status] : [];

  const raw = typeof d.raw === "string" ? d.raw : JSON.stringify(d, null, 2);

  const result: WhoisAnalyzeResult = {
    ...initialWhoisAnalyzeResult,
    domain,
    registrar:       d.registrar       ?? "Unknown",
    registrarURL:    d.registrar_url   ?? "Unknown",
    ianaId:          d.iana_id         ?? "N/A",
    whoisServer:     "yisi.yun",
    updatedDate:     d.updated_date    ?? "Unknown",
    creationDate,
    expirationDate,
    nameServers:     Array.isArray(d.name_servers) ? d.name_servers : [],
    status:          statuses.map(s => ({ status: s, url: "" })),
    registrantName:  d.registrant_name ?? "Unknown",
    registrantEmail: d.registrant_email ?? "Unknown",
    registrantOrganization: d.registrant_org ?? "Unknown",
    registrantCountry: d.registrant_country ?? "Unknown",
    dnssec:          d.dnssec          ?? "Unknown",
    rawWhoisContent: raw,
    remainingDays:   expirationDate !== "Unknown" ? remainingDays(expirationDate) : null,
    domainAge:       creationDate   !== "Unknown" ? domainAge(creationDate)       : null,
    registerPrice: null, renewPrice: null, negotiable: null,
    cidr: "", inetNum: "", inet6Num: "", netRange: "", netName: "", netType: "", originAS: "",
    registryDomainId: "Unknown",
    registrantProvince: "Unknown", registrantCity: "Unknown",
    registrantAddress: "Unknown", registrantPostalCode: "Unknown",
    registrantPhone: "Unknown", registrantFax: "Unknown",
    adminName: "Unknown", adminOrganization: "Unknown",
    adminCountry: "Unknown", adminEmail: "Unknown", adminPhone: "Unknown",
    techName: "Unknown", techOrganization: "Unknown",
    techEmail: "Unknown", techPhone: "Unknown",
    abuseEmail: "Unknown", abusePhone: "Unknown",
  };

  return {
    status: true,
    time: (Date.now() - start) / 1000,
    source: "YISI.YUN",
    result,
  };
}

// ── Public entry point ─────────────────────────────────────────────────────────

export type ThirdPartyApiSource = "tianhu" | "yisi";

export async function lookupViaThirdPartyApi(
  domain: string,
  source: ThirdPartyApiSource,
): Promise<WhoisResult> {
  if (source === "tianhu") return lookupViaTianhu(domain);
  if (source === "yisi")   return lookupViaYisi(domain);
  return { status: false, time: 0, error: `未知 API 源: ${source}` };
}
