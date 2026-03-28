/**
 * Fallback WHOIS lookup via yisi.yun public API (no auth required).
 * Called when native RDAP + WHOIS produce no usable result for a domain.
 *
 * Endpoint: GET https://yisi.yun/api/lookup?query=<domain>
 */

import { WhoisResult, WhoisAnalyzeResult, DomainStatusProps, initialWhoisAnalyzeResult } from "@/lib/whois/types";

const YISI_API = "https://yisi.yun/api/lookup";
const YISI_TIMEOUT = 4_000;

interface YisiStatus {
  status: string;
  url: string;
}

interface YisiResult {
  domain: string;
  registrar: string;
  registrarURL: string;
  ianaId: string;
  whoisServer: string;
  creationDate: string | null;
  expirationDate: string | null;
  updatedDate: string | null;
  status: YisiStatus[];
  nameServers: string[];
  registrantOrganization: string | null;
  registrantOrganizationEn: string | null;
  registrantProvince: string | null;
  registrantCountry: string | null;
  registrantPhone: string | null;
  registrantEmail: string | null;
  dnssec: string | null;
  rawWhoisContent: string | null;
  domainAge: number | null;
  remainingDays: number | null;
  domainNotFound: boolean;
}

interface YisiResponse {
  status: boolean;
  time: number;
  cached?: boolean;
  source?: string;
  result?: YisiResult;
  error?: string;
}

function str(v: string | null | undefined, fallback = "Unknown"): string {
  if (!v || v.trim() === "" || v.trim().toLowerCase() === "unknown") return fallback;
  return v.trim();
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "Unknown";
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return "Unknown";
    return d.toISOString();
  } catch {
    return "Unknown";
  }
}

function hasUsableData(r: YisiResult): boolean {
  if (r.domainNotFound) return false;
  return (
    Boolean(r.registrar && r.registrar !== "Unknown") ||
    Boolean(r.expirationDate) ||
    Boolean(r.creationDate) ||
    (Array.isArray(r.nameServers) && r.nameServers.length > 0)
  );
}

function toAnalyzeResult(r: YisiResult, domain: string): WhoisAnalyzeResult {
  const statuses: DomainStatusProps[] = Array.isArray(r.status)
    ? r.status.map((s) => ({ status: s.status, url: s.url ?? "" }))
    : [];

  return {
    ...initialWhoisAnalyzeResult,
    domain: r.domain || domain,
    registrar: str(r.registrar),
    registrarURL: str(r.registrarURL),
    ianaId: str(r.ianaId, "N/A"),
    whoisServer: str(r.whoisServer),
    creationDate: formatDate(r.creationDate),
    expirationDate: formatDate(r.expirationDate),
    updatedDate: formatDate(r.updatedDate),
    status: statuses,
    nameServers: Array.isArray(r.nameServers) ? r.nameServers.map((ns) => ns.toUpperCase()) : [],
    registrantOrganization: str(r.registrantOrganization || r.registrantOrganizationEn),
    registrantProvince: str(r.registrantProvince),
    registrantCountry: str(r.registrantCountry),
    registrantPhone: str(r.registrantPhone),
    registrantEmail: str(r.registrantEmail),
    dnssec: r.dnssec ? r.dnssec.toLowerCase() : "unsigned",
    rawWhoisContent: r.rawWhoisContent || "",
    domainAge: typeof r.domainAge === "number" ? r.domainAge : null,
    remainingDays: typeof r.remainingDays === "number" ? r.remainingDays : null,
    registerPrice: null,
    renewPrice: null,
    negotiable: null,
  };
}

/**
 * Try fetching from yisi.yun. Returns a WhoisResult if data is usable,
 * or null so the caller can fall back to the DNS probe error page.
 */
export async function lookupYisi(domain: string): Promise<WhoisResult | null> {
  const { getApiConfig } = await import("@/lib/api-config");
  const cfg = await getApiConfig();
  if (!cfg.yisi_enabled || !cfg.yisi_key) return null;
  const apiKey = cfg.yisi_key;

  try {
    const url = `${YISI_API}?query=${encodeURIComponent(domain)}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), YISI_TIMEOUT);

    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        "x-api-key": apiKey,
      },
    }).finally(() => clearTimeout(timer));

    if (!res.ok) return null;

    const json: YisiResponse = await res.json();
    if (!json.status || !json.result) return null;

    if (!hasUsableData(json.result)) return null;

    return {
      time: json.time ?? 0,
      status: true,
      cached: json.cached ?? false,
      source: "YISI.YUN",
      result: toAnalyzeResult(json.result, domain),
    };
  } catch {
    return null;
  }
}
