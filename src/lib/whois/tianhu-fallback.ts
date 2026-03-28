/**
 * Fallback WHOIS lookup via tian.hu public API (free, no auth required).
 * Called before yisi.yun when native RDAP + WHOIS produce no usable result.
 *
 * Endpoint: GET https://api.tian.hu/whois/{domain}
 * Rate limit: 25/min, 300/day (shared across all callers)
 */

import {
  WhoisResult,
  WhoisAnalyzeResult,
  DomainStatusProps,
  initialWhoisAnalyzeResult,
} from "@/lib/whois/types";

const TIANHU_API = "https://api.tian.hu/whois";
const TIANHU_TIMEOUT = 4_000;

interface TianhuDomain {
  name_servers?: string[];
  status?: string[];
  domain?: string;
  id?: string;
  whois_server?: string;
  updated_date?: string;
  created_date?: string;
  expired_date?: string;
  dnssec?: boolean;
}

interface TianhuRegistrar {
  registrar_name?: string;
  referral_url?: string;
  registrar_ianaid?: string;
  registrar_email?: string;
  registrar_phone?: string;
}

interface TianhuFormatted {
  domain?: TianhuDomain;
  registrar?: TianhuRegistrar;
  registrant?: Record<string, string>;
  technical?: Record<string, string>;
  billing?: Record<string, string>;
}

interface TianhuData {
  domain: string;
  tld: string;
  status: number;
  rdap: boolean;
  result?: string;
  formatted?: TianhuFormatted;
  tags?: Array<{ color: string; desc: string; group: string; link?: string }>;
}

interface TianhuResponse {
  code: number;
  message: string;
  data?: TianhuData;
}

function str(v: string | null | undefined, fallback = "Unknown"): string {
  if (!v || v.trim() === "" || v.trim().toLowerCase() === "unknown")
    return fallback;
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

function stripHtml(html: string): string {
  return html
    .replace(/<a[^>]*>/gi, "")
    .replace(/<\/a>/gi, "")
    .replace(/<b>/gi, "")
    .replace(/<\/b>/gi, "")
    .replace(/<[^>]+>/g, "")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"');
}

function calcAge(createdIso: string | undefined): number | null {
  if (!createdIso) return null;
  try {
    const ms = Date.now() - new Date(createdIso).getTime();
    return Math.floor(ms / (1000 * 60 * 60 * 24 * 365));
  } catch {
    return null;
  }
}

function calcRemaining(expiredIso: string | undefined): number | null {
  if (!expiredIso) return null;
  try {
    const ms = new Date(expiredIso).getTime() - Date.now();
    return Math.max(0, Math.floor(ms / (1000 * 60 * 60 * 24)));
  } catch {
    return null;
  }
}

function hasUsableData(data: TianhuData): boolean {
  if (data.status !== 1) return false;
  const d = data.formatted?.domain;
  const r = data.formatted?.registrar;
  return (
    Boolean(r?.registrar_name) ||
    Boolean(d?.expired_date) ||
    Boolean(d?.created_date) ||
    (Array.isArray(d?.name_servers) && (d!.name_servers!.length ?? 0) > 0)
  );
}

function toAnalyzeResult(data: TianhuData, domain: string): WhoisAnalyzeResult {
  const d = data.formatted?.domain ?? {};
  const r = data.formatted?.registrar ?? {};

  const statuses: DomainStatusProps[] = Array.isArray(d.status)
    ? d.status.map((s) => ({
        status: s,
        url: `https://icann.org/epp#${s}`,
      }))
    : [];

  const nameServers = Array.isArray(d.name_servers)
    ? d.name_servers.map((ns) => ns.toUpperCase())
    : [];

  const rawText = data.result ? stripHtml(data.result) : "";

  return {
    ...initialWhoisAnalyzeResult,
    domain: data.domain || domain,
    registrar: str(r.registrar_name),
    registrarURL: str(r.referral_url),
    ianaId: str(r.registrar_ianaid, "N/A"),
    whoisServer: str(d.whois_server),
    creationDate: formatDate(d.created_date),
    expirationDate: formatDate(d.expired_date),
    updatedDate: formatDate(d.updated_date),
    status: statuses,
    nameServers,
    registrantOrganization:
      str(data.formatted?.registrant?.organization) ||
      str(data.formatted?.registrant?.name),
    registrantCountry: str(data.formatted?.registrant?.country),
    registrantProvince: str(data.formatted?.registrant?.province),
    registrantPhone: str(data.formatted?.registrant?.phone),
    registrantEmail: str(data.formatted?.registrant?.email),
    dnssec: d.dnssec ? "signed" : "unsigned",
    rawWhoisContent: rawText,
    domainAge: calcAge(d.created_date),
    remainingDays: calcRemaining(d.expired_date),
    registerPrice: null,
    renewPrice: null,
    negotiable: null,
  };
}

/**
 * Try fetching WHOIS from tian.hu. Returns a WhoisResult if data is usable,
 * or null so the caller can try the next fallback.
 */
export async function lookupTianhu(
  domain: string,
): Promise<WhoisResult | null> {
  const { getApiConfig } = await import("@/lib/api-config");
  const cfg = await getApiConfig();
  if (!cfg.tianhu_enabled) return null;

  try {
    const url = `${TIANHU_API}/${encodeURIComponent(domain)}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIANHU_TIMEOUT);

    const res = await fetch(url, {
      signal: controller.signal,
      headers: { Accept: "application/json" },
    }).finally(() => clearTimeout(timer));

    if (!res.ok) return null;

    const json: TianhuResponse = await res.json();
    if (json.code !== 200 || !json.data) return null;
    if (!hasUsableData(json.data)) return null;

    return {
      time: 0,
      status: true,
      cached: false,
      source: "tian.hu",
      result: toAnalyzeResult(json.data, domain),
    };
  } catch {
    return null;
  }
}
