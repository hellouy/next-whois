/**
 * Third-party WHOIS API adapters.
 * Converts tianhu / yisi responses into a normalised WhoisResult so they
 * can be returned from the main lookup flow transparently.
 */
import { WhoisResult, WhoisAnalyzeResult, initialWhoisAnalyzeResult } from "./types";
import { many } from "@/lib/db-query";
import { analyzeWhois } from "./common_parser";
import { lookupNicPh } from "./http-scrapers/nic-ph";
import { lookupNicTt } from "./http-scrapers/nic-tt";
import { lookupNicGm } from "./http-scrapers/nic-gm";
import { lookupNicBb } from "./http-scrapers/nic-bb";

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

  const statuses: string[] = (() => {
    const raw = Array.isArray(domainInfo.status)
      ? domainInfo.status
      : typeof domainInfo.status === "string" ? [domainInfo.status] : [];
    return raw.map((s: unknown): string => {
      if (typeof s === "string") return s;
      if (s && typeof s === "object") {
        const o = s as Record<string, unknown>;
        if (typeof o.code === "string") return o.code;
        if (typeof o.status === "string") return o.status;
        if (typeof o.name === "string") return o.name;
      }
      return "";
    }).filter((s: string) => s.length > 0);
  })();

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

  // YISI.YUN returns j.result with camelCase field names
  const d = j.result ?? {};

  // If the domain was not found, return a definitive "not found" result
  // so the UI shows "未注册" rather than a registered card with all-Unknown fields.
  if (d.domainNotFound === true || d.domainReserved === false && d.registrar === "Unknown" && !d.creationDate) {
    const raw = typeof d.rawWhoisContent === "string" ? d.rawWhoisContent : JSON.stringify(d, null, 2);
    return {
      status: false,
      time: (Date.now() - start) / 1000,
      error: "Domain not found",
      source: "YISI.YUN",
      result: {
        ...initialWhoisAnalyzeResult,
        domain,
        rawWhoisContent: raw,
        registerPrice: d.registerPrice ?? null,
        renewPrice: d.renewPrice ?? null,
        negotiable: null,
        cidr: "", inetNum: "", inet6Num: "", netRange: "", netName: "", netType: "", originAS: "",
      } as WhoisAnalyzeResult,
    };
  }

  // YISI.YUN uses camelCase field names directly in j.result
  const expirationDate = d.expirationDate ?? "Unknown";
  const creationDate   = d.creationDate   ?? "Unknown";

  const statuses: string[] = (() => {
    const rawStatus = Array.isArray(d.status)
      ? d.status
      : typeof d.status === "string" ? [d.status] : [];
    return rawStatus.map((s: unknown): string => {
      if (typeof s === "string") return s;
      if (s && typeof s === "object") {
        const o = s as Record<string, unknown>;
        if (typeof o.code === "string") return o.code;
        if (typeof o.status === "string") return o.status;
        if (typeof o.name === "string") return o.name;
      }
      return "";
    }).filter((s: string) => s.length > 0);
  })();

  // nameServers: YISI returns an array of strings
  const nameServers: string[] = Array.isArray(d.nameServers)
    ? d.nameServers.map((ns: unknown) => (typeof ns === "string" ? ns : String(ns)))
    : [];

  // rawWhoisContent: prefer the dedicated field, fall back to serialised result
  const raw = typeof d.rawWhoisContent === "string" && d.rawWhoisContent.trim().length > 0
    ? d.rawWhoisContent
    : JSON.stringify(d, null, 2);

  const result: WhoisAnalyzeResult = {
    ...initialWhoisAnalyzeResult,
    domain,
    registrar:       d.registrar              ?? "Unknown",
    registrarURL:    d.registrarURL            ?? "Unknown",
    ianaId:          d.ianaId                 ?? "N/A",
    whoisServer:     d.whoisServer             ?? "yisi.yun",
    updatedDate:     d.updatedDate             ?? "Unknown",
    creationDate,
    expirationDate,
    nameServers,
    status:          statuses.map(s => ({ status: s, url: "" })),
    registrantOrganization: d.registrantOrganization ?? "Unknown",
    registrantCountry:      d.registrantCountry      ?? "Unknown",
    registrantProvince:     d.registrantProvince     ?? "Unknown",
    registrantCity:         d.registrantCity         ?? "Unknown",
    registrantPhone:        d.registrantPhone        ?? "Unknown",
    registrantEmail:        d.registrantEmail        ?? "Unknown",
    registrantName:         d.registrantName         ?? "Unknown",
    dnssec:          d.dnssec                 ?? "Unknown",
    rawWhoisContent: raw,
    remainingDays:   expirationDate !== "Unknown" ? remainingDays(expirationDate) : null,
    domainAge:       creationDate   !== "Unknown" ? domainAge(creationDate)       : null,
    registerPrice:   d.registerPrice ?? null,
    renewPrice:      d.renewPrice    ?? null,
    negotiable: null,
    cidr: d.cidr ?? "", inetNum: d.inetNum ?? "", inet6Num: d.inet6Num ?? "",
    netRange: d.netRange ?? "", netName: d.netName ?? "", netType: d.netType ?? "",
    originAS: d.originAS ?? "",
    registryDomainId: "Unknown",
    registrantAddress: "Unknown", registrantPostalCode: "Unknown",
    registrantFax: "Unknown",
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

// ── ph_web adapter (NIC.PH web scraper — whois.dot.ph) ─────────────────────────

async function lookupViaPhWeb(domain: string): Promise<WhoisResult> {
  const start = Date.now();
  const r = await lookupNicPh(domain);
  const elapsed = (Date.now() - start) / 1000;

  if (!r.success) {
    // "Domain not found or not registered" → forward as definitive not-found
    if (!r.blocked && r.reason.toLowerCase().includes("not found")) {
      return {
        status: false,
        time: elapsed,
        error: "Domain not found",
        source: "whois.ph",
      };
    }
    return {
      status: false,
      time: elapsed,
      error: r.blocked
        ? "whois.dot.ph 需要人机验证，无法自动查询"
        : `NIC.PH 查询失败: ${r.reason}`,
      source: "whois.ph",
    };
  }

  const expirationDate = r.expiresDate || "Unknown";
  const creationDate   = r.createdDate || "Unknown";

  const domainResult: WhoisAnalyzeResult = {
    ...initialWhoisAnalyzeResult,
    domain,
    registrar:              r.registrar              || "Unknown",
    registrarURL:           "https://whois.dot.ph/",
    ianaId:                 "N/A",
    whoisServer:            "whois.dot.ph",
    updatedDate:            r.updatedDate            || "Unknown",
    creationDate,
    expirationDate,
    nameServers:            r.nameservers,
    // status is now string[] — map each to the {status, url} shape
    status:                 r.status.length > 0
                              ? r.status.map(s => ({ status: s, url: "" }))
                              : [{ status: "Active", url: "" }],
    registrantName:         r.registrant             || "Unknown",
    registrantOrganization: r.registrantOrg          || "Unknown",
    registrantCountry:      "PH",
    registrantEmail:        "Unknown",
    dnssec:                 "Unknown",
    rawWhoisContent:        r.rawWhoisContent,
    remainingDays: expirationDate !== "Unknown" ? (() => {
      try { return Math.round((new Date(expirationDate).getTime() - Date.now()) / 86_400_000); } catch { return null; }
    })() : null,
    domainAge: creationDate !== "Unknown" ? (() => {
      try { return Math.round((Date.now() - new Date(creationDate).getTime()) / 86_400_000); } catch { return null; }
    })() : null,
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
    time: elapsed,
    source: "whois.ph",
    result: domainResult,
  };
}

// ── tt_web adapter (TTNIC web scraper — nic.tt) ────────────────────────────────

async function lookupViaTtWeb(domain: string): Promise<WhoisResult> {
  const start = Date.now();
  const r = await lookupNicTt(domain);
  const elapsed = (Date.now() - start) / 1000;

  if (!r.success) {
    // "Domain not found or not registered" → forward as definitive not-found
    if (!r.blocked && r.reason.toLowerCase().includes("not found")) {
      return {
        status: false,
        time: elapsed,
        error: "Domain not found",
        source: "whois.nic.tt",
      };
    }
    return {
      status: false,
      time: elapsed,
      error: r.blocked
        ? "nic.tt 需要人机验证，无法自动查询"
        : `TTNIC 查询失败: ${r.reason}`,
      source: "whois.nic.tt",
    };
  }

  const expirationDate = r.expiresDate || "Unknown";
  const creationDate   = r.createdDate || "Unknown";

  const domainResult: WhoisAnalyzeResult = {
    ...initialWhoisAnalyzeResult,
    domain,
    registrar:              "TTNIC — Trinidad and Tobago Network Information Centre",
    registrarURL:           "https://www.nic.tt/cgi-bin/search.pl",
    ianaId:                 "N/A",
    whoisServer:            "whois.nic.tt",
    updatedDate:            "Unknown",
    creationDate,
    expirationDate,
    nameServers:            r.nameservers,
    status:                 [{ status: "Active", url: "" }],
    registrantName:         r.registrant || "Unknown",
    registrantOrganization: "Unknown",
    registrantCountry:      "TT",
    registrantEmail:        "Unknown",
    dnssec:                 "Unknown",
    rawWhoisContent:        r.rawWhoisContent,
    remainingDays: expirationDate !== "Unknown" ? (() => {
      try { return Math.round((new Date(expirationDate).getTime() - Date.now()) / 86_400_000); } catch { return null; }
    })() : null,
    domainAge: creationDate !== "Unknown" ? (() => {
      try { return Math.round((Date.now() - new Date(creationDate).getTime()) / 86_400_000); } catch { return null; }
    })() : null,
    registerPrice: null, renewPrice: null, negotiable: null,
    cidr: "", inetNum: "", inet6Num: "", netRange: "", netName: "", netType: "", originAS: "",
    registryDomainId: "Unknown",
    registrantProvince: "Unknown", registrantCity: "Unknown",
    registrantAddress: r.registrantAddress || "Unknown", registrantPostalCode: "Unknown",
    registrantPhone: "Unknown", registrantFax: "Unknown",
    adminName: "Unknown", adminOrganization: "Unknown",
    adminCountry: "Unknown", adminEmail: "Unknown", adminPhone: "Unknown",
    techName: "Unknown", techOrganization: "Unknown",
    techEmail: "Unknown", techPhone: "Unknown",
    abuseEmail: "Unknown", abusePhone: "Unknown",
  };

  return {
    status: true,
    time: elapsed,
    source: "whois.nic.tt",
    result: domainResult,
  };
}

// ── gm_web adapter (GM-NIC web scraper — nic.gm) ──────────────────────────────

async function lookupViaGmWeb(domain: string): Promise<WhoisResult> {
  const start = Date.now();
  const r = await lookupNicGm(domain);
  const elapsed = (Date.now() - start) / 1000;

  if (!r.success) {
    // "Domain not found or not registered" → forward as definitive not-found
    if (!r.blocked && r.reason.toLowerCase().includes("not found")) {
      return {
        status: false,
        time: elapsed,
        error: "Domain not found",
        source: "whois.nic.gm",
      };
    }
    return {
      status: false,
      time: elapsed,
      error: r.blocked
        ? "nic.gm 暂时无法访问，无法自动查询"
        : `GM-NIC 查询失败: ${r.reason}`,
      source: "whois.nic.gm",
    };
  }

  const registrationDate = r.registrationDate || "Unknown";
  const domainResult: WhoisAnalyzeResult = {
    ...initialWhoisAnalyzeResult,
    domain,
    registrar:              r.reserved ? "Unknown" : "GM-NIC (CYPDOM) — Gambia ccTLD Registry",
    registrarURL:           "https://www.nic.gm/NIC2/search.html",
    ianaId:                 "N/A",
    whoisServer:            "whois.nic.gm",
    updatedDate:            "Unknown",
    creationDate:           registrationDate,
    expirationDate:         "Unknown",
    nameServers:            r.nameservers,
    status:                 r.reserved
      ? [{ status: "registry-reserved", url: "" }]
      : [{ status: "Active", url: "" }],
    registrantName:         "Unknown",
    registrantOrganization: "Unknown",
    registrantCountry:      "GM",
    registrantEmail:        "Unknown",
    dnssec:                 "Unknown",
    rawWhoisContent:        r.rawWhoisContent,
    remainingDays: null,
    domainAge: registrationDate !== "Unknown" ? (() => {
      try { return Math.round((Date.now() - new Date(registrationDate).getTime()) / 86_400_000); } catch { return null; }
    })() : null,
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
    time: elapsed,
    source: "whois.nic.gm",
    result: domainResult,
  };
}

// ── bb_web adapter (BB registry web WHOIS — whois.telecoms.gov.bb) ─────────────

async function lookupViaBbWeb(domain: string): Promise<WhoisResult> {
  const start = Date.now();
  const r = await lookupNicBb(domain);
  const elapsed = (Date.now() - start) / 1000;

  if (!r.success) {
    if (!r.blocked && r.reason.toLowerCase().includes("not found")) {
      return {
        status: false,
        time: elapsed,
        error: "Domain not found",
        source: "whois.telecoms.gov.bb",
      };
    }
    return {
      status: false,
      time: elapsed,
      error: r.blocked
        ? "bb WHOIS 暂时无法访问，无法自动查询"
        : `BB 注册局查询失败: ${r.reason}`,
      source: "whois.telecoms.gov.bb",
    };
  }

  // The <pre> block is standard WHOIS text — run it through the generic parser
  // so registrar/dates/nameservers/statuses are structured exactly like a TCP
  // WHOIS response.
  let parsed: WhoisAnalyzeResult;
  try {
    parsed = await analyzeWhois(r.rawWhoisContent);
  } catch {
    parsed = { ...initialWhoisAnalyzeResult };
  }
  const result: WhoisAnalyzeResult = {
    ...parsed,
    domain,
    whoisServer: "whois.telecoms.gov.bb",
    registrar: parsed.registrar || "Unknown",
    registrarURL: "https://www.telecoms.gov.bb",
    rawWhoisContent: r.rawWhoisContent,
    registrantCountry: parsed.registrantCountry === "Unknown" ? "BB" : parsed.registrantCountry,
  };

  return { status: true, time: elapsed, source: "whois.telecoms.gov.bb", result };
}

// ── Public entry point ─────────────────────────────────────────────────────────

export type ThirdPartyApiSource = "tianhu" | "yisi" | "ph_web" | "tt_web" | "gm_web" | "bb_web";

export async function lookupViaThirdPartyApi(
  domain: string,
  source: ThirdPartyApiSource,
): Promise<WhoisResult> {
  if (source === "tianhu")  return lookupViaTianhu(domain);
  if (source === "yisi")    return lookupViaYisi(domain);
  if (source === "ph_web")  return lookupViaPhWeb(domain);
  if (source === "tt_web")  return lookupViaTtWeb(domain);
  if (source === "gm_web")  return lookupViaGmWeb(domain);
  if (source === "bb_web")  return lookupViaBbWeb(domain);
  return { status: false, time: 0, error: `未知 API 源: ${source}` };
}
