import { MAX_WHOIS_FOLLOW, LOOKUP_TIMEOUT } from "@/lib/env";
function intEnv(name: string, def: number): number {
  const v = typeof process !== "undefined" ? process.env[name] : undefined;
  const n = v ? parseInt(v, 10) : NaN;
  return isNaN(n) ? def : n;
}
import { WhoisResult, WhoisAnalyzeResult, initialWhoisAnalyzeResult } from "@/lib/whois/types";
import {
  getJsonRedisValueWithTtl,
  setJsonRedisValue,
  isRedisAvailable,
  getRemainingTtl,
} from "@/lib/server/redis";

const L1_TTL_MS = 30_000;
const L1_MAX = 500;
type MemEntry = { value: WhoisResult; expiresAt: number };
const _memCache = new Map<string, MemEntry>();
function l1Get(key: string): WhoisResult | null {
  const entry = _memCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) { _memCache.delete(key); return null; }
  return entry.value;
}
function l1Set(key: string, value: WhoisResult) {
  if (_memCache.size >= L1_MAX) {
    const oldest = _memCache.keys().next().value;
    if (oldest) _memCache.delete(oldest);
  }
  _memCache.set(key, { value, expiresAt: Date.now() + L1_TTL_MS });
}

/**
 * Evicts all L1 in-memory lookup results whose domain ends with `.{tld}`.
 * Called by the admin server-save/delete flow so the next query hits the
 * freshly configured server rather than returning a stale cached result.
 * Returns the number of entries evicted.
 */
export function invalidateLookupCacheForTld(tld: string): number {
  const suffix = `.${tld.toLowerCase().replace(/^\./, "")}`;
  let count = 0;
  for (const key of [..._memCache.keys()]) {
    const domain = key.startsWith("whois:") ? key.slice(6) : key;
    if (domain === tld || domain.endsWith(suffix)) {
      _memCache.delete(key);
      count++;
    }
  }
  return count;
}
import { analyzeWhois } from "@/lib/whois/common_parser";
import { extractDomain } from "@/lib/utils";
import { lookupRdap, convertRdapToWhoisResult, RDAP_DIRECT_CCTLDS } from "@/lib/whois/rdap_client";
let _whoiserPromise: Promise<typeof import("whoiser")> | null = null;
const getWhoiser = () => {
  if (!_whoiserPromise) _whoiserPromise = import("whoiser");
  return _whoiserPromise;
};
void getWhoiser();
import("@/lib/whois/custom-servers").then(m => m.getAllCustomServers()).catch(() => {});
warmupDnsCache([
  "whois.verisign-grs.com",
  "whois.pir.org",
  "whois.iana.org",
  "whois.afilias.net",
  "whois.nic.fr",
  "whois.denic.de",
  "whois.cnnic.cn",
  "whois.nic.uk",
  "whois.apnic.net",
  "whois.arin.net",
  "whois.ripe.net",
  "whois.lacnic.net",
  "whois.afrinic.net",
]);
import { domainToASCII } from "url";
import {
  getCustomServerEntry,
  isTldKnownNoServer,
  isHttpEntry,
  isScraperEntry,
  getTcpHost,
  isUserManagedServer,
  setDiscoveredServer,
  HttpServerEntry,
} from "@/lib/whois/custom-servers";
import { probeDomain } from "@/lib/whois/dns-check";
import { warmupDnsCache } from "@/lib/whois/dns-resolver";
import { lookupNicBa } from "@/lib/whois/http-scrapers/nic-ba";
import { getCnReservedSldInfo } from "@/lib/whois/cn-reserved-sld";
import { getGtldWhoisServer } from "@/lib/whois/whois_gtld_bootstrap";

class ScraperRequiredError extends Error {
  registryUrl: string;
  blocked: boolean;
  constructor(message: string, registryUrl: string, blocked = false) {
    super(message);
    this.name = "ScraperRequiredError";
    this.registryUrl = registryUrl;
    this.blocked = blocked;
  }
}

const WHOIS_ERROR_PATTERNS = [
  /no match/i,
  /not found/i,
  /no data found/i,
  /no entries found/i,
  /no object found/i,
  /nothing found/i,
  /invalid query/i,
  /^error:/im,
  /malformed/i,
  /object does not exist/i,
  /domain not found/i,
  /status:\s*free/i,
  /status:\s*available/i,
  /is available for/i,
  /no whois information/i,
  /tld is not supported/i,
];

const WHOIS_RATE_LIMIT_PATTERNS = [
  /rate.?limit/i,
  /too many (?:requests|queries)/i,
  /query.?rate.*exceeded/i,
  /exceeded.*query.?limit/i,
  /access denied/i,
  /connection refused/i,
  /temporarily.?blocked/i,
  /please.{0,20}try again later/i,
];

function isWhoisRateLimited(raw: string): boolean {
  return WHOIS_RATE_LIMIT_PATTERNS.some((p) => p.test(raw));
}

const WHOIS_NOT_REGISTERED_PATTERNS = [
  /no match/i,
  /not found/i,
  /no data found/i,
  /no entries found/i,
  /no object found/i,
  /nothing found/i,
  /object does not exist/i,
  /domain not found/i,
  /status:\s*free/i,
  /status:\s*available/i,
  /is available for/i,
];

function isNotRegisteredWhoisResponse(whoisError: string): boolean {
  return WHOIS_NOT_REGISTERED_PATTERNS.some((p) => p.test(whoisError));
}

function toAsciiDomain(domain: string): string {
  if (!/[^\x00-\x7F]/.test(domain)) return domain;
  try {
    const ascii = domainToASCII(domain.toLowerCase());
    if (ascii && ascii !== domain.toLowerCase() && !ascii.includes("\u0000")) {
      return ascii;
    }
  } catch {}
  return domain;
}

function isIanaFallback(raw: string): boolean {
  return raw.includes("% IANA WHOIS server");
}

function detectWhoisError(raw: string): string | null {
  const lines = raw
    .split("\n")
    .map((l) => l.trim())
    .filter(
      (l) =>
        l.length > 0 &&
        !l.startsWith("%") &&
        !l.startsWith("#") &&
        !l.startsWith(">>>") &&
        !l.startsWith("NOTICE") &&
        !l.startsWith("TERMS OF USE"),
    );
  if (lines.length === 0) return "Empty WHOIS response";

  for (const pattern of WHOIS_ERROR_PATTERNS) {
    const match = raw.match(pattern);
    if (match) {
      const matchLine = raw.split("\n").find((l) => pattern.test(l));
      return matchLine?.trim() || match[0];
    }
  }
  return null;
}

function isEmptyResult(result: {
  domain: string;
  registrar: string;
  creationDate: string;
  expirationDate: string;
  nameServers: string[];
  cidr: string;
  netRange: string;
  netName: string;
  originAS: string;
  inetNum: string;
  inet6Num: string;
}): boolean {
  const hasIpData =
    (result.cidr && result.cidr !== "Unknown") ||
    (result.netRange && result.netRange !== "Unknown") ||
    (result.netName && result.netName !== "Unknown") ||
    (result.originAS && result.originAS !== "Unknown") ||
    (result.inetNum && result.inetNum !== "Unknown") ||
    (result.inet6Num && result.inet6Num !== "Unknown");
  if (hasIpData) return false;

  return (
    (!result.domain || result.domain === "") &&
    result.registrar === "Unknown" &&
    result.creationDate === "Unknown" &&
    result.expirationDate === "Unknown" &&
    result.nameServers.length === 0
  );
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Timeout")), ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

interface WhoisRawResult {
  raw: string;
  structured: Record<string, any>;
  server?: string;
  registryUrl?: string;
}

function isIPAddress(query: string): boolean {
  const bare = query.replace(/\/\d{1,3}$/, "");
  return (
    /^(\d{1,3}\.){3}\d{1,3}$/.test(bare) ||
    /^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/.test(bare)
  );
}

function isASNumber(query: string): boolean {
  return /^AS\d+$/i.test(query);
}

async function queryWhoisTcp(
  host: string,
  port: number,
  query: string,
  timeoutMs: number,
): Promise<string> {
  const { resolveWithDohFallback } = await import("./dns-resolver");
  let resolvedHost = host;
  try {
    resolvedHost = await resolveWithDohFallback(host);
  } catch {}

  return new Promise((resolve, reject) => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const net = require("node:net") as typeof import("net");
    let data = "";
    const socket = net.connect({ host: resolvedHost, port }, () =>
      socket.write(query + "\r\n"),
    );
    socket.setTimeout(timeoutMs);
    socket.on("data", (chunk: Buffer) => (data += chunk.toString()));
    socket.on("close", () => resolve(data));
    socket.on("timeout", () => socket.destroy(new Error("TCP WHOIS timeout")));
    socket.on("error", reject);
  });
}

function stripHtmlToWhoisText(html: string): string {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, "")
    .replace(/<style[\s\S]*?<\/style>/gi, "")
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(?:tr|p|div|li|h[1-6]|pre)>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/[ \t]+/g, " ")
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0)
    .join("\n");
}

async function queryWhoisHttp(
  entry: HttpServerEntry,
  domain: string,
  timeoutMs: number,
): Promise<string> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const placeholder = (s: string) => s.replace(/\{\{domain\}\}/g, domain);
  const url = placeholder(entry.url);
  const method = entry.method || "GET";

  try {
    const init: RequestInit = {
      method,
      signal: controller.signal,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (compatible; next-whois-ui/1.0; +https://github.com/zmh-program/next-whois-ui)",
        Accept: "text/plain, text/html, */*",
      },
    };
    if (method === "POST") {
      init.body = entry.body ? placeholder(entry.body) : domain;
      (init.headers as Record<string, string>)["Content-Type"] =
        "application/x-www-form-urlencoded";
    }
    const res = await fetch(url, init);
    if (!res.ok) {
      throw new Error(`HTTP WHOIS server returned ${res.status}`);
    }
    const contentType = res.headers.get("content-type") || "";
    const text = await res.text();
    if (contentType.includes("text/html") || text.trimStart().startsWith("<!")) {
      return stripHtmlToWhoisText(text);
    }
    return text;
  } finally {
    clearTimeout(timer);
  }
}

const _ianaServerCache = new Map<string, { server: string | null; expires: number }>();
const IANA_CACHE_MAX = 2000;

async function getIanaWhoisServer(tld: string): Promise<string | null> {
  const now = Date.now();
  const cached = _ianaServerCache.get(tld);
  if (cached && cached.expires > now) return cached.server;
  try {
    const raw = await queryWhoisTcp("whois.iana.org", 43, tld, 5_000);
    const m = raw.match(/^refer:\s*(\S+)/im);
    const server = m ? m[1].trim().toLowerCase() : null;
    if (_ianaServerCache.size >= IANA_CACHE_MAX && !_ianaServerCache.has(tld)) {
      const oldest = _ianaServerCache.keys().next().value;
      if (oldest !== undefined) _ianaServerCache.delete(oldest);
    }
    _ianaServerCache.set(tld, { server, expires: now + 86_400_000 });
    if (server) {
      setDiscoveredServer(tld, server, "iana").catch(() => {});
    }
    return server;
  } catch {
    return null;
  }
}

async function getLookupWhois(domain: string): Promise<WhoisRawResult> {
  if (isIPAddress(domain)) {
    const ip = domain.replace(/\/\d{1,3}$/, "");
    const { whoisIp } = await getWhoiser();
    const data = await whoisIp(ip, { timeout: LOOKUP_TIMEOUT });
    return {
      raw: (data as any).__raw || "",
      structured: data as any,
      server: "ip-whois",
    };
  }

  if (isASNumber(domain)) {
    const asNum = parseInt(domain.replace(/^AS/i, ""));
    const { whoisAsn } = await getWhoiser();
    const data = await whoisAsn(asNum, { timeout: LOOKUP_TIMEOUT });
    return {
      raw: (data as any).__raw || "",
      structured: data as any,
      server: "asn-whois",
    };
  }

  const rawExtracted = extractDomain(domain) || domain;
  const domainToQuery = toAsciiDomain(rawExtracted);
  const follow = Math.min(Math.max(MAX_WHOIS_FOLLOW, 1), 2) as 1 | 2;
  const innerTimeout = Math.min(LOOKUP_TIMEOUT, WHOIS_TIMEOUT - 300);
  const tld = domainToQuery.split(".").slice(1).join(".");
  const tldSuffix = domainToQuery.split(".").pop() || "";
  let customEntry: Awaited<ReturnType<typeof getCustomServerEntry>>;
  let isUserServer: boolean;
  if (tld === tldSuffix) {
    const [ce, us] = await Promise.all([getCustomServerEntry(tld), isUserManagedServer(tld)]);
    customEntry = ce;
    isUserServer = us;
  } else {
    const [[ce1, ce2], [us1, us2]] = await Promise.all([
      Promise.all([getCustomServerEntry(tld), getCustomServerEntry(tldSuffix)]),
      Promise.all([isUserManagedServer(tld), isUserManagedServer(tldSuffix)]),
    ]);
    customEntry = ce1 || ce2;
    isUserServer = us1 || us2;
  }

  if (customEntry) {
    if (isScraperEntry(customEntry)) {
      const { name: scraperName, registryUrl } = customEntry;
      if (scraperName === "nic-ba") {
        const nicBaResult = await lookupNicBa(domainToQuery, innerTimeout);
        if (nicBaResult.success) {
          return {
            raw: nicBaResult.raw,
            structured: {},
            server: "nic.ba",
            registryUrl,
          };
        }
        const nicBaFail = nicBaResult as { success: false; blocked: boolean; reason: string };
        throw new ScraperRequiredError(
          nicBaFail.blocked
            ? "nic.ba requires CAPTCHA verification — automated WHOIS lookup is not available for .ba domains"
            : `nic.ba scraper error: ${nicBaFail.reason}`,
          registryUrl,
          nicBaFail.blocked,
        );
      }
      throw new ScraperRequiredError(
        `No scraper implementation for "${scraperName}"`,
        registryUrl,
      );
    } else if (isHttpEntry(customEntry)) {
      const raw = await queryWhoisHttp(customEntry, domainToQuery, innerTimeout);
      if (!raw || raw.trim().length === 0) {
        if (isUserServer) {
          throw new Error(`No data returned from HTTP WHOIS server: ${customEntry.url}`);
        }
      } else {
        if (isUserServer && isWhoisRateLimited(raw)) {
          throw new Error(`Custom WHOIS server ${customEntry.url} is rate-limiting requests — please try again later`);
        }
        return { raw, structured: {}, server: customEntry.url };
      }
    } else {
      const tcpHost = getTcpHost(customEntry);
      if (tcpHost) {
        const port =
          typeof customEntry === "object" &&
          "port" in customEntry &&
          customEntry.port
            ? customEntry.port
            : 43;
        try {
          const { whoisQuery } = await getWhoiser();
          const raw =
            port === 43
              ? await whoisQuery(tcpHost, domainToQuery, innerTimeout)
              : await queryWhoisTcp(tcpHost, port, domainToQuery, innerTimeout);
          if (raw && raw.trim().length > 0) {
            if (isUserServer && isWhoisRateLimited(raw)) {
              throw new Error(`Custom WHOIS server ${tcpHost} is rate-limiting requests — please try again later`);
            }
            return { raw, structured: {}, server: tcpHost };
          }
          if (isUserServer) {
            throw new Error(`No data returned from custom WHOIS server: ${tcpHost}`);
          }
        } catch (tcpErr) {
          if (isUserServer) throw tcpErr;
        }
      }
    }
  }

  if (await isTldKnownNoServer(tld || tldSuffix)) {
    throw new Error(`No public WHOIS server available for .${tld || tldSuffix} domains`);
  }

  const bootstrapWhoisHost = getGtldWhoisServer(tld) ?? getGtldWhoisServer(tldSuffix);

  let primaryError: unknown = null;

  if (bootstrapWhoisHost) {
    try {
      const raw = await queryWhoisTcp(bootstrapWhoisHost, 43, domainToQuery, innerTimeout);
      if (raw && raw.trim().length > 0 && !isIanaFallback(raw)) {
        return { raw, structured: {}, server: bootstrapWhoisHost };
      }
    } catch (err) {
      primaryError = err;
    }
  }

  {
    const { whoisDomain } = await getWhoiser();

    function extractRawFromData(data: any): WhoisRawResult | null {
      const servers = Object.keys(data ?? {});
      if (servers.length === 0) return null;
      const lastServer = servers[servers.length - 1];
      const structured = (data as any)[lastServer] || {};
      const rawParts: string[] = [];
      for (const s of servers) {
        const entry = (data as any)[s];
        if (entry?.__raw) {
          rawParts.push(entry.__raw);
        } else if (entry) {
          const lines: string[] = [];
          for (const [k, v] of Object.entries(entry)) {
            if (k === "text" || k === "__raw" || k === "__comments") continue;
            if (Array.isArray(v)) {
              for (const item of v) lines.push(`${k}: ${item}`);
            } else if (v !== undefined && v !== null && v !== "") {
              lines.push(`${k}: ${v}`);
            }
          }
          if (lines.length > 0) rawParts.push(lines.join("\n"));
        }
      }
      const raw = rawParts.join("\n\n") || "";
      return { raw, structured, server: lastServer };
    }

    try {
      const data = await whoisDomain(domainToQuery, {
        raw: true,
        follow,
        timeout: innerTimeout,
      });
      const result = extractRawFromData(data);
      if (result && result.raw.trim().length > 0) return result;
    } catch (err) {
      if (!primaryError) primaryError = err;
    }
  }

  const ianaServer = await getIanaWhoisServer(tldSuffix);
  if (ianaServer && ianaServer !== bootstrapWhoisHost) {
    try {
      const raw = await queryWhoisTcp(ianaServer, 43, domainToQuery, innerTimeout);
      if (raw && raw.trim().length > 0) {
        return { raw, structured: {}, server: ianaServer };
      }
    } catch {}
  }

  throw primaryError ?? new Error("No WHOIS server responded");
}

function pickStr(a: string, b: string): string {
  return a && a !== "Unknown" && a !== "" ? a : b;
}

function mergeResults(
  rdap: WhoisAnalyzeResult,
  whoisParsed: WhoisAnalyzeResult,
): WhoisAnalyzeResult {
  return {
    domain: pickStr(rdap.domain, whoisParsed.domain),
    domainPunycode: rdap.domainPunycode || whoisParsed.domainPunycode,
    registrar: pickStr(rdap.registrar, whoisParsed.registrar),
    registrarURL: pickStr(rdap.registrarURL, whoisParsed.registrarURL),
    ianaId: pickStr(rdap.ianaId, whoisParsed.ianaId),
    whoisServer: pickStr(rdap.whoisServer, whoisParsed.whoisServer),
    registryDomainId: pickStr(rdap.registryDomainId, whoisParsed.registryDomainId),
    updatedDate: pickStr(rdap.updatedDate, whoisParsed.updatedDate),
    creationDate: pickStr(rdap.creationDate, whoisParsed.creationDate),
    expirationDate: pickStr(rdap.expirationDate, whoisParsed.expirationDate),
    status: rdap.status.length > 0 ? rdap.status : whoisParsed.status,
    nameServers:
      rdap.nameServers.length > 0 ? rdap.nameServers : whoisParsed.nameServers,
    registrantName: pickStr(rdap.registrantName, whoisParsed.registrantName),
    registrantOrganization: pickStr(
      rdap.registrantOrganization,
      whoisParsed.registrantOrganization,
    ),
    registrantCountry: pickStr(rdap.registrantCountry, whoisParsed.registrantCountry),
    registrantProvince: pickStr(rdap.registrantProvince, whoisParsed.registrantProvince),
    registrantCity: pickStr(rdap.registrantCity, whoisParsed.registrantCity),
    registrantAddress: pickStr(rdap.registrantAddress, whoisParsed.registrantAddress),
    registrantPostalCode: pickStr(rdap.registrantPostalCode, whoisParsed.registrantPostalCode),
    registrantPhone: pickStr(rdap.registrantPhone, whoisParsed.registrantPhone),
    registrantFax: pickStr(rdap.registrantFax, whoisParsed.registrantFax),
    registrantEmail: pickStr(rdap.registrantEmail, whoisParsed.registrantEmail),
    adminName: pickStr(rdap.adminName, whoisParsed.adminName),
    adminOrganization: pickStr(rdap.adminOrganization, whoisParsed.adminOrganization),
    adminCountry: pickStr(rdap.adminCountry, whoisParsed.adminCountry),
    adminEmail: pickStr(rdap.adminEmail, whoisParsed.adminEmail),
    adminPhone: pickStr(rdap.adminPhone, whoisParsed.adminPhone),
    techName: pickStr(rdap.techName, whoisParsed.techName),
    techOrganization: pickStr(rdap.techOrganization, whoisParsed.techOrganization),
    techEmail: pickStr(rdap.techEmail, whoisParsed.techEmail),
    techPhone: pickStr(rdap.techPhone, whoisParsed.techPhone),
    abuseEmail: pickStr(rdap.abuseEmail, whoisParsed.abuseEmail),
    abusePhone: pickStr(rdap.abusePhone, whoisParsed.abusePhone),
    dnssec: pickStr(rdap.dnssec, whoisParsed.dnssec),
    rawWhoisContent: rdap.rawWhoisContent || whoisParsed.rawWhoisContent,
    rawRdapContent: rdap.rawRdapContent || whoisParsed.rawRdapContent,
    domainAge: rdap.domainAge ?? whoisParsed.domainAge,
    remainingDays: rdap.remainingDays ?? whoisParsed.remainingDays,
    registerPrice: rdap.registerPrice ?? whoisParsed.registerPrice,
    renewPrice: rdap.renewPrice ?? whoisParsed.renewPrice,
    negotiable: rdap.negotiable ?? whoisParsed.negotiable,
    cidr: pickStr(rdap.cidr, whoisParsed.cidr),
    inetNum: pickStr(rdap.inetNum, whoisParsed.inetNum),
    inet6Num: pickStr(rdap.inet6Num, whoisParsed.inet6Num),
    netRange: pickStr(rdap.netRange, whoisParsed.netRange),
    netName: pickStr(rdap.netName, whoisParsed.netName),
    netType: pickStr(rdap.netType, whoisParsed.netType),
    originAS: pickStr(rdap.originAS, whoisParsed.originAS),
  };
}

export function computeSmartTtl(result: WhoisResult): number {
  if (!result.status || !result.result) return 0;

  const r = result.result;

  const isIpQuery =
    (r.cidr    && r.cidr    !== "Unknown") ||
    (r.inetNum && r.inetNum !== "Unknown") ||
    (r.inet6Num && r.inet6Num !== "Unknown") ||
    (r.originAS && r.originAS !== "Unknown") ||
    (r.netRange && r.netRange !== "Unknown");
  if (isIpQuery) return 86_400;

  const statuses = (r.status || []).map((s) => s.status?.toLowerCase() ?? "");
  const isReserved =
    statuses.some((s) => s.includes("registry-reserved")) ||
    statuses.some((s) => s.includes("pending"));
  if (isReserved) return 43_200;

  const hasRegistrar   = r.registrar    && r.registrar    !== "Unknown";
  const hasExpiry      = r.expirationDate && r.expirationDate !== "Unknown";
  const hasNameServers = r.nameServers  && r.nameServers.length > 0;
  const hasCreation    = r.creationDate && r.creationDate !== "Unknown";
  const isRegistered   = !!(hasRegistrar || hasExpiry || hasCreation || hasNameServers);

  if (!isRegistered) return 300;

  const remaining = r.remainingDays;
  if (remaining !== null && remaining !== undefined) {
    if (remaining <= 0)   return 600;
    if (remaining <= 7)   return 1_800;
    if (remaining <= 60)  return 3_600;
    if (remaining <= 180) return 21_600;
  }

  return 43_200;
}

export async function lookupWhoisWithCache(
  domain: string,
  options: { nocache?: boolean; cacheOnly?: boolean } = {},
): Promise<WhoisResult> {
  const cnReserved = getCnReservedSldInfo(domain);
  if (cnReserved) {
    return {
      time: 0,
      status: true,
      cached: false,
      cacheTtl: 43_200,
      source: "whois",
      result: {
        ...initialWhoisAnalyzeResult,
        domain,
        status: [{ status: "registry-reserved", url: "" }],
        rawWhoisContent: `[CN Reserved] ${cnReserved.descZh}`,
      },
    };
  }

  const key = `whois:${domain}`;

  if (!options.nocache) {
    const l1Hit = l1Get(key);
    if (l1Hit) {
      const remainingTtl = await getRemainingTtl(key).catch(() => null);
      return { ...l1Hit, time: 0, cached: true, cachedAt: l1Hit.cachedAt, cacheTtl: remainingTtl ?? l1Hit.cacheTtl };
    }

    if (isRedisAvailable()) {
      const l2 = await getJsonRedisValueWithTtl<WhoisResult>(key);
      if (l2) {
        l1Set(key, l2.value);
        return { ...l2.value, time: 0, cached: true, cachedAt: l2.value.cachedAt, cacheTtl: l2.remainingTtl ?? l2.value.cacheTtl };
      }
    }
  }

  if (options.cacheOnly) {
    return { time: 0, status: false, cached: false };
  }

  const result = await lookupWhois(domain);

  if (result.status) {
    const ttl = computeSmartTtl(result);
    const now = Date.now();
    const toStore: WhoisResult = { ...result, cachedAt: now, cacheTtl: ttl };
    l1Set(key, toStore);
    if (isRedisAvailable() && ttl > 0) {
      setJsonRedisValue<WhoisResult>(key, toStore, ttl).catch(() => {});
    }
    return { ...result, cached: false, cachedAt: now, cacheTtl: ttl };
  }

  return { ...result, cached: false };
}

const RDAP_TIMEOUT  = intEnv("RDAP_TIMEOUT_MS",  3_500);
const WHOIS_TIMEOUT = intEnv("WHOIS_TIMEOUT_MS", 8_000);

export async function lookupWhois(domain: string): Promise<WhoisResult> {
  const startTime = performance.now();
  const elapsed = () => (performance.now() - startTime) / 1000;
  const isDomainQuery = !isIPAddress(domain) && !isASNumber(domain);
  const tldSuffix = domain.split(".").pop()?.toLowerCase() ?? "";

  async function failWithDns(error: string, registryUrl?: string): Promise<WhoisResult> {
    const dnsProbe = isDomainQuery
      ? await probeDomain(domain).catch(() => undefined)
      : undefined;
    return { time: elapsed(), status: false, cached: false, error, dnsProbe, registryUrl };
  }

  // Step 1: Try RDAP
  let rdapData: any = null;
  try {
    const rdap = await withTimeout(lookupRdap(domain), RDAP_TIMEOUT);
    if (rdap && !rdap.errorCode) rdapData = rdap;
  } catch {}

  // Step 2: Try WHOIS (custom server → bootstrap → whoiser → IANA)
  // Skip for ccTLDs that have a known direct RDAP endpoint and RDAP succeeded.
  const skipWhois = rdapData !== null && isDomainQuery && RDAP_DIRECT_CCTLDS.has(tldSuffix);
  let whoisData: WhoisRawResult | null = null;
  let whoisError: unknown = null;
  if (!skipWhois) {
    try {
      whoisData = await withTimeout(getLookupWhois(domain), WHOIS_TIMEOUT);
    } catch (e) {
      whoisError = e;
    }
  }

  // Step 3: Build result — prefer RDAP, merge WHOIS if available, fall back to WHOIS-only
  const rdapRaw = rdapData ? JSON.stringify(rdapData, null, 2) : undefined;
  const whoisRawStr = whoisData?.raw || null;

  if (rdapData) {
    try {
      let result = await convertRdapToWhoisResult(rdapData, domain);
      if (whoisRawStr && !isIanaFallback(whoisRawStr)) {
        try {
          const whoisParsed = await analyzeWhois(whoisRawStr);
          result = mergeResults(result, whoisParsed);
        } catch {}
        result.rawWhoisContent = whoisRawStr;
      }
      if (whoisData?.server) result.whoisServer = pickStr(result.whoisServer, whoisData.server);
      result.rawRdapContent = rdapRaw!;
      return { time: elapsed(), status: true, cached: false, source: "rdap", result };
    } catch {}
  }

  if (whoisRawStr) {
    if (isIanaFallback(whoisRawStr)) {
      return failWithDns("No WHOIS/RDAP server available for this TLD");
    }
    if (isWhoisRateLimited(whoisRawStr)) {
      return failWithDns("WHOIS 服务器临时限制了本次查询速率，请稍后再试");
    }
    try {
      const result = await analyzeWhois(whoisRawStr);
      const detectedError = detectWhoisError(whoisRawStr);
      if (detectedError || isEmptyResult(result)) {
        if (detectedError && isNotRegisteredWhoisResponse(detectedError)) {
          return {
            time: elapsed(),
            status: false,
            cached: false,
            error: detectedError,
            dnsProbe: {
              domain,
              registrationStatus: "unregistered",
              confidence: "high",
              signals: [],
              nameservers: [],
              ipv4: [],
              ipv6: [],
              mx: [],
              hasSsl: null,
            },
          };
        }
        return failWithDns(detectedError || "Empty WHOIS response");
      }
      if (whoisData?.server) result.whoisServer = pickStr(result.whoisServer, whoisData.server);
      if (rdapRaw) result.rawRdapContent = rdapRaw;
      return { time: elapsed(), status: true, cached: false, source: "whois", result };
    } catch (parseError: unknown) {
      return failWithDns(
        parseError instanceof Error ? parseError.message : "Failed to parse WHOIS response",
      );
    }
  }

  const scraperRegistryUrl =
    whoisError instanceof ScraperRequiredError ? whoisError.registryUrl : undefined;
  const whoisMsg = whoisError instanceof Error ? whoisError.message : "";
  const whoisReturnedEmpty = whoisData !== null && (!whoisData.raw || whoisData.raw.trim().length === 0);
  const errMsg = /not supported/i.test(whoisMsg)
    ? "WHOIS/RDAP not available for this TLD"
    : /cannot read properties/i.test(whoisMsg)
    ? "No WHOIS/RDAP data found for this query"
    : whoisReturnedEmpty && whoisData?.server
    ? `WHOIS server (${whoisData.server}) connected but returned no data — the server may restrict access by IP or require queries from the registry's country`
    : whoisMsg || "Unknown error occurred";
  return failWithDns(errMsg, scraperRegistryUrl);
}
