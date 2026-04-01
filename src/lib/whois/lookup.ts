import { MAX_WHOIS_FOLLOW, LOOKUP_TIMEOUT } from "@/lib/env";
import { WhoisResult, WhoisRawResult } from "@/lib/whois/types";
import {
  getJsonRedisValueWithTtl,
  setJsonRedisValue,
  isRedisAvailable,
  getRemainingTtl,
} from "@/lib/server/redis";
import { analyzeWhois } from "@/lib/whois/common_parser";
import { extractDomain } from "@/lib/utils";
import { lookupRdap, convertRdapToWhoisResult, RdapResponse } from "@/lib/whois/rdap_client";
import { getCnReservedSldInfo } from "@/lib/whois/cn-reserved-sld";
import { probeDomain } from "@/lib/whois/dns-check";
import { warmupDnsCache } from "@/lib/whois/dns-resolver";
import {
  isWhoisRateLimited,
  isNotRegisteredWhoisResponse,
  isIanaFallback,
  detectWhoisError,
  isEmptyResult,
  isIPAddress,
  isASNumber,
  toAsciiDomain,
} from "@/lib/whois/whois-patterns";
import { lookupIpOrAsn, tryGenericWhoisForDomain, mergeResults, pickStr } from "@/lib/whois/whois-generic";
import { initialWhoisAnalyzeResult } from "@/lib/whois/types";

warmupDnsCache([
  "whois.verisign-grs.com", "whois.pir.org", "whois.iana.org",
  "whois.afilias.net", "whois.nic.fr", "whois.denic.de",
  "whois.cnnic.cn", "whois.nic.uk", "whois.apnic.net",
  "whois.arin.net", "whois.ripe.net", "whois.lacnic.net", "whois.afrinic.net",
]);

// ── L1 in-process cache (30 s / 500 entries) ─────────────────────────────────
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

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Timeout")), ms);
    promise.then(
      (v) => { clearTimeout(timer); resolve(v); },
      (e) => { clearTimeout(timer); reject(e); },
    );
  });
}

// ── Smart cache TTL ───────────────────────────────────────────────────────────
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
  if (statuses.some((s) => s.includes("registry-reserved") || s.includes("pending"))) return 43_200;

  const isRegistered = !!(
    (r.registrar && r.registrar !== "Unknown") ||
    (r.expirationDate && r.expirationDate !== "Unknown") ||
    (r.creationDate && r.creationDate !== "Unknown") ||
    (r.nameServers && r.nameServers.length > 0)
  );
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

// ── Cache-aware public entry point ────────────────────────────────────────────
export async function lookupWhoisWithCache(
  domain: string,
  options: { nocache?: boolean; cacheOnly?: boolean } = {},
): Promise<WhoisResult> {
  const cnReserved = getCnReservedSldInfo(domain);
  if (cnReserved) {
    return {
      time: 0, status: true, cached: false, cacheTtl: 43_200, source: "whois",
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

  if (options.cacheOnly) return { time: 0, status: false, cached: false };

  const result = await lookupWhois(domain);
  if (result.status) {
    const ttl = computeSmartTtl(result);
    const now = Date.now();
    const toStore: WhoisResult = { ...result, cachedAt: now, cacheTtl: ttl };
    l1Set(key, toStore);
    if (isRedisAvailable() && ttl > 0) setJsonRedisValue<WhoisResult>(key, toStore, ttl).catch(() => {});
    return { ...result, cached: false, cachedAt: now, cacheTtl: ttl };
  }
  return { ...result, cached: false };
}

function intEnv(name: string, def: number): number {
  const n = parseInt(process.env[name] ?? "", 10);
  return isNaN(n) ? def : n;
}

// ── Core lookup: custom server → RDAP → generic WHOIS → merge/error ──────────
// Timeouts: RDAP_TIMEOUT_MS (default 3.5 s), WHOIS_TIMEOUT_MS (default 8 s).
// 8 s WHOIS budget accommodates slow ccTLD servers (e.g. .cn, .de).
const RDAP_TIMEOUT  = intEnv("RDAP_TIMEOUT_MS",  3_500);
const WHOIS_TIMEOUT = intEnv("WHOIS_TIMEOUT_MS", 8_000);
type RdapResult = RdapResponse | { errorCode: number; title?: string };

export async function lookupWhois(domain: string): Promise<WhoisResult> {
  const startTime = performance.now();
  const elapsed = () => (performance.now() - startTime) / 1000;
  const isDomainQuery = !isIPAddress(domain) && !isASNumber(domain);

  async function failWithDns(error: string, registryUrl?: string): Promise<WhoisResult> {
    const dnsProbe = isDomainQuery
      ? await probeDomain(domain).catch(() => undefined)
      : undefined;
    return { time: elapsed(), status: false, cached: false, error, dnsProbe, registryUrl };
  }

  // ── IP / ASN shortcut ─────────────────────────────────────────────────────
  if (!isDomainQuery) {
    let whoisData: WhoisRawResult | null = null;
    let whoisError: unknown = null;
    try {
      whoisData = await withTimeout(lookupIpOrAsn(domain), WHOIS_TIMEOUT);
    } catch (e) { whoisError = e; }
    if (whoisData?.raw) {
      try {
        const result = await analyzeWhois(whoisData.raw);
        return { time: elapsed(), status: true, cached: false, source: "whois", result };
      } catch (e: unknown) {
        return failWithDns(e instanceof Error ? e.message : "Failed to parse response");
      }
    }
    return failWithDns(whoisError instanceof Error ? whoisError.message : "Unknown error occurred");
  }

  // ── Domain lookup ─────────────────────────────────────────────────────────
  const rawExtracted = extractDomain(domain) || domain;
  const domainToQuery = toAsciiDomain(rawExtracted);
  const tld = domainToQuery.split(".").slice(1).join(".");
  const tldSuffix = domainToQuery.split(".").pop() || "";
  const innerTimeout = Math.min(LOOKUP_TIMEOUT, WHOIS_TIMEOUT - 300);
  const follow = Math.min(Math.max(MAX_WHOIS_FOLLOW, 1), 2) as 1 | 2;

  // RDAP + WHOIS in parallel — original approach: always run both concurrently.
  // Running concurrently avoids skipping WHOIS when RDAP returns incomplete data.
  const [rdapSettled, whoisSettled] = await Promise.allSettled([
    withTimeout(lookupRdap(domain), RDAP_TIMEOUT) as Promise<RdapResult>,
    withTimeout(
      tryGenericWhoisForDomain(domainToQuery, tld, tldSuffix, innerTimeout, follow),
      WHOIS_TIMEOUT,
    ),
  ]);

  const rdapSettledResult = rdapSettled.status === "fulfilled" ? rdapSettled.value : null;
  const rdapData: RdapResponse | null = rdapSettledResult && !("errorCode" in rdapSettledResult) ? rdapSettledResult as RdapResponse : null;
  const whoisData: WhoisRawResult | null = whoisSettled.status === "fulfilled" ? whoisSettled.value : null;
  const whoisError: unknown = whoisSettled.status === "rejected" ? whoisSettled.reason : null;
  // Step 4: Build result — prefer RDAP, optionally enrich with WHOIS raw text,
  // then fall back to WHOIS-only; if neither succeeded, return error.
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
    if (isIanaFallback(whoisRawStr)) return failWithDns("No WHOIS/RDAP server available for this TLD");
    if (isWhoisRateLimited(whoisRawStr)) return failWithDns("WHOIS 服务器临时限制了本次查询速率，请稍后再试");
    try {
      const result = await analyzeWhois(whoisRawStr);
      const detectedError = detectWhoisError(whoisRawStr);
      if (detectedError || isEmptyResult(result)) {
        if (detectedError && isNotRegisteredWhoisResponse(detectedError)) {
          return {
            time: elapsed(), status: false, cached: false, error: detectedError,
            dnsProbe: {
              domain, registrationStatus: "unregistered", confidence: "high",
              signals: [], nameservers: [], ipv4: [], ipv6: [], mx: [], hasSsl: null,
            },
          };
        }
        return failWithDns(detectedError || "Empty WHOIS response");
      }
      if (whoisData?.server) result.whoisServer = pickStr(result.whoisServer, whoisData.server);
      if (rdapRaw) result.rawRdapContent = rdapRaw;
      return { time: elapsed(), status: true, cached: false, source: "whois", result };
    } catch (e: unknown) {
      return failWithDns(e instanceof Error ? e.message : "Failed to parse WHOIS response");
    }
  }

  const whoisMsg = whoisError instanceof Error ? whoisError.message : "";
  const rdapMsg = rdapSettled.status === "rejected" ? (rdapSettled.reason instanceof Error ? rdapSettled.reason.message : "") : "";
  const whoisReturnedEmpty = whoisData !== null && (!whoisData.raw || whoisData.raw.trim().length === 0);
  const errMsg = /not supported/i.test(whoisMsg)
    ? "WHOIS/RDAP not available for this TLD"
    : /cannot read properties/i.test(whoisMsg) || /cannot read properties/i.test(rdapMsg)
    ? "No WHOIS/RDAP data found for this query"
    : whoisReturnedEmpty && whoisData?.server
    ? `WHOIS server (${whoisData.server}) connected but returned no data — the server may restrict access by IP or require queries from the registry's country`
    : whoisMsg || rdapMsg || "Unknown error occurred";
  return failWithDns(errMsg);
}
