import { MAX_WHOIS_FOLLOW, LOOKUP_TIMEOUT } from "@/lib/env";
import { WhoisResult, WhoisRawResult, WhoisAnalyzeResult } from "@/lib/whois/types";
import {
  getJsonRedisValueWithTtl,
  setJsonRedisValue,
  isRedisAvailable,
  getWhoisDbCache,
  setWhoisDbCache,
} from "@/lib/server/redis";
import { analyzeWhois } from "@/lib/whois/common_parser";
import { extractDomain } from "@/lib/utils";
import { lookupRdap, convertRdapToWhoisResult, RdapResponse, RDAP_OUTER_TIMEOUT_MS } from "@/lib/whois/rdap_client";
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
import { ScraperRequiredError } from "@/lib/whois/custom-servers";
import { lookupIpOrAsn, tryGenericWhoisForDomain, mergeResults, pickStr } from "@/lib/whois/whois-generic";
import { initialWhoisAnalyzeResult } from "@/lib/whois/types";
import { recordTldLookupFailure, getTldApiSource, clearTldFailureStats } from "@/lib/db";
import { lookupViaThirdPartyApi, ThirdPartyApiSource } from "./third-party-api";

warmupDnsCache([
  // gTLD / IANA / RIR
  "whois.verisign-grs.com", "whois.pir.org", "whois.iana.org",
  "whois.afilias.net", "whois.apnic.net",
  "whois.arin.net", "whois.ripe.net", "whois.lacnic.net", "whois.afrinic.net",
  // Popular gTLD registry WHOIS
  "whois.centralnic.com", "whois.donuts.co", "whois.afilias-grs.info",
  "whois.nic.google", "whois.godaddy.com", "whois.uniregistry.net",
  "whois.publicinterestregistry.org",
  // High-traffic ccTLD WHOIS servers
  "whois.nic.hu", "whois.jprs.jp", "whois.registro.br",
  "whois.nic.fr", "whois.denic.de", "whois.nic.uk",
  "whois.cnnic.cn", "whois.nic.it", "whois.tcinet.ru",
  "whois.dns.pl", "whois.dnsbelgium.be", "whois.domreg.lt",
  "whois.nic.au", "whois.srs.net.nz", "whois.teleinfo.cn",
  // Additional ccTLD servers
  "whois.nic.es", "whois.nic.se", "whois.norid.no",
  "whois.nic.fi", "whois.dk-hostmaster.dk", "whois.domain.fi",
  "whois.nic.ch", "whois.switch.ch", "whois.nic.at",
  "whois.nic.cz", "whois.sk-nic.sk", "whois.nic.ro",
  "whois.registry.net.za", "whois.nic.ng", "whois.rnids.rs",
  "whois.nic.co.uk", "whois.nominet.org.uk",
  "whois.nic.kr", "whois.twnic.net.tw", "whois.pandi.or.id",
  "whois.vnnic.vn", "whois.thnic.co.th", "whois.nic.ir",
  "whois.nic.tr", "whois.pknic.net.pk", "whois.nic.mx",
]);

// Pre-warm the whoiser module in the background so the first WHOIS TCP lookup
// does not pay the module-parse cost (~30-100 ms) during the request hot path.
import("whoiser").catch(() => {});

// ── L1 in-process cache (60 s / 2 000 entries, LRU eviction) ─────────────────
// Increased from 30 s / 500 to absorb more repeated queries between Redis
// round-trips while keeping memory bounded.  LRU eviction keeps hot domains
// alive longer, evicting cold entries first.
const L1_TTL_MS = 60_000;
const L1_MAX = 2_000;
type MemEntry = { value: WhoisResult; expiresAt: number };
const _memCache = new Map<string, MemEntry>();

function l1Get(key: string): WhoisResult | null {
  const entry = _memCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) { _memCache.delete(key); return null; }
  // LRU: re-insert to move to Map end (most-recently-used position).
  _memCache.delete(key);
  _memCache.set(key, entry);
  return entry.value;
}

// ── In-flight deduplication ───────────────────────────────────────────────────
// Prevents thundering-herd on cache misses: if N requests arrive simultaneously
// for the same uncached domain, only the first spawns a real lookup; the rest
// await the shared Promise and get the result for free.
const _inflight = new Map<string, Promise<WhoisResult>>();

/**
 * Compute approximate remaining TTL (seconds) from the stored result's
 * cachedAt + cacheTtl timestamps — no Redis round-trip needed.
 * Used in place of getRemainingTtl() on L1 cache hits to save one network call.
 */
function l1ComputeRemainingTtl(r: WhoisResult): number | null {
  if (!r.cacheTtl || !r.cachedAt) return null;
  const ageS = (Date.now() - r.cachedAt) / 1000;
  return Math.max(0, Math.round(r.cacheTtl - ageS));
}

function l1Set(key: string, value: WhoisResult) {
  // Remove first so existing keys are moved to MRU position (LRU Map semantics).
  if (_memCache.has(key)) _memCache.delete(key);
  if (_memCache.size >= L1_MAX) {
    // Evict the LRU entry (first/oldest key in insertion order).
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

// ── Transient-failure detection ───────────────────────────────────────────────
// Returns true when a failed lookup result is worth retrying (network blip,
// empty response, timeout) vs. a definitive failure that retrying cannot fix.
function isTransientLookupFailure(result: WhoisResult): boolean {
  if (result.status) return false;
  const err = (result.error ?? "").toLowerCase();
  // Definitive: IANA fallback ("No WHOIS/RDAP server available for this TLD")
  if (err.includes("no whois") && err.includes("available")) return false;
  // Definitive: server reports TLD not supported ("WHOIS/RDAP not available for this TLD")
  if (err.includes("not available for this tld") || err.includes("not supported")) return false;
  // Definitive: DNS confirmed the domain is unregistered
  if (result.dnsProbe?.registrationStatus === "unregistered") return false;
  // Definitive: RDAP authoritatively said the domain does not exist (HTTP 404)
  if (err.includes("domain not found")) return false;
  // Everything else (timeout, connection reset, empty response, rate-limited)
  // is potentially transient — worth one automatic retry.
  return true;
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
    // L1 — in-process memory (fastest, no network)
    const l1Hit = l1Get(key);
    if (l1Hit) {
      // Compute remaining TTL locally — avoids an extra Redis round-trip on every
      // L1 cache hit. The result is accurate to within the L1 TTL window.
      const remainingTtl = l1ComputeRemainingTtl(l1Hit);
      return { ...l1Hit, time: 0, cached: true, cachedAt: l1Hit.cachedAt, cacheTtl: remainingTtl ?? l1Hit.cacheTtl };
    }
    // L2 — Redis (Upstash HTTP preferred, ioredis TCP standby)
    if (isRedisAvailable()) {
      const l2 = await getJsonRedisValueWithTtl<WhoisResult>(key);
      if (l2) {
        l1Set(key, l2.value);
        return { ...l2.value, time: 0, cached: true, cachedAt: l2.value.cachedAt, cacheTtl: l2.remainingTtl ?? l2.value.cacheTtl };
      }
    }
    // L3 — PostgreSQL fallback (used when both Redis tiers are unavailable)
    if (!isRedisAvailable()) {
      const l3Raw = await getWhoisDbCache(key);
      if (l3Raw) {
        try {
          const l3 = JSON.parse(l3Raw) as WhoisResult;
          l1Set(key, l3);
          return { ...l3, time: 0, cached: true };
        } catch { /* corrupted — fall through to fresh lookup */ }
      }
    }
    // In-flight deduplication: piggyback on a concurrent lookup for the same domain.
    const inflight = _inflight.get(key);
    if (inflight) return inflight;
  }

  if (options.cacheOnly) return { time: 0, status: false, cached: false };

  // ── Per-TLD third-party API override ────────────────────────────────────────
  // If the admin has configured a third-party API source for this TLD, use it
  // for ALL queries (skips local WHOIS/RDAP entirely).
  if (!isIPAddress(domain) && !isASNumber(domain)) {
    const parts = domain.toLowerCase().split(".");
    const tld = parts.length >= 2 ? parts[parts.length - 1] : "";
    if (tld) {
      const apiSrc = await getTldApiSource(tld).catch(() => null);
      if (apiSrc) {
        const r = await lookupViaThirdPartyApi(domain, apiSrc as ThirdPartyApiSource);
        if (r.status) {
          const ttl = 3600; // 1-hour TTL for third-party results
          const now = Date.now();
          const toStore: WhoisResult = { ...r, cachedAt: now, cacheTtl: ttl };
          l1Set(key, toStore);
          if (isRedisAvailable()) {
            setJsonRedisValue<WhoisResult>(key, toStore, ttl).catch(() => {});
          }
          // Third-party API proved it can handle this TLD — auto-remove the
          // failure stats record so it disappears from the admin failures list.
          clearTldFailureStats(tld).catch(() => {});
          return { ...r, cached: false, cachedAt: now, cacheTtl: ttl };
        }
        // Third-party was explicitly configured by the admin for this TLD —
        // it means the native WHOIS/RDAP stack doesn't work here (.ba/.bb etc.).
        // Return the third-party error directly instead of falling through to a
        // guaranteed-to-fail (and slow) native lookup.
        return { ...r, cached: false };
      }
    }
  }

  const doLookup = async (): Promise<WhoisResult> => {
    let result = await lookupWhois(domain);
    // Retry once on transient failures (e.g., intermittent connectivity to
    // slow ccTLD WHOIS servers like whois.nic.hu from cloud infrastructure).
    // Use jitter (400–800ms) to avoid thundering herd on concurrent retries.
    if (isTransientLookupFailure(result)) {
      const jitter = 400 + Math.floor(Math.random() * 400);
      await new Promise((r) => setTimeout(r, jitter));
      const retried = await lookupWhois(domain);
      if (retried.status) result = retried;
    }
    if (result.status) {
      const ttl = computeSmartTtl(result);
      const now = Date.now();
      const toStore: WhoisResult = { ...result, cachedAt: now, cacheTtl: ttl };
      l1Set(key, toStore);
      if (ttl > 0) {
        if (isRedisAvailable()) {
          setJsonRedisValue<WhoisResult>(key, toStore, ttl).catch(() => {});
        } else {
          // Both Redis tiers unavailable — persist to PostgreSQL L3.
          setWhoisDbCache(key, JSON.stringify(toStore), ttl).catch(() => {});
        }
      }
      return { ...result, cached: false, cachedAt: now, cacheTtl: ttl };
    }
    return { ...result, cached: false };
  };

  if (options.nocache) return doLookup();

  // Register in-flight promise so concurrent identical requests share this lookup.
  const promise = doLookup();
  _inflight.set(key, promise);
  try {
    return await promise;
  } finally {
    _inflight.delete(key);
  }
}

function intEnv(name: string, def: number): number {
  const n = parseInt(process.env[name] ?? "", 10);
  return isNaN(n) ? def : n;
}

// ── Core lookup: custom server → RDAP → generic WHOIS → merge/error ──────────
// Timeouts: RDAP_TIMEOUT_MS (default 4.0 s), WHOIS_TIMEOUT_MS (default 8 s).
// RDAP: bumped 2500 → 4000 ms — some ccTLD RDAP servers (e.g. .rw, .tz, .ke)
// respond in 2-3.5 s from cloud infra; the old cap triggered needless retries.
// WHOIS: 8000 ms (restored; was briefly reduced, broke slow servers like .nic.hu).
const RDAP_TIMEOUT  = intEnv("RDAP_TIMEOUT_MS",  4_000);
const WHOIS_TIMEOUT = intEnv("WHOIS_TIMEOUT_MS", 8_000);

/**
 * Per-TLD WHOIS timeout overrides (milliseconds).
 * Used for registries whose WHOIS servers consistently respond slowly.
 * When set, the inner TCP timeout AND the outer withTimeout wrapper are
 * both extended beyond the global WHOIS_TIMEOUT for that TLD.
 */
const SLOW_WHOIS_TLDS: Readonly<Record<string, number>> = {
  // Known slow ccTLD WHOIS servers (anecdotally 4-10 s from global infra)
  hu: 12_000,  // whois.nic.hu — 4-8 s typical
  jp:  9_000,  // whois.jprs.jp — 3-6 s typical
  br:  9_000,  // whois.registro.br — 3-6 s typical
  ar: 12_000,  // whois.nic.ar — 5-10 s typical
  kr:  9_000,  // whois.kr — 3-6 s typical
  au:  9_000,  // whois.auda.org.au — 3-6 s typical
  nz:  9_000,  // whois.srs.net.nz — 3-5 s typical
  tw:  9_000,  // whois.twnic.net.tw — 3-6 s typical
  id:  9_000,  // whois.pandi.or.id — variable
  vn:  9_000,  // whois.vnnic.vn — variable
  ir: 10_000,  // whois.nic.ir — slow
  pk:  9_000,  // whois.pknic.net.pk — slow
  pl:  9_000,  // whois.dns.pl — 3-6 s typical
  za: 10_000,  // whois.registry.net.za — 4-8 s typical
  mx:  9_000,  // whois.nic.mx — 3-6 s typical
  th:  9_000,  // whois.thnic.co.th — 3-6 s typical
};
/**
 * TLDs that have no publicly accessible WHOIS or RDAP server at all.
 * Queries for these TLDs skip the full WHOIS/RDAP timeout cycle (saves up to
 * 20 s of guaranteed waiting) and go straight to DNS probe for availability.
 * When DNS is also unreachable for these TLDs, we treat the domain as
 * "likely unregistered" with low confidence rather than hard "LOOKUP FAILED".
 */
const NO_SERVER_TLDS = new Set<string>([
  "hm",  // Heard Island & McDonald Islands — IANA managed, no public WHOIS/RDAP
  "aq",  // Antarctica — IANA managed, no public WHOIS/RDAP
  "bv",  // Bouvet Island — no public WHOIS/RDAP
  "sj",  // Svalbard & Jan Mayen — no public WHOIS/RDAP
  "eh",  // Western Sahara — no public WHOIS/RDAP
  "tf",  // French Southern Territories — IANA managed, no public WHOIS/RDAP
  "pm",  // Saint Pierre & Miquelon — no public WHOIS/RDAP
]);

type RdapResult = RdapResponse | { errorCode: number; title?: string };

/**
 * lookupWhoisWithCache variant that supports streaming partial results.
 * When RDAP returns before WHOIS, `onPartialResult` is called immediately
 * so callers can stream RDAP-only data to the client before WHOIS enrichment
 * completes. The returned Promise resolves with the fully merged result.
 */
export async function lookupWhoisCacheStreaming(
  domain: string,
  options: { nocache?: boolean } = {},
  onPartialResult?: (partial: WhoisResult) => void,
): Promise<WhoisResult> {
  const cnReserved = getCnReservedSldInfo(domain);
  if (cnReserved) {
    const r: WhoisResult = {
      time: 0, status: true, cached: false, cacheTtl: 43_200, source: "whois",
      result: {
        ...initialWhoisAnalyzeResult,
        domain,
        status: [{ status: "registry-reserved", url: "" }],
        rawWhoisContent: `[CN Reserved] ${cnReserved.descZh}`,
      },
    };
    onPartialResult?.(r);
    return r;
  }

  const key = `whois:${domain}`;

  if (!options.nocache) {
    // L1 — in-process memory (fastest, no network)
    const l1Hit = l1Get(key);
    if (l1Hit) {
      const remainingTtl = l1ComputeRemainingTtl(l1Hit);
      const r = { ...l1Hit, time: 0, cached: true, cacheTtl: remainingTtl ?? l1Hit.cacheTtl };
      // Cache hits are already complete — do NOT call onPartialResult here.
      // Emitting a partial chunk for a cache hit would cause the streaming
      // endpoint to send partial:true followed by partial:false with identical
      // data, producing a false "refreshing" flash in the UI.
      return r;
    }
    // L2 — Redis (Upstash HTTP preferred, ioredis TCP standby)
    if (isRedisAvailable()) {
      const l2 = await getJsonRedisValueWithTtl<WhoisResult>(key);
      if (l2) {
        l1Set(key, l2.value);
        const r = { ...l2.value, time: 0, cached: true, cacheTtl: l2.remainingTtl ?? l2.value.cacheTtl };
        // Same reasoning as L1: cache hits skip partial notification.
        return r;
      }
    }
    // L3 — PostgreSQL fallback (used when both Redis tiers are unavailable)
    if (!isRedisAvailable()) {
      const l3Raw = await getWhoisDbCache(key);
      if (l3Raw) {
        try {
          const l3 = JSON.parse(l3Raw) as WhoisResult;
          l1Set(key, l3);
          return { ...l3, time: 0, cached: true };
        } catch { /* corrupted — fall through to fresh lookup */ }
      }
    }
    // In-flight deduplication: piggyback on a concurrent identical lookup.
    // Note: the secondary request won't receive streaming partials (the first
    // request owns the onPartialResult callback), but it avoids a duplicate
    // WHOIS query — it receives the final result as soon as the first completes.
    const inflight = _inflight.get(key);
    if (inflight) return inflight;
  }

  // ── Per-TLD third-party API override (mirrors lookupWhoisWithCache) ──────────
  if (!isIPAddress(domain) && !isASNumber(domain)) {
    const parts = domain.toLowerCase().split(".");
    const tld = parts.length >= 2 ? parts[parts.length - 1] : "";
    if (tld) {
      const apiSrc = await getTldApiSource(tld).catch(() => null);
      if (apiSrc) {
        const r = await lookupViaThirdPartyApi(domain, apiSrc as ThirdPartyApiSource);
        if (r.status) {
          const ttl = 3600;
          const now = Date.now();
          const toStore: WhoisResult = { ...r, cachedAt: now, cacheTtl: ttl };
          l1Set(key, toStore);
          if (isRedisAvailable()) {
            setJsonRedisValue<WhoisResult>(key, toStore, ttl).catch(() => {});
          }
          clearTldFailureStats(tld).catch(() => {});
          onPartialResult?.({ ...r, cached: false, cachedAt: now, cacheTtl: ttl });
          return { ...r, cached: false, cachedAt: now, cacheTtl: ttl };
        }
        // Admin explicitly configured this TLD for third-party — native lookup
        // won't work here.  Return the third-party error directly so the caller
        // gets an immediate response with no wasted WHOIS/RDAP timeout.
        onPartialResult?.({ ...r, cached: false });
        return { ...r, cached: false };
      }
    }
  }

  const doLookup = async (): Promise<WhoisResult> => {
    let result = await lookupWhois(domain, onPartialResult);
    // Retry once on transient failures (same logic as lookupWhoisWithCache).
    // Pass onPartialResult to the retry so that if RDAP succeeds on the second
    // attempt the partial result is streamed immediately (clears the loading
    // skeleton at ~RDAP_TIMEOUT rather than waiting the full retry duration).
    if (isTransientLookupFailure(result)) {
      const jitter = 400 + Math.floor(Math.random() * 400);
      await new Promise((r) => setTimeout(r, jitter));
      const retried = await lookupWhois(domain, onPartialResult);
      if (retried.status) result = retried;
    }
    if (result.status) {
      const ttl = computeSmartTtl(result);
      const now = Date.now();
      const toStore: WhoisResult = { ...result, cachedAt: now, cacheTtl: ttl };
      l1Set(key, toStore);
      if (ttl > 0) {
        if (isRedisAvailable()) {
          setJsonRedisValue<WhoisResult>(key, toStore, ttl).catch(() => {});
        } else {
          // Both Redis tiers unavailable — persist to PostgreSQL L3.
          setWhoisDbCache(key, JSON.stringify(toStore), ttl).catch(() => {});
        }
      }
      return { ...result, cached: false, cachedAt: now, cacheTtl: ttl };
    }
    return { ...result, cached: false };
  };

  if (options.nocache) return doLookup();

  // Register in-flight promise so concurrent identical requests share this lookup.
  const promise = doLookup();
  _inflight.set(key, promise);
  try {
    return await promise;
  } finally {
    _inflight.delete(key);
  }
}

export async function lookupWhois(domain: string, onPartialResult?: (partial: WhoisResult) => void): Promise<WhoisResult> {
  const startTime = performance.now();
  const elapsed = () => (performance.now() - startTime) / 1000;
  const isDomainQuery = !isIPAddress(domain) && !isASNumber(domain);

  // Holds a pre-started DNS probe promise (started when RDAP fails, so DNS runs
  // in parallel with WHOIS rather than serially after it — saves up to 5 s on
  // the failure path).
  let _earlyDnsProbe: Promise<import("@/lib/whois/dns-check").DnsProbeResult | undefined> | null = null;

  async function failWithDns(error: string, registryUrl?: string): Promise<WhoisResult> {
    // Reuse the early DNS probe if it was started during the RDAP failure;
    // otherwise start one now (fallback for paths that skipped the early start).
    const dnsProbe = isDomainQuery
      ? await (_earlyDnsProbe ?? probeDomain(domain)).catch(() => undefined)
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

  function recordFailure(
    reason: "no_server" | "timeout" | "parse_error" | "rate_limited" | "iana_fallback",
    errorMsg?: string,
  ) {
    recordTldLookupFailure(tldSuffix, reason, domainToQuery, errorMsg).catch(() => {});
  }
  const baseInnerTimeout = Math.min(LOOKUP_TIMEOUT, WHOIS_TIMEOUT - 300);
  // Per-TLD extended timeout for known-slow WHOIS servers.
  // Both the inner TCP timeout and the outer withTimeout wrapper are extended.
  const tldExtraMs = SLOW_WHOIS_TLDS[tldSuffix] ?? 0;
  const innerTimeout = Math.max(baseInnerTimeout, tldExtraMs);
  const effectiveWhoisTimeout = innerTimeout > WHOIS_TIMEOUT ? innerTimeout + 300 : WHOIS_TIMEOUT;
  const follow = Math.min(Math.max(MAX_WHOIS_FOLLOW, 1), 2) as 1 | 2;

  // ── Fast-fail for TLDs with no public WHOIS/RDAP server ──────────────────
  // Skip the full timeout cycle and go straight to DNS probe.
  // When DNS is also unreachable (allTimedOut), we use "unregistered" (low
  // confidence) so the UI shows the available card rather than a hard error.
  if (NO_SERVER_TLDS.has(tldSuffix)) {
    recordFailure("no_server", `No public WHOIS/RDAP server for .${tldSuffix}`);
    const rawDns = await probeDomain(domain).catch(() => undefined);
    // When DNS is also unreachable for a no-server TLD, assume unregistered (low confidence).
    // rawDns may be undefined on probe error; allTimedOut may be true on network failure.
    let dnsProbe: Awaited<ReturnType<typeof probeDomain>>;
    if (!rawDns) {
      dnsProbe = { domain, registrationStatus: "unregistered", confidence: "low", signals: [], nameservers: [], ipv4: [], ipv6: [], mx: [], hasSsl: null };
    } else if (rawDns.registrationStatus === "unknown") {
      dnsProbe = { ...rawDns, registrationStatus: "unregistered", confidence: "low" };
    } else {
      dnsProbe = rawDns;
    }
    return {
      time: elapsed(), status: false, cached: false,
      error: "WHOIS/RDAP not available for this TLD",
      dnsProbe,
    };
  }

  // Grace period (ms) WHOIS gets to complete after RDAP already succeeded.
  // Reduced from 1200 → 900 ms: 900 ms is enough for most WHOIS servers to
  // respond while showing the final merged result ~300 ms sooner.
  const RDAP_WIN_WHOIS_GRACE_MS = 900;

  // Start RDAP + WHOIS in parallel.
  // IMPORTANT: The outer withTimeout must use RDAP_OUTER_TIMEOUT_MS (12 s), NOT
  // RDAP_TIMEOUT (4 s), so per-TLD inner timeouts in rdap_client.ts (e.g. .rw=6s,
  // .ar=10s) fire BEFORE the outer wrapper cancels the promise.  RDAP_TIMEOUT is
  // kept for documentation; RDAP_OUTER_TIMEOUT_MS is the actual runtime value.
  const rdapPromise = withTimeout(lookupRdap(domain), RDAP_OUTER_TIMEOUT_MS) as Promise<RdapResult>;
  const whoisPromise = withTimeout(
    tryGenericWhoisForDomain(domainToQuery, tld, tldSuffix, innerTimeout, follow),
    effectiveWhoisTimeout,
  );

  // When RDAP finishes first with good data, only wait an additional grace period
  // for WHOIS to add raw text — then proceed rather than blocking until WHOIS_TIMEOUT.
  let rdapSettled: PromiseSettledResult<RdapResult | null>;
  let whoisSettled: PromiseSettledResult<WhoisRawResult | null>;

  // Cache the first convertRdapToWhoisResult call so the final merge can reuse it
  // instead of calling it a second time — avoids 50-200 ms of redundant CPU work.
  let _precomputedRdap: WhoisAnalyzeResult | null = null;

  const rdapEarlyResult = await Promise.race([
    rdapPromise.then(v => ({ settled: true as const, value: v as RdapResult | null })).catch(() => ({ settled: true as const, value: null as RdapResult | null })),
    whoisPromise.then(() => ({ settled: false as const })).catch(() => ({ settled: false as const })),
  ]);

  if (rdapEarlyResult.settled) {
    // RDAP finished first — check if it has good data
    const rdapVal: RdapResult | null = rdapEarlyResult.value ?? null;
    const hasGoodRdap = rdapVal !== null && !("errorCode" in rdapVal);
    if (hasGoodRdap) {
      // If a streaming callback is provided, fire the partial RDAP-only result
      // immediately so the caller can stream it to the client before WHOIS arrives.
      // We always convert here (not just when onPartialResult is set) so the result
      // is cached in _precomputedRdap for the final merge, avoiding a second call.
      if (onPartialResult) {
        try {
          const partialRdapResult = await convertRdapToWhoisResult(rdapVal as RdapResponse, domain);
          partialRdapResult.rawRdapContent = JSON.stringify(rdapVal, null, 2);
          _precomputedRdap = partialRdapResult;
          onPartialResult({
            time: elapsed(),
            status: true,
            cached: false,
            source: "rdap",
            result: partialRdapResult,
          });
        } catch { /* ignore — final result will include RDAP data */ }
      }
      // Give WHOIS a short grace window to add enrichment data
      const whoisGraceResult = await Promise.race([
        whoisPromise
          .then(v  => ({ status: "fulfilled" as const, value: v }))
          .catch(e  => ({ status: "rejected"  as const, reason: e })),
        new Promise<{ status: "rejected"; reason: Error }>(res =>
          setTimeout(() => res({ status: "rejected", reason: new Error("whois-grace-timeout") }), RDAP_WIN_WHOIS_GRACE_MS)
        ),
      ]);
      rdapSettled  = { status: "fulfilled", value: rdapVal };
      whoisSettled = whoisGraceResult;
    } else {
      // RDAP failed/empty — start DNS probe NOW so it runs in parallel with WHOIS
      // instead of serially after WHOIS times out (saves up to 5 s on failure path).
      if (isDomainQuery) {
        _earlyDnsProbe = probeDomain(domain).catch(() => undefined);
      }
      const [r, w] = await Promise.allSettled([rdapPromise, whoisPromise]);
      rdapSettled  = { status: "fulfilled", value: rdapVal };
      whoisSettled = w;
      void r; // already settled, just for symmetry
    }
  } else {
    // WHOIS finished first — start DNS probe in parallel with the remaining RDAP wait
    // so we have DNS data ready if RDAP also fails.
    if (isDomainQuery) {
      _earlyDnsProbe = probeDomain(domain).catch(() => undefined);
    }
    const [r, w] = await Promise.allSettled([rdapPromise, whoisPromise]);
    rdapSettled  = r;
    whoisSettled = w;
  }

  const rdapSettledResult = rdapSettled.status === "fulfilled" ? rdapSettled.value : null;
  const rdapData: RdapResponse | null = rdapSettledResult && !("errorCode" in rdapSettledResult) ? rdapSettledResult as RdapResponse : null;
  const whoisData: WhoisRawResult | null = whoisSettled.status === "fulfilled" ? whoisSettled.value : null;
  const whoisError: unknown = whoisSettled.status === "rejected" ? whoisSettled.reason : null;

  // If RDAP explicitly returned "Object Not Found" (HTTP 404), the domain is
  // definitively unregistered — even when WHOIS also returned connection-error
  // text (e.g. "error: getaddrinfo ENOTFOUND whois.nic.google" embedded in the
  // whoiser response body).  This is the authoritative signal for RDAP-only TLDs
  // such as Google-managed .dev, .app, .page, .foo, .zip, .mov whose WHOIS
  // server (whois.nic.google) is not publicly resolvable.  Checking here, before
  // the whoisRawStr block, prevents the WHOIS garbage text from reaching
  // detectWhoisError and masking the real "not registered" outcome.
  const rdapErrorCode = rdapSettledResult && "errorCode" in rdapSettledResult
    ? (rdapSettledResult as { errorCode: number }).errorCode
    : null;
  // RDAP 404 means "domain not found" for TLDs that have an RDAP service
  // (e.g. Google TLDs: .dev, .app, .page).  But for TLDs with NO RDAP service
  // at all (e.g. .im), the IANA bootstrap itself returns 404 — in that case
  // WHOIS may still have valid data.  Only trust the RDAP 404 as definitive
  // when WHOIS also returned nothing useful.
  const whoisHasData = !!(whoisData?.raw?.trim());
  if (rdapErrorCode === 404 && !whoisHasData) {
    const dnsProbe = isDomainQuery
      ? await (_earlyDnsProbe ?? probeDomain(domain)).catch(() => undefined)
      : undefined;
    return {
      time: elapsed(), status: false, cached: false,
      error: "Domain not found",
      dnsProbe: dnsProbe ?? {
        domain, registrationStatus: "unregistered", confidence: "high",
        signals: [], nameservers: [], ipv4: [], ipv6: [], mx: [], hasSsl: null,
      },
    };
  }

  // Step 4: Build result — prefer RDAP, optionally enrich with WHOIS raw text,
  // then fall back to WHOIS-only; if neither succeeded, return error.
  const rdapRaw = rdapData ? JSON.stringify(rdapData, null, 2) : undefined;
  const whoisRawStr = whoisData?.raw || null;

  if (rdapData) {
    try {
      // Reuse the pre-converted RDAP result from the streaming partial if available —
      // avoids a second convertRdapToWhoisResult call (saves 50-200 ms).
      let result = _precomputedRdap ?? await convertRdapToWhoisResult(rdapData, domain);
      // Only use WHOIS raw to enrich the RDAP result when the raw text is
      // genuine WHOIS data — not an IANA bootstrap page and not a detected
      // error (e.g. the "error: getaddrinfo ENOTFOUND" strings that whoiser
      // embeds when it cannot reach the WHOIS server).  Storing error text
      // as rawWhoisContent would pollute the "Raw WHOIS" tab for users.
      if (whoisRawStr && !isIanaFallback(whoisRawStr) && !detectWhoisError(whoisRawStr)) {
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
      recordFailure("iana_fallback", "No WHOIS/RDAP server available for this TLD");
      return failWithDns("No WHOIS/RDAP server available for this TLD");
    }
    if (isWhoisRateLimited(whoisRawStr)) {
      recordFailure("rate_limited");
      return failWithDns("WHOIS server temporarily rate-limited this query — please try again in a moment");
    }
    try {
      const result = await analyzeWhois(whoisRawStr);
      // If analyzeWhois explicitly detected a registry-level domain status
      // (reserved, premium, prohibited, blocked), trust that result even when
      // detectWhoisError() would otherwise classify the response as an error
      // via a broad pattern (e.g., CNNIC "can not be registered online" matches
      // /not registered/i, incorrectly flagging an existing reserved domain as
      // unregistered).
      const hasRegistryStatus = result.status?.some(s =>
        ["registry-reserved", "registry-premium", "prohibited", "registrationProhibited", "blocked"].includes(s.status ?? "")
      );
      if (hasRegistryStatus) {
        // Fill in the domain name from the query if the WHOIS body omitted it
        if (!result.domain) result.domain = rawExtracted;
        if (whoisData?.server) result.whoisServer = pickStr(result.whoisServer, whoisData.server);
        if (rdapRaw) result.rawRdapContent = rdapRaw;
        return { time: elapsed(), status: true, cached: false, source: "whois", result };
      }
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
        recordFailure("parse_error", detectedError || "Empty WHOIS response");
        return failWithDns(detectedError || "Empty WHOIS response");
      }
      if (whoisData?.server) result.whoisServer = pickStr(result.whoisServer, whoisData.server);
      if (rdapRaw) result.rawRdapContent = rdapRaw;
      return { time: elapsed(), status: true, cached: false, source: "whois", result };
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Failed to parse WHOIS response";
      recordFailure("parse_error", msg);
      return failWithDns(msg);
    }
  }

  const whoisMsg = whoisError instanceof Error ? whoisError.message : "";
  const rdapMsg = rdapSettled.status === "rejected" ? (rdapSettled.reason instanceof Error ? rdapSettled.reason.message : "") : "";
  const whoisReturnedEmpty = whoisData !== null && (!whoisData.raw || whoisData.raw.trim().length === 0);

  // Preserve the registryUrl from ScraperRequiredError so the UI can show a
  // "manual lookup" link when automated access is blocked (e.g. .ba).
  const scraperRegistryUrl = whoisError instanceof ScraperRequiredError
    ? whoisError.registryUrl
    : undefined;

  const reason = /timeout|timed.?out/i.test(whoisMsg) ? "timeout" : "no_server";
  const errMsg = /not supported/i.test(whoisMsg)
    ? "WHOIS/RDAP not available for this TLD"
    : /cannot read properties/i.test(whoisMsg) || /cannot read properties/i.test(rdapMsg)
    ? "No WHOIS/RDAP data found for this query"
    : whoisReturnedEmpty && whoisData?.server
    ? `WHOIS server (${whoisData.server}) connected but returned no data — the server may restrict access by IP or require queries from the registry's country`
    : whoisMsg || rdapMsg || "Unknown error occurred";
  recordFailure(reason, errMsg);
  return failWithDns(errMsg, scraperRegistryUrl);
}
