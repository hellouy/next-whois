import { MAX_WHOIS_FOLLOW, LOOKUP_TIMEOUT } from "@/lib/env";
import { WhoisResult, WhoisRawResult, WhoisAnalyzeResult } from "@/lib/whois/types";
import {
  getJsonRedisValueWithTtl,
  setJsonRedisValue,
  isRedisAvailable,
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
import { recordTldLookupFailure } from "@/lib/db";

warmupDnsCache([
  // gTLD / IANA / RIR
  "whois.verisign-grs.com", "whois.pir.org", "whois.iana.org",
  "whois.afilias.net", "whois.apnic.net",
  "whois.arin.net", "whois.ripe.net", "whois.lacnic.net", "whois.afrinic.net",
  // High-traffic ccTLD WHOIS servers
  "whois.nic.hu", "whois.jprs.jp", "whois.registro.br",
  "whois.nic.fr", "whois.denic.de", "whois.nic.uk",
  "whois.cnnic.cn", "whois.nic.it", "whois.tcinet.ru",
  "whois.dns.pl", "whois.dnsbelgium.be", "whois.domreg.lt",
  "whois.nic.au", "whois.srs.net.nz", "whois.teleinfo.cn",
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
    const l1Hit = l1Get(key);
    if (l1Hit) {
      // Compute remaining TTL locally — avoids an extra Redis round-trip on every
      // L1 cache hit. The result is accurate to within the L1 TTL window (30 s).
      const remainingTtl = l1ComputeRemainingTtl(l1Hit);
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
    if (isRedisAvailable()) {
      const l2 = await getJsonRedisValueWithTtl<WhoisResult>(key);
      if (l2) {
        l1Set(key, l2.value);
        const r = { ...l2.value, time: 0, cached: true, cacheTtl: l2.remainingTtl ?? l2.value.cacheTtl };
        // Same reasoning as L1: cache hits skip partial notification.
        return r;
      }
    }
  }

  let result = await lookupWhoisStreaming(domain, onPartialResult);
  // Retry once on transient failures (same logic as lookupWhoisWithCache).
  // Pass onPartialResult to the retry so that if RDAP succeeds on the second
  // attempt the partial result is streamed immediately (clears the loading
  // skeleton at ~RDAP_TIMEOUT rather than waiting the full retry duration).
  if (isTransientLookupFailure(result)) {
    await new Promise((r) => setTimeout(r, 250));
    const retried = await lookupWhoisStreaming(domain, onPartialResult);
    if (retried.status) result = retried;
  }
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

/**
 * Core streaming lookup — fires RDAP + WHOIS in parallel.
 * When RDAP resolves first with good data, `onPartialResult` is called
 * immediately with an RDAP-only result so the caller can stream it to the
 * client. The function then waits for WHOIS enrichment (short grace period)
 * before returning the fully merged final result.
 */
async function lookupWhoisStreaming(
  domain: string,
  onPartialResult?: (partial: WhoisResult) => void,
): Promise<WhoisResult> {
  return lookupWhois(domain, onPartialResult);
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

  // Grace period (ms) WHOIS gets to complete after RDAP already succeeded.
  // Reduced from 1200 → 900 ms: 900 ms is enough for most WHOIS servers to
  // respond while showing the final merged result ~300 ms sooner.
  const RDAP_WIN_WHOIS_GRACE_MS = 900;

  // Start RDAP + WHOIS in parallel.
  const rdapPromise = withTimeout(lookupRdap(domain), RDAP_TIMEOUT) as Promise<RdapResult>;
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
  // Step 4: Build result — prefer RDAP, optionally enrich with WHOIS raw text,
  // then fall back to WHOIS-only; if neither succeeded, return error.
  const rdapRaw = rdapData ? JSON.stringify(rdapData, null, 2) : undefined;
  const whoisRawStr = whoisData?.raw || null;

  if (rdapData) {
    try {
      // Reuse the pre-converted RDAP result from the streaming partial if available —
      // avoids a second convertRdapToWhoisResult call (saves 50-200 ms).
      let result = _precomputedRdap ?? await convertRdapToWhoisResult(rdapData, domain);
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
      recordFailure("iana_fallback", "No WHOIS/RDAP server available for this TLD");
      return failWithDns("No WHOIS/RDAP server available for this TLD");
    }
    if (isWhoisRateLimited(whoisRawStr)) {
      recordFailure("rate_limited");
      return failWithDns("WHOIS 服务器临时限制了本次查询速率，请稍后再试");
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

  const reason = /timeout|timed.?out/i.test(whoisMsg) ? "timeout"
    : /not supported|no.*server|no public/i.test(whoisMsg) ? "no_server"
    : "no_server";
  const errMsg = /not supported/i.test(whoisMsg)
    ? "WHOIS/RDAP not available for this TLD"
    : /cannot read properties/i.test(whoisMsg) || /cannot read properties/i.test(rdapMsg)
    ? "No WHOIS/RDAP data found for this query"
    : whoisReturnedEmpty && whoisData?.server
    ? `WHOIS server (${whoisData.server}) connected but returned no data — the server may restrict access by IP or require queries from the registry's country`
    : whoisMsg || rdapMsg || "Unknown error occurred";
  recordFailure(reason, errMsg);
  return failWithDns(errMsg);
}
