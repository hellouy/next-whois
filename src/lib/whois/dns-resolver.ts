/**
 * DNS-over-HTTPS fallback resolver for WHOIS TCP connections.
 *
 * Some ccTLD WHOIS servers have valid A records in global DNS (Google 8.8.8.8,
 * Cloudflare 1.1.1.1) but are unresolvable via the system resolver used by
 * cloud providers (Vercel / AWS Lambda).  The ccTLD's own nameservers may not
 * be reachable from cloud egress IPs, causing ENOTFOUND even for hosts that
 * are perfectly accessible once you know their IP.
 *
 * Example: whois.bnnic.bn → 202.152.92.245 resolves fine via Cloudflare DoH,
 * but the Vercel system resolver returns ENOTFOUND.  The TCP connection to the
 * resolved IP on port 43 works and returns correct WHOIS data.
 *
 * Strategy:
 *   1. Check in-process cache (zero latency within the same invocation).
 *   2. Check Redis cache (persists across cold starts — avoids DoH round-trip).
 *   3. Try system DNS via dns.promises.resolve4() — zero extra latency.
 *   4. On ENOTFOUND / ESERVFAIL, fall back to Cloudflare DoH (pure HTTPS).
 *   5. Cache successful answers in both Redis and in-process cache.
 *
 * Usage: call resolveWithDohFallback(host) before net.connect() and pass the
 * returned IP as the host.  This avoids Node.js v20 net.connect lookup-option
 * callback quirks entirely.
 */

import * as dns from "dns";
import * as https from "https";

// ── DoH response TTL bounds ───────────────────────────────────────────────────
const MIN_TTL_MS = 60_000;
const MAX_TTL_MS = 3_600_000;
const REDIS_DNS_PREFIX = "dns:v4:";
// Store in Redis for up to 1 hour regardless of DNS TTL (WHOIS server IPs are stable)
const REDIS_DNS_TTL_S = 3_600;

interface CacheEntry {
  ip: string;
  expires: number;
}

const _cache = new Map<string, CacheEntry>();

function cachedIp(host: string): string | null {
  const entry = _cache.get(host);
  if (entry && entry.expires > Date.now()) return entry.ip;
  _cache.delete(host);
  return null;
}

function setCached(host: string, ip: string, ttlMs: number) {
  _cache.set(host, { ip, expires: Date.now() + ttlMs });
}

// ── Redis-backed DNS cache (persists across cold starts) ──────────────────────
async function redisGetDns(host: string): Promise<string | null> {
  try {
    const { redis, isRedisAvailable } = await import("@/lib/server/redis");
    if (!isRedisAvailable() || !redis) return null;
    const val = await redis.get(REDIS_DNS_PREFIX + host);
    return val || null;
  } catch {
    return null;
  }
}

async function redisSetDns(host: string, ip: string): Promise<void> {
  try {
    const { redis, isRedisAvailable } = await import("@/lib/server/redis");
    if (!isRedisAvailable() || !redis) return;
    await redis.set(REDIS_DNS_PREFIX + host, ip, "EX", REDIS_DNS_TTL_S);
  } catch {
    // ignore
  }
}

/**
 * Resolve a hostname to an IPv4 address using Cloudflare DNS-over-HTTPS.
 * Returns the first A record found, or rejects if NXDOMAIN / timeout.
 */
function dohResolve(host: string): Promise<string> {
  const cached = cachedIp(host);
  if (cached) return Promise.resolve(cached);

  return new Promise<string>((resolve, reject) => {
    const url =
      "https://cloudflare-dns.com/dns-query?name=" +
      encodeURIComponent(host) +
      "&type=A";

    const req = https.get(
      url,
      { headers: { Accept: "application/dns-json" }, timeout: 6_000 },
      (res) => {
        let raw = "";
        res.on("data", (c: Buffer) => (raw += c.toString()));
        res.on("end", () => {
          try {
            const j = JSON.parse(raw) as {
              Status: number;
              Answer?: Array<{ type: number; data: string; TTL: number }>;
            };
            if (j.Status === 0 && j.Answer) {
              const aRecords = j.Answer.filter((a) => a.type === 1);
              if (aRecords.length > 0) {
                const ttlMs = Math.min(
                  Math.max((aRecords[0].TTL ?? 300) * 1_000, MIN_TTL_MS),
                  MAX_TTL_MS,
                );
                const ip = aRecords[0].data;
                setCached(host, ip, ttlMs);
                return resolve(ip);
              }
            }
            reject(new Error("DoH NXDOMAIN: " + host));
          } catch (e) {
            reject(e);
          }
        });
      },
    );

    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("DoH timeout: " + host));
    });
  });
}

/**
 * Resolves a hostname to an IPv4 address, using Cloudflare DoH as a fallback
 * when the system resolver returns ENOTFOUND or ESERVFAIL.
 *
 * Resolution order:
 *   1. In-process memory cache (zero latency)
 *   2. Redis cache (persists across cold starts)
 *   3. System DNS resolver
 *   4. Cloudflare DoH
 *
 * Returns the original hostname unchanged if it is already an IP address,
 * so callers can pass the result directly to net.connect({ host }).
 */
export async function resolveWithDohFallback(host: string): Promise<string> {
  // Already an IP — nothing to resolve
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) {
    return host;
  }

  // 1. In-process cache (zero latency within the same invocation)
  const memHit = cachedIp(host);
  if (memHit) return memHit;

  // 2. Redis cache (survives cold starts)
  const redisHit = await redisGetDns(host);
  if (redisHit) {
    setCached(host, redisHit, MAX_TTL_MS);
    return redisHit;
  }

  // 3. System DNS
  try {
    const addrs = await dns.promises.resolve4(host);
    if (addrs.length > 0) {
      const ip = addrs[0];
      setCached(host, ip, MIN_TTL_MS * 5);
      redisSetDns(host, ip).catch(() => {});
      return ip;
    }
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "ENOTFOUND" && code !== "ESERVFAIL" && code !== "EAI_AGAIN") {
      throw err; // propagate unexpected errors (ECONNREFUSED, etc.)
    }
    // Fall through to DoH
  }

  // 4. Cloudflare DoH fallback
  const ip = await dohResolve(host);
  redisSetDns(host, ip).catch(() => {});
  return ip;
}

/**
 * Pre-warm DNS cache for a list of well-known WHOIS server hostnames.
 * Called at module load so the first real request hits the cache.
 * Failures are silently ignored — warmup is best-effort.
 */
export function warmupDnsCache(hosts: string[]): void {
  for (const host of hosts) {
    resolveWithDohFallback(host).catch(() => {});
  }
}
