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
 *   1. Try system DNS via dns.promises.resolve4() — zero extra latency.
 *   2. On ENOTFOUND / ESERVFAIL, fall back to Cloudflare DoH (pure HTTPS,
 *      no extra dependencies).
 *   3. Cache successful DoH answers with their DNS TTL (min 60 s, max 1 h).
 *   4. Return the original error if DoH also fails.
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
                _cache.set(host, { ip, expires: Date.now() + ttlMs });
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
 * Returns the original hostname unchanged if it is already an IP address,
 * so callers can pass the result directly to net.connect({ host }).
 *
 * Usage in queryWhoisTcp:
 *   const ip = await resolveWithDohFallback(host);
 *   net.connect({ host: ip, port }, ...)
 */
export async function resolveWithDohFallback(host: string): Promise<string> {
  // Already an IP — nothing to resolve
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) {
    return host;
  }

  // Check DoH cache first (avoid even a system-DNS round-trip on repeated queries)
  const cached = cachedIp(host);
  if (cached) return cached;

  // Try system DNS
  try {
    const addrs = await dns.promises.resolve4(host);
    if (addrs.length > 0) return addrs[0];
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code !== "ENOTFOUND" && code !== "ESERVFAIL" && code !== "EAI_AGAIN") {
      throw err; // propagate unexpected errors (ECONNREFUSED, etc.)
    }
    // Fall through to DoH
  }

  return dohResolve(host);
}
