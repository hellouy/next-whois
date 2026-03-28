/**
 * DNS-over-HTTPS fallback resolver for WHOIS TCP connections.
 *
 * Some ccTLD WHOIS servers have valid A records in global DNS (Google 8.8.8.8,
 * Cloudflare 1.1.1.1) but are unreachable via the system resolver used by
 * cloud providers (Vercel / AWS Lambda).  This happens because the ccTLD's own
 * nameservers are not correctly delegated or reachable from cloud egress IPs.
 *
 * Example: whois.bnnic.bn → 202.152.92.245 resolves fine via Cloudflare DoH,
 * but the system resolver returns ENOTFOUND.  The TCP connection to the resolved
 * IP works perfectly.
 *
 * Strategy:
 *   1. Try system DNS via dns.lookup() (zero latency when it works).
 *   2. On ENOTFOUND only, fall back to Cloudflare DoH (HTTPS, no extra libs).
 *   3. Cache successful DoH answers with their DNS TTL (min 60 s, max 1 h).
 *   4. If DoH also fails (NXDOMAIN / timeout), return the original ENOTFOUND.
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
 * Returns the first A record found, or rejects if none.
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
 * Returns a custom `lookup` function compatible with Node.js `net.connect()`.
 *
 * Usage:
 *   net.connect({ host, port, lookup: makeDnsFallbackLookup() }, onConnect)
 *
 * The returned function first tries the system resolver.  Only on ENOTFOUND
 * does it attempt Cloudflare DoH.  All other errors (ECONNREFUSED, ETIMEDOUT,
 * etc.) are passed through unchanged.
 */
export function makeDnsFallbackLookup(): (
  hostname: string,
  options: dns.LookupOptions,
  callback: (
    err: NodeJS.ErrnoException | null,
    address: string,
    family: number,
  ) => void,
) => void {
  return function dnsWithDohFallback(hostname, _options, callback) {
    dns.lookup(hostname, { family: 4 }, (err, address, family) => {
      if (!err) return callback(null, address as string, family);
      if (err.code !== "ENOTFOUND") return callback(err, "", 0);

      // System DNS returned ENOTFOUND — try Cloudflare DoH before giving up
      dohResolve(hostname)
        .then((ip) => callback(null, ip, 4))
        .catch(() => callback(err, "", 0)); // return the original ENOTFOUND
    });
  };
}
