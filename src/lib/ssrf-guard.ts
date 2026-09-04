import * as dns from "dns";

/**
 * Shared SSRF guard used by /api/http/check and /api/ssl/cert.
 *
 * isPrivateHost: literal classification of a host string (dotted IPv4,
 * IPv6 literal, localhost) against RFC1918/loopback/link-local/CGNAT and
 * other non-routable space. Works on raw hostnames and on addresses
 * returned by DNS resolution.
 */
export function isPrivateHost(host: string): boolean {
  const h = host.toLowerCase();
  const bare = h.startsWith("[") && h.endsWith("]") ? h.slice(1, -1) : h;

  if (bare === "localhost" || bare.endsWith(".localhost")) return true;
  if (bare === "::" || bare === "::1" || bare === "0:0:0:0:0:0:0:1") return true;

  // IPv4-mapped IPv6 (::ffff:127.0.0.1)
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(bare);
  if (mapped) return isPrivateHost(mapped[1]);

  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(bare);
  if (v4) {
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    return (
      a === 0 || // 0.0.0.0/8 "this network"
      a === 10 || // 10.0.0.0/8 private
      (a === 100 && b >= 64 && b <= 127) || // 100.64.0.0/10 CGNAT
      a === 127 || // 127.0.0.0/8 loopback
      (a === 169 && b === 254) || // 169.254.0.0/16 link-local + metadata
      (a === 172 && b >= 16 && b <= 31) || // 172.16.0.0/12 private
      (a === 192 && (b === 168 || b === 0)) || // 192.168/16 + 192.0.0/24 + 192.0.2/24
      (a === 198 && (b === 18 || b === 19)) || // 198.18.0.0/15 benchmark
      (a === 203 && b === 0) || // 203.0.113.0/24 TEST-NET-3
      a >= 224 // multicast (224/4) + reserved (240/4) + broadcast
    );
  }

  // IPv6 literals: unique-local fc00::/7, link-local fe80::/10
  if (/^(fc|fd)[0-9a-f]{2}:/.test(bare)) return true;
  if (/^fe[89ab][0-9a-f]?:/.test(bare)) return true;

  if (/\.local$/i.test(bare)) return true;
  return false;
}

/**
 * Normalize any IPv4 notation (dotted, decimal, hex, octal, mixed) to a
 * dotted-quad string, or null when input is not an IPv4 literal. Closes the
 * integer/hex bypass (e.g. 2130706433 == 127.0.0.1).
 */
export function normalizeIPv4(host: string): string | null {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return host;
  if (/^(0x[0-9a-f]+|\d+)$/i.test(host)) {
    const n = /^0x/i.test(host)
      ? parseInt(host, 16)
      : host.startsWith("0") && host.length > 1
        ? parseInt(host, 8)
        : parseInt(host, 10);
    if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) return null;
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  }
  if (/^(\d+|0x[0-9a-f]+)(\.(\d+|0x[0-9a-f]+)){0,3}$/i.test(host)) {
    const parts = host
      .split(".")
      .map(p =>
        /^0x/i.test(p)
          ? parseInt(p, 16)
          : p.startsWith("0") && p.length > 1
            ? parseInt(p, 8)
            : parseInt(p, 10)
      );
    if (parts.some(p => !Number.isInteger(p) || p < 0 || p > 255)) return null;
    while (parts.length < 4) parts.push(0);
    return parts.join(".");
  }
  return null;
}

/**
 * Full private/internal-address guard: literal check plus DNS resolution so
 * hostnames resolving into private space are rejected before any network
 * connection is opened. Callers must invoke it on the initial target and
 * again on every redirect hop.
 */
export async function isBlockedHost(host: string): Promise<boolean> {
  if (isPrivateHost(host)) return true;
  const ipv4 = normalizeIPv4(host);
  if (ipv4) return isPrivateHost(ipv4);
  try {
    const addrs: { address: string }[] = await dns.promises.lookup(
      host.replace(/^\[|\]$/g, ""),
      { all: true }
    );
    if (!addrs || addrs.length === 0) return false;
    return addrs.some(a => isPrivateHost(a.address));
  } catch {
    return false;
  }
}
