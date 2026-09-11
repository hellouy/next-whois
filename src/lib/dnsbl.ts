// DNSBL (DNS-based Blackhole List) checking for IPv4 addresses.
// Uses public, free DNSBL zones; queries are plain DNS lookups only.

import dns from "dns/promises";

export const DNSBL_ZONES = [
  "zen.spamhaus.org",
  "sbl.spamhaus.org",
  "xbl.spamhaus.org",
  "pbl.spamhaus.org",
  "b.barracudacentral.org",
  "bl.spamcop.net",
  "dnsbl.sorbs.net",
  "spam.dnsbl.sorbs.net",
  "dnsbl.abuse.ch",
] as const;

export type DnsblResult = {
  zone: string;
  listed: boolean;
  returnCode: string | null;
  type: string | null;
  latencyMs: number;
};

export const DNSBL_TIMEOUT_MS = 3000;
export const DNSBL_CONCURRENCY = 4;

// Reverse an IPv4 octet string: "1.2.3.4" -> "4.3.2.1"
export function reverseIpv4(ip: string): string {
  return ip.split(".").reverse().join(".");
}

// Map a 127.x return code to a human-readable category.
export function classifyReturnCode(code: string): string | null {
  const normalized = code.replace(/^127\.0\.0\./, "");
  switch (normalized) {
    case "2":  return "spam";
    case "3":  return "zombie";
    case "4":  return "open_proxy";
    case "5":  return "open_relay";
    case "6":  return "exploitable";
    case "7":  return "hijacked";
    case "8":  return "dialup";
    case "9":  return "abuse";
    case "10": return "dynamic";
    case "11": return "onion";
    case "12": return "tor";
    case "13": return "tor";
    case "14": return "open_resolver";
    default:   return null;
  }
}

async function checkZone(ip: string, zone: string): Promise<DnsblResult> {
  const t0 = Date.now();
  const reversed = reverseIpv4(ip);
  const hostname = `${reversed}.${zone}`;
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("DNSBL_TIMEOUT")), DNSBL_TIMEOUT_MS);
  });
  try {
    const addresses = await Promise.race([dns.resolve4(hostname, { ttl: true }), timeout]);
    const latencyMs = Date.now() - t0;
    if (addresses.length > 0) {
      const code = String(addresses[0].address);
      return { zone, listed: true, returnCode: code, type: classifyReturnCode(code), latencyMs };
    }
    return { zone, listed: false, returnCode: null, type: null, latencyMs };
  } catch {
    // NXDOMAIN (not listed) or timeout/network error → treat as not listed
    return { zone, listed: false, returnCode: null, type: null, latencyMs: Date.now() - t0 };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function checkDnsbl(ip: string, zones: readonly string[] = DNSBL_ZONES): Promise<DnsblResult[]> {
  const results: DnsblResult[] = [];
  for (let i = 0; i < zones.length; i += DNSBL_CONCURRENCY) {
    const batch = zones.slice(i, i + DNSBL_CONCURRENCY);
    const settled = await Promise.allSettled(batch.map(zone => checkZone(ip, zone)));
    settled.forEach((s, idx) => {
      results.push(s.status === "fulfilled" ? s.value : { zone: batch[idx], listed: false, returnCode: null, type: null, latencyMs: DNSBL_TIMEOUT_MS });
    });
  }
  return results;
}
