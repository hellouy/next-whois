import dns from "dns/promises";
import https from "https";
import { domainToASCII } from "url";
import { extractDomain } from "@/lib/utils";

export type DnsProbeResult = {
  domain: string;
  registrationStatus: "registered" | "unregistered" | "unknown";
  confidence: "high" | "medium" | "low";
  signals: DnsSignal[];
  nameservers: string[];
  ipv4: string[];
  ipv6: string[];
  mx: string[];
  hasSsl: boolean | null;
};

export type DnsSignal = {
  type: string;
  value: string;
  label: string;
};

const DNS_TIMEOUT_MS = 5000;

/**
 * Wraps a DNS lookup promise with a timeout.
 *
 * Returns:
 *  - The resolved value on success
 *  - An empty array on DNS errors (ENOTFOUND = NXDOMAIN, ENODATA = no records of
 *    this type, ESERVFAIL = registry error) — these are definitive "no records"
 *    answers, distinct from a timeout.
 *  - null on actual network timeout (DNS server unreachable / no response)
 *
 * This distinction is critical: NXDOMAIN (domain doesn't exist) must not be
 * treated the same as a timeout (DNS unreachable) — the former means the domain
 * is unregistered, the latter means we have no information.
 */
function withDnsTimeout<T extends unknown[]>(promise: Promise<T>): Promise<T | null> {
  return Promise.race([
    promise.catch((e) => {
      const code = (e as NodeJS.ErrnoException)?.code ?? "";
      // Definitive DNS answers: domain doesn't exist or has no records of this type.
      // Return an empty array so the caller knows we got a real response.
      if (
        code === "ENOTFOUND" ||  // NXDOMAIN — domain doesn't exist
        code === "ENODATA"  ||  // Domain exists but no records of this type
        code === "ESERVFAIL"    // Registry/resolver error — treat as no data
      ) {
        return [] as unknown as T;
      }
      // Everything else (ETIMEOUT, ECONNREFUSED, etc.) → treat as timeout / no info
      return null;
    }),
    new Promise<null>((resolve) => setTimeout(() => resolve(null), DNS_TIMEOUT_MS)),
  ]);
}

async function checkSsl(domain: string): Promise<boolean> {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(false), 4000);
    const req = https.request(
      { hostname: domain, port: 443, method: "HEAD", path: "/", timeout: 3500 },
      () => {
        clearTimeout(timeout);
        resolve(true);
      },
    );
    req.on("error", () => {
      clearTimeout(timeout);
      resolve(false);
    });
    req.on("timeout", () => {
      clearTimeout(timeout);
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}

function toAsciiForDns(input: string): string {
  if (!/[^\x00-\x7F]/.test(input)) return input;
  try {
    const ascii = domainToASCII(input.toLowerCase());
    if (ascii && !ascii.includes("\u0000")) return ascii;
  } catch {}
  return input;
}

export async function probeDomain(input: string): Promise<DnsProbeResult> {
  const extracted = extractDomain(input) || input;
  const domain = toAsciiForDns(extracted);

  const [nsResult, aResult, aaaaResult, mxResult] = await Promise.all([
    withDnsTimeout(dns.resolveNs(domain)),
    withDnsTimeout(dns.resolve4(domain)),
    withDnsTimeout(dns.resolve6(domain)),
    withDnsTimeout(dns.resolveMx(domain)),
  ]);

  // Track whether each lookup actually responded (null = timed out / failed).
  // We distinguish "server said NXDOMAIN / empty" (returned []) from "no response
  // at all" (returned null after timeout) to avoid false "unregistered" results
  // when DNS is unreachable from this infrastructure.
  const nsTimedOut   = nsResult   === null;
  const aTimedOut    = aResult    === null;
  const aaaaTimedOut = aaaaResult === null;
  const mxTimedOut   = mxResult   === null;
  const allTimedOut  = nsTimedOut && aTimedOut && aaaaTimedOut && mxTimedOut;

  const nameservers = nsResult ?? [];
  const ipv4 = aResult ?? [];
  const ipv6 = aaaaResult ?? [];
  const mx = mxResult ? mxResult.map((r) => r.exchange) : [];

  const hasAny = nameservers.length > 0 || ipv4.length > 0 || ipv6.length > 0 || mx.length > 0;

  let hasSsl: boolean | null = null;
  if (ipv4.length > 0 || ipv6.length > 0) {
    hasSsl = await checkSsl(domain);
  }

  const signals: DnsSignal[] = [];
  if (nameservers.length > 0) {
    signals.push({ type: "NS", value: nameservers[0], label: `NS: ${nameservers.slice(0, 2).join(", ")}` });
  }
  if (ipv4.length > 0) {
    signals.push({ type: "A", value: ipv4[0], label: `A: ${ipv4.slice(0, 2).join(", ")}` });
  }
  if (ipv6.length > 0) {
    signals.push({ type: "AAAA", value: ipv6[0], label: `AAAA: ${ipv6[0]}` });
  }
  if (mx.length > 0) {
    signals.push({ type: "MX", value: mx[0], label: `MX: ${mx.slice(0, 2).join(", ")}` });
  }
  if (hasSsl !== null) {
    signals.push({ type: "SSL", value: String(hasSsl), label: hasSsl ? "SSL: Certificate valid" : "SSL: No response" });
  }

  let registrationStatus: DnsProbeResult["registrationStatus"] = "unknown";
  let confidence: DnsProbeResult["confidence"] = "low";

  if (nameservers.length > 0) {
    // NS records are the most authoritative signal: domain is definitely registered
    registrationStatus = "registered";
    confidence = "high";
  } else if (ipv4.length > 0 || ipv6.length > 0 || mx.length > 0) {
    // A/AAAA/MX records without NS: domain appears active even if NS lookup failed
    registrationStatus = "registered";
    confidence = "medium";
  } else if (!allTimedOut) {
    // At least one lookup returned an actual response (empty = NXDOMAIN).
    // This is meaningfully different from a timeout: we got a real DNS answer
    // saying the domain has no records, which suggests it is unregistered.
    registrationStatus = "unregistered";
    confidence = "medium";
  }
  // If allTimedOut: all DNS queries timed out — we have no evidence either way.
  // Keep registrationStatus = "unknown" so the UI shows "查询失败" rather than
  // incorrectly reporting the domain as available / unregistered.

  return {
    domain,
    registrationStatus,
    confidence,
    signals,
    nameservers,
    ipv4,
    ipv6,
    mx,
    hasSsl,
  };
}
