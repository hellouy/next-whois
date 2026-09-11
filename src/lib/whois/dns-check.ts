import dns from "dns/promises";
import https from "https";
import { domainToASCII } from "url";
import { extractDomain } from "@/lib/utils";

export type DnsParkingInfo = {
  isParked: boolean;
  provider: string | null;
};

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
  /** Detected domain-parking / aftermarket-listing platform via NS records. */
  parking?: DnsParkingInfo;
};

export type DnsSignal = {
  type: string;
  value: string;
  label: string;
};

const DNS_TIMEOUT_MS = 5000;

/** Shorter timeout for the batch fast-probe path (see probeDomainFast). */
const DNS_FAST_TIMEOUT_MS = 2500;

/**
 * Authoritative nameserver suffixes of well-known domain parking / aftermarket
 * listing platforms. A domain whose NS points to one of these is very likely
 * parked or listed for sale (i.e. a "premium" aftermarket name).
 *
 * `domaincontrol.com` is deliberately excluded: it is GoDaddy's generic DNS
 * hosting and is used by countless normal, non-parked websites.
 */
const PARKING_NS_MAP: Array<{ provider: string; suffixes: string[] }> = [
  { provider: "Sedo", suffixes: ["sedoparking.com", "sedo.com"] },
  { provider: "Afternic", suffixes: ["afternic.com"] },
  { provider: "BuyDomains", suffixes: ["buydomains.com"] },
  { provider: "Bodis", suffixes: ["bodis.com"] },
  { provider: "ParkingCrew", suffixes: ["parkingcrew.net"] },
  { provider: "HugeDomains", suffixes: ["hugedomains.com"] },
  { provider: "Dan.com", suffixes: ["dan.com"] },
  { provider: "Above.com", suffixes: ["above.com"] },
  { provider: "ParkLogic", suffixes: ["parklogic.com"] },
  { provider: "DomainSponsor", suffixes: ["domainsponsor.com"] },
];

/**
 * Match a list of nameserver hostnames against the parking platform map.
 * Returns the provider name if any NS matches, otherwise null.
 */
export function detectParkingProvider(nameservers: string[]): string | null {
  if (!nameservers || nameservers.length === 0) return null;
  const lower = nameservers.map((ns) => ns.toLowerCase().trim());
  for (const entry of PARKING_NS_MAP) {
    for (const suffix of entry.suffixes) {
      const matched = lower.some(
        (ns) => ns === suffix || ns.endsWith(`.${suffix}`),
      );
      if (matched) return entry.provider;
    }
  }
  return null;
}

/**
 * Wraps a DNS lookup promise with a timeout.
 *
 * Returns:
 *  - The resolved value on success
 *  - An empty array on definitive "no records" answers (ENOTFOUND = NXDOMAIN,
 *    ENODATA = domain exists but no records of this type) — these mean the
 *    queried record type genuinely doesn't exist.
 *  - null on anything ambiguous: timeouts, network errors, ESERVFAIL, EREFUSED,
 *    etc. ESERVFAIL is a temporary resolver/registry failure, NOT a "no
 *    records" answer — treating it as "domain unregistered" would mis-report a
 *    transient DNS hiccup as a registrable domain.
 *
 * This distinction is critical: NXDOMAIN (domain doesn't exist) must not be
 * treated the same as a timeout (DNS unreachable) — the former means the domain
 * is unregistered, the latter means we have no information.
 */
function withDnsTimeout<T extends unknown[]>(promise: Promise<T>): Promise<T | null> {
  return withDnsTimeoutMs(promise, DNS_TIMEOUT_MS);
}

/**
 * Same semantics as withDnsTimeout but with a configurable timeout budget.
 * Used by probeDomainFast so the batch path can finish faster than the
 * single-query probe (which also runs an SSL handshake that we skip here).
 */
function withDnsTimeoutMs<T extends unknown[]>(promise: Promise<T>, timeoutMs: number): Promise<T | null> {
  return Promise.race([
    promise.catch((e) => {
      const code = (e as NodeJS.ErrnoException)?.code ?? "";
      // Definitive DNS answers: domain doesn't exist or has no records of this type.
      // Return an empty array so the caller knows we got a real response.
      if (
        code === "ENOTFOUND" ||  // NXDOMAIN — domain doesn't exist
        code === "ENODATA"       // Domain exists but no records of this type
      ) {
        return [] as unknown as T;
      }
      // Everything else (ESERVFAIL = resolver/registry error, ETIMEOUT,
      // ECONNREFUSED, etc.) → treat as no info, never as a definitive answer.
      return null;
    }),
    new Promise<null>((resolve) => setTimeout(() => resolve(null), timeoutMs)),
  ]);
}

async function checkSsl(domain: string): Promise<boolean> {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => resolve(false), 2000);
    const req = https.request(
      { hostname: domain, port: 443, method: "HEAD", path: "/", timeout: 1500 },
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

  const parkingProvider = detectParkingProvider(nameservers);

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
    parking: {
      isParked: parkingProvider !== null,
      provider: parkingProvider,
    },
  };
}

/**
 * Lightweight DNS probe result used by the batch availability path
 * (`lookupBatchAvailability`). Unlike `DnsProbeResult` it omits the SSL
 * handshake (slow, unreliable on bulk queries) and the per-signal breakdown,
 * but adds the wildcard-A verdict used to avoid mistaking an unregistered
 * domain that the registry answers with a wildcard record for a registered one.
 */
export type FastProbeResult = {
  domain: string;
  registrationStatus: "registered" | "unregistered" | "unknown";
  confidence: "high" | "medium" | "low";
  nameservers: string[];
  ipv4: string[];
  ipv6: string[];
  mx: string[];
  /** True when the registry answers arbitrary subdomains with the same A/AAAA records. */
  isWildcardA: boolean;
  /** NS points to a known parking / aftermarket platform. */
  parked: boolean;
  parkingProvider: string | null;
  allTimedOut: boolean;
};

/**
 * Detect whether the TLD registry answers ANY subdomain with the same A/AAAA
 * records as the queried domain (wildcard DNS). This is the tell-tale sign of
 * a registry that synthesizes answers for unregistered names — a domain whose
 * NS is empty but whose A record is really a wildcard must NOT be treated as
 * "registered" based on that A record alone.
 *
 * We resolve a random subdomain `{random}.{domain}` and compare its A/AAAA
 * addresses against the target's. If they overlap non-empty, the TLD is
 * serving wildcard answers. Returns false on timeout / resolver errors / when
 * the random subdomain has no records — in all those cases we simply have no
 * wildcard evidence.
 */
export async function detectWildcardA(domain: string): Promise<boolean> {
  const randomLabel = `w${Math.random().toString(36).slice(2, 10)}`;
  const probeSub = toAsciiForDns(`${randomLabel}.${extractDomain(domain) || domain}`);

  const [target4, target6] = await Promise.all([
    withDnsTimeoutMs(dns.resolve4(domain), DNS_FAST_TIMEOUT_MS),
    withDnsTimeoutMs(dns.resolve6(domain), DNS_FAST_TIMEOUT_MS),
  ]);
  const t4 = (target4 ?? []).filter(Boolean);
  const t6 = (target6 ?? []).filter(Boolean);
  if (t4.length === 0 && t6.length === 0) return false;

  const [sub4, sub6] = await Promise.all([
    withDnsTimeoutMs(dns.resolve4(probeSub), DNS_FAST_TIMEOUT_MS),
    withDnsTimeoutMs(dns.resolve6(probeSub), DNS_FAST_TIMEOUT_MS),
  ]);
  const s4 = (sub4 ?? []).filter(Boolean);
  const s6 = (sub6 ?? []).filter(Boolean);

  // Overlap check: the random subdomain must answer with at least one address
  // that the target also has. Identical sets → classic wildcard. Partial
  // overlap also counts (some registries rotate a pool of wildcard IPs).
  const overlap4 = s4.length > 0 && t4.some((ip) => s4.includes(ip));
  const overlap6 = s6.length > 0 && t6.some((ip) => s6.includes(ip));
  return overlap4 || overlap6;
}

/**
 * Fast DNS probe for the batch availability path. Parallel NS/A/AAAA/MX with a
 * 2.5s timeout (vs 5s + SSL for the single-query `probeDomain`). The caller
 * combines its verdict with RDAP/WHOIS fallback (see lookupBatchAvailability).
 */
export async function probeDomainFast(input: string): Promise<FastProbeResult> {
  const extracted = extractDomain(input) || input;
  const domain = toAsciiForDns(extracted);

  const [nsResult, aResult, aaaaResult, mxResult] = await Promise.all([
    withDnsTimeoutMs(dns.resolveNs(domain), DNS_FAST_TIMEOUT_MS),
    withDnsTimeoutMs(dns.resolve4(domain), DNS_FAST_TIMEOUT_MS),
    withDnsTimeoutMs(dns.resolve6(domain), DNS_FAST_TIMEOUT_MS),
    withDnsTimeoutMs(dns.resolveMx(domain), DNS_FAST_TIMEOUT_MS),
  ]);

  const nsTimedOut   = nsResult   === null;
  const aTimedOut    = aResult    === null;
  const aaaaTimedOut = aaaaResult === null;
  const mxTimedOut   = mxResult   === null;
  const allTimedOut  = nsTimedOut && aTimedOut && aaaaTimedOut && mxTimedOut;

  const nameservers = nsResult ?? [];
  const ipv4 = aResult ?? [];
  const ipv6 = aaaaResult ?? [];
  const mx = mxResult ? mxResult.map((r) => r.exchange) : [];

  const hasNs = nameservers.length > 0;
  const hasAOrAaaa = ipv4.length > 0 || ipv6.length > 0;
  const hasMx = mx.length > 0;
  const hasAny = hasNs || hasAOrAaaa || hasMx;

  // A/AAAA/MX without any NS is ambiguous: it could be a live registered site
  // whose NS lookup failed, or — far more common on bulk checks — a wildcard
  // answer from a registry that synthesizes records for unregistered names.
  let isWildcardA = false;
  if (!hasNs && hasAOrAaaa) {
    isWildcardA = await detectWildcardA(domain).catch(() => false);
  }

  let registrationStatus: FastProbeResult["registrationStatus"] = "unknown";
  let confidence: FastProbeResult["confidence"] = "low";

  if (hasNs) {
    // NS records are the most authoritative signal: domain is definitely registered
    registrationStatus = "registered";
    confidence = "high";
  } else if (!isWildcardA && (hasAOrAaaa || hasMx)) {
    // Real A/AAAA/MX with no wildcard evidence → domain appears active.
    registrationStatus = "registered";
    confidence = "medium";
  } else if (!allTimedOut) {
    // At least one lookup returned a real answer (empty = NXDOMAIN / ENODATA),
    // or the records we saw are wildcard noise → no evidence of registration.
    registrationStatus = "unregistered";
    confidence = isWildcardA ? "low" : "medium";
  }
  // If allTimedOut: no information — keep "unknown".

  const parkingProvider = detectParkingProvider(nameservers);

  return {
    domain,
    registrationStatus,
    confidence,
    nameservers,
    ipv4,
    ipv6,
    mx,
    isWildcardA,
    parked: parkingProvider !== null,
    parkingProvider,
    allTimedOut,
  };
}
