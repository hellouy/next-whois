import { lookupWhoisWithCache } from "@/lib/whois/lookup";
import { probeDomain, type DnsProbeResult } from "@/lib/whois/dns-check";
import { isNotRegisteredWhoisResponse } from "@/lib/whois/whois-patterns";
import { createLogger } from "@/lib/logger";

const logger = createLogger("server/release-confirm");

/**
 * Result of a multi-source domain-release verification.
 *
 * `released` is only true when ALL independent sources agree the name is gone:
 *   1. a live, uncached registry lookup reports "not found",
 *   2. an independent DNS probe cannot resolve ANY record for the name,
 *   3. a second registry lookup (run after a short delay) again reports not found.
 *
 * Failing any single source means the domain is STILL OCCUPIED (e.g. a registry
 * hold that outlasts the date-based drop estimate) or the data is inconclusive —
 * in both cases we must NOT tell the user the name is available.
 */
export type ReleaseConfirmation = {
  released: boolean;
  reason: string;
  /** Registry status objects from the first live lookup (empty when none). */
  eppStatuses: string[];
};

/** Single, bounded, uncached registry lookup for a domain. */
async function boundedLookup(domain: string, timeoutMs = 9000): Promise<Awaited<ReturnType<typeof lookupWhoisWithCache>> | null> {
  return Promise.race([
    lookupWhoisWithCache(domain, { nocache: true }).catch(() => null),
    new Promise<null>((resolve) => setTimeout(() => resolve(null), timeoutMs)),
  ]);
}

function extractEppStatuses(r: Awaited<ReturnType<typeof lookupWhoisWithCache>> | null): string[] {
  return Array.isArray(r?.result?.status)
    ? r!.result!.status!.map((s: { status?: string }) => s.status ?? "").filter(Boolean)
    : [];
}

/**
 * Registry side considers the name free iff an uncached lookup came back with
 * no registration result and an explicit "not registered" WHOIS signal.
 * A lookup error mentioning the word "not found" alone is NOT enough — the
 * message must be a genuine registry not-registered pattern.
 */
function registryReportsFree(r: Awaited<ReturnType<typeof lookupWhoisWithCache>> | null): boolean {
  return Boolean(
    r &&
    r.status === false &&
    !r.result &&
    isNotRegisteredWhoisResponse(r.error ?? ""),
  );
}

/**
 * DNS side independently confirms the name no longer resolves. Uses the deep
 * probe (joinable every plausible DNS signal) and treats a hard NXDOMAIN /
 * empty answer as unregistered — a timed-out probe is inconclusive and must
 * NOT be treated as "released".
 */
async function dnsReportsFree(domain: string): Promise<{ free: boolean; probe?: DnsProbeResult | null }> {
  const probe = await Promise.race([
    probeDomain(domain).catch(() => null),
    new Promise<null>((resolve) => setTimeout(() => resolve(null), 5000)),
  ]);
  if (!probe) return { free: false };
  return { free: probe.registrationStatus === "unregistered", probe };
}

/**
 * Three-source verification that a domain is genuinely available again.
 * Throws on unexpected internal errors so the caller can fail-conservative and
 * keep treating the domain as occupied.
 */
export async function confirmDomainReleased(domain: string): Promise<ReleaseConfirmation> {
  // Source 1 — live registry (uncached)
  const first = await boundedLookup(domain);
  const firstEpp = extractEppStatuses(first);
  if (!registryReportsFree(first)) {
    return {
      released: false,
      reason: first
        ? (first.result ? "registry still reports registration data" : "registry lookup not definitively free")
        : "registry lookup timed out",
      eppStatuses: firstEpp,
    };
  }

  // Source 2 — independent DNS probe
  const dns = await dnsReportsFree(domain);
  if (!dns.free) {
    return {
      released: false,
      reason: dns.probe
        ? `DNS still resolves the name (${dns.probe.registrationStatus})`
        : "DNS probe timed out",
      eppStatuses: firstEpp,
    };
  }

  // Source 3 — second registry lookup after a short delay, to rule out a
  // transient registry-side blip on the first query.
  await new Promise((r) => setTimeout(r, 1500));
  const second = await boundedLookup(domain);
  const secondEpp = extractEppStatuses(second);
  if (!registryReportsFree(second)) {
    return {
      released: false,
      reason: "second registry lookup did not confirm release",
      eppStatuses: secondEpp.length ? secondEpp : firstEpp,
    };
  }

  logger.info(`[release-confirm] ${domain} confirmed released across registry ×2 + DNS`);
  return { released: true, reason: "registry ×2 + DNS all report the name is free", eppStatuses: [] };
}