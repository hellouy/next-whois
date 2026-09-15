import { lookupWhoisWithCache } from "@/lib/whois/lookup";
import { isNotRegisteredWhoisResponse } from "@/lib/whois/whois-patterns";
import { createLogger } from "@/lib/logger";

const logger = createLogger("server/subscription-live");

/**
 * Live availability re-check for the subscriptions dashboard.
 *
 * The date-based lifecycle is estimated from the registry TLD config and the
 * LAST synced expiry/EPP snapshot — a name can pass its estimated drop date yet
 * still be occupied (Registry Hold) or get registered by someone else after a
 * real release. Before the UI shows "released / now available" it must confirm
 * against a live, uncached registry lookup whether registration data still
 * exists for the name.
 *
 * live: null        — subscription is in-range; no live re-check needed
 *       "released"  — registry no longer returns registration data (genuinely free)
 *       "occupied"  — registry still returns a registration object (still held)
 *       "re_registered" — was released earlier and is now occupied by someone else
 *       "unknown"   — lookup errored/timed out; keep conservatively occupied
 */
export type LiveStatus = "released" | "occupied" | "re_registered" | "unknown";

export type LiveCheck = {
  live: LiveStatus | null;
  eppStatuses: string[];
  recheckedAt: string | null;
};

const THROTTLE_MS = 60_000;
const LOOKUP_TIMEOUT_MS = 8_000;

// Per-process throttle so the dashboard + subscriptions API don't hammer the
// same domain in back-to-back requests (the combine/GET paths run in parallel).
const recentChecks = new Map<string, { live: LiveStatus; eppStatuses: string[]; at: number }>();

function extractEpp(res: Awaited<ReturnType<typeof lookupWhoisWithCache>> | null): string[] {
  if (!res?.result?.status) return [];
  return res.result.status
    .map((s) => (s as { status?: string }).status ?? "")
    .filter(Boolean);
}

async function liveLookup(domain: string): Promise<Awaited<ReturnType<typeof lookupWhoisWithCache>> | null> {
  return Promise.race([
    lookupWhoisWithCache(domain, { nocache: true }).catch(() => null),
    new Promise<null>((resolve) => setTimeout(() => resolve(null), LOOKUP_TIMEOUT_MS)),
  ]);
}

export async function liveCheckDomain(domain: string): Promise<LiveCheck> {
  const nowMs = Date.now();
  const cached = recentChecks.get(domain);
  if (cached && nowMs - cached.at < THROTTLE_MS) {
    return {
      live: cached.live,
      eppStatuses: cached.eppStatuses,
      recheckedAt: new Date(cached.at).toISOString(),
    };
  }

  const res = await liveLookup(domain);
  const epp = extractEpp(res);

  let live: LiveStatus = "unknown";
  if (res === null) {
    live = "unknown";
  } else if (epp.length > 0) {
    live = "occupied";
  } else if (isNotRegisteredWhoisResponse(res.error ?? "")) {
    live = "released";
  } else {
    live = "unknown";
  }

  recentChecks.set(domain, { live, eppStatuses: epp, at: nowMs });
  if (live === "unknown" && res) logger.debug(`[live] ${domain}: no clear signal`);
  return { live, eppStatuses: epp, recheckedAt: new Date(nowMs).toISOString() };
}

/**
 * Whether a subscription warrants a live re-check on dashboard load. Only
 * post-expiry / dropped / pending-delete phases (plus any cancelled name that
 * previously reached the drop estimate) are candidates — in-range subscriptions
 * keep their persisted snapshot and skip the slow WHOIS round-trip.
 */
export function needsLiveCheck(phase: string | null, active: boolean): boolean {
  if (!phase) return false;
  // Any name that has passed (or is right at) its expiry — grace and beyond —
  // gets a live re-check: the estimated drop date from the TLD config is a
  // guess, so the UI must confirm against the actual registry snapshot.
  return phase === "dropped" || phase === "pendingDelete" || phase === "redemption" || phase === "grace";
}

/**
 * A still-occupied name on a CANCELLED subscription means it was released at
 * some point and has since been registered by someone else — surface that as
 * "re_registered" instead of the generic "occupied".
 */
export function classifyLive(live: LiveStatus, active: boolean): LiveStatus {
  if (live === "occupied" && !active) return "re_registered";
  return live;
}