import { run, many, isDbReady } from "@/lib/db-query";

const FALLBACK_THRESHOLD = 3;

function extractTld(domain: string): string {
  const parts = domain.toLowerCase().split(".");
  return parts.length >= 2 ? parts[parts.length - 1] : domain.toLowerCase();
}

// ─── Static permanent-fallback list ───────────────────────────────────────────
// TLDs confirmed to have NO public WHOIS server AND no accessible RDAP endpoint.
// For these, native lookup will ALWAYS fail, so we skip the 3-failure learning
// cycle and jump directly to yisi/tianhu on the very first query.
//
// Criteria for inclusion:
//   - Listed as null (no WHOIS server) in cctld-whois-servers.json, AND
//   - Confirmed no RDAP in STATIC_NO_RDAP (tld-rdap-skip.ts) or otherwise known
//
// TLDs that sometimes succeed via custom scrapers (e.g. .ba → nic-ba) are NOT
// listed here; they get promoted via forceTldFallback after a confirmed block.
const STATIC_ALWAYS_FALLBACK = new Set<string>([
  // ── Confirmed no WHOIS server + confirmed no RDAP ─────────────────────────
  "bd",  // Bangladesh — WHOIS null, no RDAP
  "cg",  // Republic of Congo — WHOIS null, no RDAP
  "er",  // Eritrea — WHOIS null, no RDAP
  "gw",  // Guinea-Bissau — WHOIS null, no RDAP
  "lr",  // Liberia — WHOIS null, no RDAP
  "ne",  // Niger — WHOIS null, no RDAP
  "sz",  // Eswatini — WHOIS null, no RDAP

  // ── Political / infrastructure reasons ───────────────────────────────────
  "kp",  // North Korea — no public internet services
  "cu",  // Cuba — no WHOIS; rdap.nic.cu exists but blocked from global infra

  // ── Dissolved / non-functional TLDs (cctld-whois-servers.json: null) ─────
  "an",  // Netherlands Antilles — dissolved 2010, TLD withdrawn
  "tp",  // East Timor — retired, replaced by .tl (which has RDAP)

  // ── Uninhabited / no registry services ───────────────────────────────────
  "aq",  // Antarctica — no ccTLD registry operates public WHOIS/RDAP
  "bv",  // Bouvet Island — Norwegian territory, no domain services
  "sj",  // Svalbard & Jan Mayen — no separate registry, redirected to .no
  "um",  // US Minor Outlying Islands — no active registry

  // ── Overseas territories with no public WHOIS/RDAP ────────────────────────
  "bl",  // Saint Barthélemy — France overseas collectivity, no public RDAP
  "bq",  // Caribbean Netherlands (Bonaire etc.) — no public RDAP
  "eh",  // Western Sahara — disputed territory, no public registry
  "fk",  // Falkland Islands — small registry, no public RDAP
  "gb",  // Great Britain (legacy .gb) — superseded by .uk, not actively used
  "gm",  // Gambia — WHOIS null, no known public RDAP endpoint
  "gu",  // Guam — US territory, no public RDAP (uses .com/.gov instead)
  "mf",  // Saint Martin — French side, no separate public RDAP
  "mh",  // Marshall Islands — WHOIS null, no public RDAP
  "va",  // Vatican City — very small registry, no public RDAP
]);

// ─── In-memory cache ──────────────────────────────────────────────────────────
// Loaded once from DB at startup (or on first use).  All reads after that are
// synchronous — zero DB latency in the hot lookup path.
const _enabled  = new Set<string>(); // TLDs with use_fallback = true
const _failCount = new Map<string, number>(); // TLD → fail_count

let _loaded = false;

async function maybeLoad(): Promise<void> {
  if (_loaded) return;
  _loaded = true;
  if (!(await isDbReady())) return;
  try {
    const rows = await many<{ tld: string; fail_count: number; use_fallback: boolean }>(
      `SELECT tld, fail_count, use_fallback FROM tld_fallback_stats`,
    ).catch(() => [] as { tld: string; fail_count: number; use_fallback: boolean }[]);
    for (const r of rows) {
      _failCount.set(r.tld, r.fail_count ?? 0);
      if (r.use_fallback) _enabled.add(r.tld);
    }
  } catch {}
}

/**
 * Synchronous check for TLDs that should ALWAYS skip native WHOIS/RDAP and go
 * straight to yisi/tianhu.  Used by lookup.ts to short-circuit native attempts
 * entirely (avoiding wasted TCP connections and timeouts) for TLDs confirmed to
 * have no accessible public WHOIS or RDAP endpoint.
 */
export function isStaticAlwaysFallback(domain: string): boolean {
  const tld = extractTld(domain);
  return STATIC_ALWAYS_FALLBACK.has(tld);
}

/**
 * Returns true if the fallback gate is open for this TLD (i.e., native WHOIS
 * / RDAP has failed enough times that we should start yisi/tianhu immediately).
 *
 * Static TLDs in STATIC_ALWAYS_FALLBACK are checked first (synchronous, zero
 * cost) — they never need to accumulate failures before using third-party APIs.
 * Hot-path: synchronous after the one-time DB seed for the dynamic set.
 */
export async function isTldFallbackEnabled(domain: string): Promise<boolean> {
  const tld = extractTld(domain);
  // Static check first — no DB round-trip needed for permanently unreachable TLDs
  if (STATIC_ALWAYS_FALLBACK.has(tld)) return true;
  await maybeLoad();
  return _enabled.has(tld);
}

export async function recordTldNativeFailure(domain: string): Promise<void> {
  await maybeLoad();
  const tld = extractTld(domain);
  const prev = _failCount.get(tld) ?? 0;
  const next = prev + 1;
  _failCount.set(tld, next);
  if (next >= FALLBACK_THRESHOLD) _enabled.add(tld);

  if (!(await isDbReady())) return;
  try {
    await run(
      `INSERT INTO tld_fallback_stats (tld, fail_count, use_fallback, last_fail_at)
       VALUES ($1, 1, false, NOW())
       ON CONFLICT (tld) DO UPDATE
         SET fail_count   = tld_fallback_stats.fail_count + 1,
             use_fallback = (tld_fallback_stats.fail_count + 1) >= $2,
             last_fail_at = NOW()`,
      [tld, FALLBACK_THRESHOLD],
    );
  } catch {}
}

export async function recordTldNativeSuccess(domain: string): Promise<void> {
  await maybeLoad();
  const tld = extractTld(domain);
  _failCount.set(tld, 0);
  _enabled.delete(tld);

  if (!(await isDbReady())) return;
  try {
    await run(
      `UPDATE tld_fallback_stats SET fail_count = 0, use_fallback = false WHERE tld = $1`,
      [tld],
    );
  } catch {}
}

/**
 * Immediately open the fallback gate for a TLD regardless of fail_count.
 * Called when the progressive fallback won the race, meaning native WHOIS / RDAP
 * was too slow — we want yisi/tianhu to race from the very start next time.
 */
export async function forceTldFallback(domain: string): Promise<void> {
  await maybeLoad();
  const tld = extractTld(domain);
  _failCount.set(tld, Math.max(_failCount.get(tld) ?? 0, FALLBACK_THRESHOLD));
  _enabled.add(tld);

  if (!(await isDbReady())) return;
  try {
    await run(
      `INSERT INTO tld_fallback_stats (tld, fail_count, use_fallback, last_fail_at)
       VALUES ($1, $2, true, NOW())
       ON CONFLICT (tld) DO UPDATE
         SET fail_count   = GREATEST(tld_fallback_stats.fail_count, $2),
             use_fallback = true,
             last_fail_at = NOW()`,
      [tld, FALLBACK_THRESHOLD],
    );
  } catch {}
}
