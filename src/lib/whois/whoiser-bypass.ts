/**
 * whoiser-bypass.ts — Auto-bypass manager for whoiser WHOIS queries.
 *
 * When whoiser consistently fails for a TLD (default: 3 consecutive failures),
 * the TLD is added to the bypass set. Subsequent lookups for that TLD skip
 * whoiser entirely and go straight to the admin-configured manual server.
 *
 * Storage layers (highest-to-lowest durability):
 *   1. PostgreSQL tld_fallback_stats.whoiser_bypass — survives restarts + deploys
 *   2. Redis whoiser_bypass:{tld} = "1" — cross-instance in-memory (Vercel)
 *   3. Redis whoiser_fail:{tld} = integer — rolling failure counter (7-day TTL)
 *   4. In-process Set<string> — hot-path zero-latency check (loaded from Redis/DB)
 *
 * When Redis is unavailable, in-process state is still maintained for the
 * lifetime of the process. DB is always updated on bypass/reset.
 */

import {
  isRedisAvailable,
  getRedisValue,
  setRedisValue,
  deleteRedisValue,
  incrRedisValue,
  deleteRedisKeysByPattern,
} from "@/lib/server/redis";
import { run, many, isDbReady } from "@/lib/db-query";

// ── Configuration ─────────────────────────────────────────────────────────────

/** Consecutive whoiser failures required to trigger auto-bypass for a TLD. */
export const BYPASS_FAIL_THRESHOLD = 3;

/** Rolling TTL (seconds) for the per-TLD failure counter in Redis. 7 days. */
const FAIL_TTL_SECONDS = 7 * 86_400;

// ── In-process bypass set ─────────────────────────────────────────────────────

/** Hot-path bypass check: zero Redis RTT for already-known bypassed TLDs. */
const _bypassed = new Set<string>();

/**
 * Whether we have already loaded the persisted bypass list from Redis/DB.
 * Avoids one-time startup overhead on first call.
 */
let _loaded = false;

// ── Redis key helpers ─────────────────────────────────────────────────────────

function failKey(tld: string) { return `whoiser_fail:${tld}`; }
function bypassKey(tld: string) { return `whoiser_bypass:${tld}`; }

// ── DB helpers ────────────────────────────────────────────────────────────────

async function dbSetBypass(tld: string, value: boolean): Promise<void> {
  if (!(await isDbReady())) return;
  try {
    await run(
      `INSERT INTO tld_fallback_stats (tld, fail_count, whoiser_bypass)
       VALUES ($1, 0, $2)
       ON CONFLICT (tld) DO UPDATE SET whoiser_bypass = $2`,
      [tld, value],
    );
  } catch { /* silently ignore — never disrupt the query path */ }
}

async function dbLoadBypassed(): Promise<string[]> {
  if (!(await isDbReady())) return [];
  try {
    const rows = await many<{ tld: string }>(
      `SELECT tld FROM tld_fallback_stats WHERE whoiser_bypass = true`,
    );
    return rows.map(r => r.tld);
  } catch { return []; }
}

// ── Lazy load bypassed TLDs from persistence ──────────────────────────────────

/**
 * Lazily warm the in-process bypass set from DB + Redis on first call.
 * Subsequent calls are no-ops (guarded by `_loaded`).
 */
async function ensureLoaded(): Promise<void> {
  if (_loaded) return;
  _loaded = true; // set before awaits to prevent concurrent double-loads

  // Primary source: DB (most durable)
  const dbTlds = await dbLoadBypassed();
  for (const t of dbTlds) _bypassed.add(t);

  // Supplement from Redis (handles edge cases where DB update was missed)
  if (isRedisAvailable()) {
    // We can't SCAN with a pattern efficiently on all Redis flavours, so we
    // rely on DB as the primary source. Redis is authoritative only for
    // real-time counter state and cross-instance sync; DB is the source of
    // truth for bypass flags.
  }
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Returns true when whoiser should be skipped for this TLD (auto-bypassed
 * due to repeated failures or manually marked in admin panel).
 *
 * Hot-path: checks in-process Set first (O(1), zero I/O).
 * Falls back to Redis on first call before the in-process set is warmed.
 */
export async function isWhoiserBypassed(tld: string): Promise<boolean> {
  const t = tld.toLowerCase().replace(/^\./, "");
  if (_bypassed.has(t)) return true;

  // Lazy-load from persistence on first call
  await ensureLoaded();
  if (_bypassed.has(t)) return true;

  // Double-check Redis in case another instance added the bypass
  if (isRedisAvailable()) {
    const val = await getRedisValue(bypassKey(t)).catch(() => null);
    if (val === "1") {
      _bypassed.add(t);
      return true;
    }
  }
  return false;
}

/**
 * Record one whoiser failure for a TLD.
 * When the failure count reaches BYPASS_FAIL_THRESHOLD:
 *   - adds TLD to in-process bypass set
 *   - persists bypass flag to Redis (cross-instance) + DB (durable)
 *
 * Called fire-and-forget from the query path — never awaited in hot path.
 */
export async function recordWhoiserFailure(tld: string): Promise<void> {
  const t = tld.toLowerCase().replace(/^\./, "");
  if (_bypassed.has(t)) return; // already bypassed — nothing to do

  let count: number | null = null;
  if (isRedisAvailable()) {
    count = await incrRedisValue(failKey(t), FAIL_TTL_SECONDS).catch(() => null);
  }

  // If Redis unavailable, use a rough in-process counter as fallback.
  // We use the bypass set size heuristic: track per-TLD failures in memory.
  if (count === null) {
    _inMemFailCounts.set(t, (_inMemFailCounts.get(t) ?? 0) + 1);
    count = _inMemFailCounts.get(t) ?? 0;
  }

  if (count >= BYPASS_FAIL_THRESHOLD) {
    console.log(`[whoiser-bypass] Auto-bypassing .${t} after ${count} failures`);
    _bypassed.add(t);
    // Persist to Redis (cross-instance awareness)
    if (isRedisAvailable()) {
      setRedisValue(bypassKey(t), "1").catch(() => {});
    }
    // Persist to DB (durable across restarts)
    dbSetBypass(t, true).catch(() => {});
  }
}

/** In-process fallback failure counter when Redis is unavailable. */
const _inMemFailCounts = new Map<string, number>();

/**
 * Reset the whoiser bypass for a single TLD.
 * Clears in-process state, Redis keys, and DB flag.
 */
export async function resetWhoiserBypass(tld: string): Promise<void> {
  const t = tld.toLowerCase().replace(/^\./, "");
  _bypassed.delete(t);
  _inMemFailCounts.delete(t);

  if (isRedisAvailable()) {
    await Promise.allSettled([
      deleteRedisValue(bypassKey(t)),
      deleteRedisValue(failKey(t)),
    ]);
  }
  await dbSetBypass(t, false);
}

/**
 * Reset whoiser bypasses for ALL TLDs.
 * Clears in-process state, Redis keys, and DB flags.
 */
export async function resetAllWhoiserBypasses(): Promise<void> {
  _bypassed.clear();
  _inMemFailCounts.clear();

  if (isRedisAvailable()) {
    await Promise.allSettled([
      deleteRedisKeysByPattern("whoiser_bypass:*"),
      deleteRedisKeysByPattern("whoiser_fail:*"),
    ]);
  }

  if (await isDbReady()) {
    await run(
      `UPDATE tld_fallback_stats SET whoiser_bypass = false WHERE whoiser_bypass = true`,
    ).catch(() => {});
  }
}

/**
 * Returns the current list of bypassed TLDs (from in-process set + DB).
 * Used by the admin panel to display bypass status.
 */
export async function getBypassedTlds(): Promise<string[]> {
  await ensureLoaded();
  return [..._bypassed].sort();
}

/**
 * Manually mark a TLD as bypassed (admin panel override).
 * Behaves identically to auto-bypass triggered by BYPASS_FAIL_THRESHOLD.
 */
export async function markWhoiserBypassed(tld: string): Promise<void> {
  const t = tld.toLowerCase().replace(/^\./, "");
  _bypassed.add(t);
  if (isRedisAvailable()) {
    setRedisValue(bypassKey(t), "1").catch(() => {});
  }
  await dbSetBypass(t, true);
}
