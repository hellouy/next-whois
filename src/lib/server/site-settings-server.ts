/**
 * Server-side settings reader for API routes.
 *
 * Cache hierarchy (fastest → slowest):
 *   L1  in-process Map    30 s   — zero latency within a warm function instance
 *   L2  Redis             60 s   — shared across Vercel function instances (Upstash)
 *   L3  PostgreSQL        source — authoritative store
 *
 * On Vercel, L1 is cold on every new instance, so L2 (Redis) is critical to
 * avoid hitting Postgres on every request.
 */

import { one, many } from "@/lib/db-query";
import {
  isRedisAvailable,
  getCachedSetting,
  setCachedSetting,
  invalidateCachedSettings,
} from "@/lib/server/redis";

// ── L1: In-process cache ──────────────────────────────────────────────────────

interface CacheEntry {
  value: string;
  ts: number;
}

const _l1 = new Map<string, CacheEntry>();
const L1_TTL_MS = 30_000; // 30 seconds

export function invalidateSettingsCache(key?: string) {
  if (key) _l1.delete(key);
  else     _l1.clear();
  // Best-effort Redis invalidation (don't await to avoid blocking callers)
  if (key === undefined) invalidateCachedSettings().catch(() => {});
}

// ── Core read with L1 → L2 → L3 ──────────────────────────────────────────────

export async function getSetting(key: string, defaultValue = ""): Promise<string> {
  const now = Date.now();

  // L1: in-process
  const l1 = _l1.get(key);
  if (l1 && now - l1.ts < L1_TTL_MS) return l1.value;

  // L2: Redis (survives across Vercel instances)
  if (isRedisAvailable()) {
    try {
      const cached = await getCachedSetting(key);
      if (cached !== null) {
        _l1.set(key, { value: cached, ts: now });
        return cached;
      }
    } catch { /* fall through */ }
  }

  // L3: database
  try {
    const row = await one<{ value: string }>(
      "SELECT value FROM site_settings WHERE key = $1",
      [key],
    );
    const value = row?.value ?? defaultValue;
    _l1.set(key, { value, ts: now });
    if (isRedisAvailable()) setCachedSetting(key, value).catch(() => {});
    return value;
  } catch {
    return defaultValue;
  }
}

/** Returns true if the setting is set to "1" (truthy toggle). */
export async function isEnabled(key: string): Promise<boolean> {
  return (await getSetting(key)) === "1";
}

/**
 * Fetch multiple settings in a single round-trip where possible.
 * L1 hits are served instantly; uncached keys are batched into one DB query.
 */
export async function getSettings(
  keys: string[],
  defaults: Record<string, string> = {},
): Promise<Record<string, string>> {
  const now = Date.now();
  const result: Record<string, string> = {};
  const uncachedL1: string[] = [];

  // L1 pass
  for (const key of keys) {
    const l1 = _l1.get(key);
    if (l1 && now - l1.ts < L1_TTL_MS) {
      result[key] = l1.value;
    } else {
      uncachedL1.push(key);
    }
  }

  if (uncachedL1.length === 0) return result;

  // L2: Redis (parallel fetch)
  const uncachedL2: string[] = [];
  if (isRedisAvailable()) {
    await Promise.all(
      uncachedL1.map(async (key) => {
        try {
          const cached = await getCachedSetting(key);
          if (cached !== null) {
            _l1.set(key, { value: cached, ts: now });
            result[key] = cached;
          } else {
            uncachedL2.push(key);
          }
        } catch {
          uncachedL2.push(key);
        }
      }),
    );
  } else {
    uncachedL2.push(...uncachedL1);
  }

  if (uncachedL2.length === 0) return result;

  // L3: database (single query for all remaining keys)
  try {
    const rows = await many<{ key: string; value: string }>(
      "SELECT key, value FROM site_settings WHERE key = ANY($1)",
      [uncachedL2],
    );
    const rowMap: Record<string, string> = {};
    for (const row of rows) rowMap[row.key] = row.value;

    for (const key of uncachedL2) {
      const value = rowMap[key] ?? defaults[key] ?? "";
      _l1.set(key, { value, ts: now });
      result[key] = value;
      if (isRedisAvailable()) setCachedSetting(key, value).catch(() => {});
    }
  } catch {
    for (const key of uncachedL2) {
      result[key] = defaults[key] ?? "";
    }
  }

  return result;
}
