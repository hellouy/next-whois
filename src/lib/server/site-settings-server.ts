/**
 * Server-side settings reader for API routes.
 * Reads individual settings from the DB with short in-process caching.
 * Use this in API handlers to enforce admin-configured toggles.
 */
import { one, many } from "@/lib/db-query";

interface CacheEntry {
  value: string;
  ts: number;
}

const _cache = new Map<string, CacheEntry>();
const CACHE_TTL_MS = 30_000; // 30 seconds

export function invalidateSettingsCache(key?: string) {
  if (key) {
    _cache.delete(key);
  } else {
    _cache.clear();
  }
}

export async function getSetting(key: string, defaultValue = ""): Promise<string> {
  const now = Date.now();
  const cached = _cache.get(key);
  if (cached && now - cached.ts < CACHE_TTL_MS) return cached.value;
  try {
    const row = await one<{ value: string }>(
      "SELECT value FROM site_settings WHERE key = $1",
      [key],
    );
    const value = row?.value ?? defaultValue;
    _cache.set(key, { value, ts: now });
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
 * Fetch multiple settings in a single DB round-trip.
 * Cache hits are served instantly; only uncached keys hit the DB.
 * Returns a record keyed by setting name; missing keys get "".
 */
export async function getSettings(
  keys: string[],
  defaults: Record<string, string> = {},
): Promise<Record<string, string>> {
  const now = Date.now();
  const result: Record<string, string> = {};
  const uncached: string[] = [];

  for (const key of keys) {
    const cached = _cache.get(key);
    if (cached && now - cached.ts < CACHE_TTL_MS) {
      result[key] = cached.value;
    } else {
      uncached.push(key);
    }
  }

  if (uncached.length > 0) {
    try {
      const rows = await many<{ key: string; value: string }>(
        "SELECT key, value FROM site_settings WHERE key = ANY($1)",
        [uncached],
      );
      const rowMap: Record<string, string> = {};
      for (const row of rows) rowMap[row.key] = row.value;
      for (const key of uncached) {
        const value = rowMap[key] ?? defaults[key] ?? "";
        _cache.set(key, { value, ts: now });
        result[key] = value;
      }
    } catch {
      for (const key of uncached) {
        result[key] = defaults[key] ?? "";
      }
    }
  }

  return result;
}
