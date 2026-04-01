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
