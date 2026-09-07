import { many, isDbReady } from "@/lib/db-query";
import type { TldLifecycle } from "@/lib/lifecycle";
import {
  isRedisAvailable,
  getJsonRedisValue,
  setJsonRedisValue,
} from "@/lib/server/redis";

let _cache: Record<string, TldLifecycle> | null = null;
let _cacheExpiry = 0;
const TTL = 5 * 60 * 1000; // 5 minutes in-process
const REDIS_TTL_S = 5 * 60; // 5 minutes in Redis
const REDIS_KEY = "lifecycle_overrides:v1";

/**
 * Loads TLD lifecycle overrides from the database.
 *
 * Priority (highest wins):
 *   1. tld_lifecycle_overrides — manually curated admin overrides
 *   2. tld_rules               — AI-scraped rules (confidence: ai/high)
 *
 * Both tables are merged so the admin table can override any AI-scraped value.
 * Now also loads drop_hour/drop_minute/drop_second/drop_timezone/pre_expiry_days
 * from tld_rules for precise drop-time display.
 */
export async function loadLifecycleOverrides(): Promise<Record<string, TldLifecycle>> {
  // L1: in-process cache
  if (_cache && Date.now() < _cacheExpiry) return _cache;

  // L2: Redis (survives across Vercel function instances)
  if (isRedisAvailable()) {
    const cached = await getJsonRedisValue<Record<string, TldLifecycle>>(REDIS_KEY);
    if (cached) {
      _cache = cached;
      _cacheExpiry = Date.now() + TTL;
      return cached;
    }
  }

  if (!(await isDbReady())) return {};
  try {
    const map: Record<string, TldLifecycle> = {};

    // Layer 1: AI-scraped tld_rules (base layer, lower priority)
    // Only rows that are genuinely ok (real scraped data) or manually edited are
    // trusted. Rows in warn_defaults / no_data / failed carry the fallback
    // 30/30/5 defaults which would otherwise be treated as authoritative AI data
    // and corrupt drop-date calculations for those TLDs.
    const aiRows = await many<{
      tld: string;
      grace_period_days: number;
      redemption_period_days: number;
      pending_delete_days: number;
      confidence: string;
      drop_hour: number | null;
      drop_minute: number | null;
      drop_second: number | null;
      drop_timezone: string | null;
      pre_expiry_days: number | null;
    }>(
      `SELECT tld, grace_period_days, redemption_period_days, pending_delete_days, confidence,
              drop_hour, drop_minute, drop_second, drop_timezone, pre_expiry_days
       FROM tld_rules
       WHERE scrape_status = 'ok' OR COALESCE(manually_edited, false) = true
       ORDER BY tld`,
    ).catch(() => []);

    for (const r of aiRows) {
      const lc: TldLifecycle = {
        grace: r.grace_period_days,
        redemption: r.redemption_period_days,
        pendingDelete: r.pending_delete_days,
        confidence: r.confidence === "high" ? "high" : "est",
      };
      if (r.drop_hour !== null) lc.dropHour = r.drop_hour;
      if (r.drop_minute !== null) lc.dropMinute = r.drop_minute;
      if (r.drop_second !== null) lc.dropSecond = r.drop_second;
      if (r.drop_timezone) lc.dropTimezone = r.drop_timezone;
      if (r.pre_expiry_days !== null) lc.preExpiryDays = r.pre_expiry_days;
      map[r.tld] = lc;
    }

    // Layer 2: Manually curated overrides (highest priority — overwrite AI data)
    const manualRows = await many<{
      tld: string; grace: number; redemption: number;
      pending_delete: number; registry: string | null;
    }>(
      `SELECT tld, grace, redemption, pending_delete, registry
       FROM tld_lifecycle_overrides ORDER BY tld`,
    ).catch(() => []);

    for (const r of manualRows) {
      map[r.tld] = {
        grace: r.grace,
        redemption: r.redemption,
        pendingDelete: r.pending_delete,
        registry: r.registry ?? undefined,
        confidence: "high",
      };
    }

    _cache = map;
    _cacheExpiry = Date.now() + TTL;
    // Write-through to Redis so other instances can skip the DB query
    if (isRedisAvailable()) {
      setJsonRedisValue(REDIS_KEY, map, REDIS_TTL_S).catch(() => {});
    }
    return map;
  } catch {
    return {};
  }
}

export function invalidateLifecycleOverridesCache(): void {
  _cache = null;
  _cacheExpiry = 0;
  // Also invalidate Redis cache so all instances pick up the change
  if (isRedisAvailable()) {
    import("@/lib/server/redis").then(({ deleteRedisValue }) =>
      deleteRedisValue(REDIS_KEY).catch(() => {})
    );
  }
}
