/**
 * redis.ts — unified Redis abstraction for Vercel + self-hosted environments.
 *
 * Connection strategy (priority order):
 *
 *   1. Upstash HTTP client  — uses REST API, zero persistent TCP connections,
 *      ideal for Vercel serverless.  Activated when KV_REST_API_URL + token
 *      are present (any prefix: wr_KV_*, xrw_KV_*, KV_*).
 *
 *   2. ioredis TCP client   — for self-hosted Redis / RedisLabs / traditional
 *      servers. Persistent connection reused via `global` in dev HMR.
 *      Activated when REDIS_URL / KV_URL / REDIS_HOST are present.
 *
 * All public functions (getRedisValue, setRedisValue, …) delegate to
 * whichever client is active, or silently return null/false when neither
 * is configured — so callers never crash on missing Redis.
 */

// ── Upstash HTTP client (Vercel-optimised) ───────────────────────────────────

type UpstashClient = import("@upstash/redis").Redis;

// Resolve env vars that Upstash Vercel integration writes with a project prefix
// (e.g. wr_KV_REST_API_URL / xrw_KV_REST_API_URL) and the unprefixed defaults.
function resolveUpstashEnv(): { url: string; token: string } | null {
  const prefixes = ["wr_", "xrw_", ""];
  for (const p of prefixes) {
    const url   = process.env[`${p}KV_REST_API_URL`];
    const token = process.env[`${p}KV_REST_API_TOKEN`];
    if (url && token) return { url, token };
  }
  return null;
}

let _upstash: UpstashClient | null | undefined; // undefined = not yet tried

function getUpstashClient(): UpstashClient | null {
  if (_upstash !== undefined) return _upstash;
  const creds = resolveUpstashEnv();
  if (!creds) { _upstash = null; return null; }
  try {
    const { Redis } = require("@upstash/redis") as typeof import("@upstash/redis");
    _upstash = new Redis({ url: creds.url, token: creds.token });
    console.log("[Redis] Using Upstash HTTP client →", creds.url);
    return _upstash;
  } catch (err: any) {
    console.error("[Redis] Failed to init Upstash client:", err.message);
    _upstash = null;
    return null;
  }
}

// ── ioredis TCP client (self-hosted fallback) ─────────────────────────────────

export const REDIS_URL =
  (process.env.xrw_REDIS_URL as string | undefined) ||
  (process.env.wr_REDIS_URL  as string | undefined) ||
  (process.env.wr_KV_URL     as string | undefined) ||
  (process.env.KV_URL        as string | undefined) ||
  (process.env.REDIS_URL     as string | undefined);

export const REDIS_HOST     = process.env.REDIS_HOST as string | undefined;
export const REDIS_PORT     = parseInt(process.env.REDIS_PORT     || "6379");
export const REDIS_PASSWORD = process.env.REDIS_PASSWORD;
export const REDIS_DB       = parseInt(process.env.REDIS_DB       || "0");

declare global {
  // eslint-disable-next-line no-var
  var __redisClient: import("ioredis").Redis | undefined | null;
  // eslint-disable-next-line no-var
  var __redisAvailable: boolean;
}

if (global.__redisAvailable === undefined) global.__redisAvailable = false;

let _ioredisAvailable = global.__redisAvailable;

function createIoredisConn(): import("ioredis").Redis | undefined {
  // Skip ioredis entirely if Upstash HTTP is available
  if (resolveUpstashEnv()) return undefined;

  const opts = {
    maxRetriesPerRequest: 1,
    connectTimeout:       3_000,
    commandTimeout:       2_000,
    lazyConnect:          false,
    enableReadyCheck:     false,
    enableOfflineQueue:   false,
    keepAlive:            10_000,
    retryStrategy(times: number) {
      if (times > 3) return null;
      return Math.min(times * 500, 2_000);
    },
  } as const;

  let client: import("ioredis").Redis | undefined;
  try {
    const Redis = (require("ioredis") as typeof import("ioredis")).default ?? require("ioredis");
    if (REDIS_URL) {
      client = new Redis(REDIS_URL, opts as any);
    } else if (REDIS_HOST) {
      client = new Redis({ ...opts, host: REDIS_HOST, port: REDIS_PORT, password: REDIS_PASSWORD, db: REDIS_DB } as any);
    }
  } catch (err) {
    console.error("[Redis] ioredis init failed:", err);
    return undefined;
  }
  if (!client) return undefined;

  client.on("ready",        ()    => { _ioredisAvailable = true;  global.__redisAvailable = true;  console.log("[Redis] Connected and ready"); });
  client.on("error",        (err) => { console.error("[Redis]", err.message); });
  client.on("close",        ()    => { _ioredisAvailable = false; global.__redisAvailable = false; });
  client.on("reconnecting", ()    => { _ioredisAvailable = false; global.__redisAvailable = false; });
  client.on("end",          ()    => { _ioredisAvailable = false; global.__redisAvailable = false; });
  return client;
}

// Singleton ioredis instance (reused across HMR reloads in dev)
export const redis: import("ioredis").Redis | undefined = (() => {
  if (resolveUpstashEnv()) return undefined; // Upstash takes over
  if (global.__redisClient !== undefined) return global.__redisClient ?? undefined;
  const client = createIoredisConn();
  global.__redisClient = client ?? null;
  return client;
})();

// ── Availability check ────────────────────────────────────────────────────────

export function isRedisAvailable(): boolean {
  if (getUpstashClient()) return true;          // Upstash is always ready
  return _ioredisAvailable || global.__redisAvailable;
}

// ── Unified operations (Upstash preferred, ioredis fallback) ─────────────────

export async function getRedisValue(key: string): Promise<string | null> {
  const up = getUpstashClient();
  if (up) {
    try { return await up.get<string>(key) ?? null; }
    catch (err: any) { console.error(`[Redis] GET ${key}:`, err.message); return null; }
  }
  if (!redis || !_ioredisAvailable) return null;
  try { return await redis.get(key); }
  catch (err: any) { console.error(`[Redis] GET ${key}:`, err.message); return null; }
}

export async function setRedisValue(
  key: string,
  value: string,
  ttl?: number,
): Promise<boolean> {
  const up = getUpstashClient();
  if (up) {
    try {
      if (ttl && ttl > 0) await up.set(key, value, { ex: ttl });
      else                 await up.set(key, value);
      return true;
    } catch (err: any) { console.error(`[Redis] SET ${key}:`, err.message); return false; }
  }
  if (!redis || !_ioredisAvailable) return false;
  try {
    if (ttl && ttl > 0) await redis.set(key, value, "EX", ttl);
    else                 await redis.set(key, value);
    return true;
  } catch (err: any) { console.error(`[Redis] SET ${key}:`, err.message); return false; }
}

export async function deleteRedisValue(key: string): Promise<boolean> {
  const up = getUpstashClient();
  if (up) {
    try { await up.del(key); return true; }
    catch (err: any) { console.error(`[Redis] DEL ${key}:`, err.message); return false; }
  }
  if (!redis || !_ioredisAvailable) return false;
  try { await redis.del(key); return true; }
  catch (err: any) { console.error(`[Redis] DEL ${key}:`, err.message); return false; }
}

/**
 * Deletes all Redis keys matching a glob pattern using SCAN (non-blocking).
 * Note: Upstash free tier limits SCAN cursor usage; falls back to no-op
 * gracefully when pattern scanning is unavailable.
 */
export async function deleteRedisKeysByPattern(pattern: string): Promise<number> {
  const up = getUpstashClient();
  if (up) {
    try {
      let deleted = 0;
      let cursor = 0 as number;
      do {
        const [next, keys] = await up.scan(cursor as unknown as number, { match: pattern, count: 100 });
        cursor = next as unknown as number;
        if (keys.length > 0) {
          await up.del(...keys);
          deleted += keys.length;
        }
      } while (cursor !== 0);
      return deleted;
    } catch (err: any) {
      console.error(`[Redis] SCAN/DEL ${pattern}:`, err.message);
      return 0;
    }
  }
  if (!redis || !_ioredisAvailable) return 0;
  try {
    let cursor = "0";
    const toDelete: string[] = [];
    do {
      const [nextCursor, keys] = await redis.scan(cursor, "MATCH", pattern, "COUNT", 100);
      cursor = nextCursor;
      toDelete.push(...keys);
    } while (cursor !== "0");
    if (toDelete.length === 0) return 0;
    await redis.del(...toDelete);
    return toDelete.length;
  } catch (err: any) {
    console.error(`[Redis] SCAN/DEL ${pattern}:`, err.message);
    return 0;
  }
}

/**
 * Atomically increments a counter key and sets TTL on first increment.
 * Uses INCR + EXPIRE pipeline for ioredis, or sequential calls for Upstash.
 */
export async function incrRedisValue(key: string, ttlSeconds: number): Promise<number | null> {
  const up = getUpstashClient();
  if (up) {
    try {
      const count = await up.incr(key);
      if (count === 1) await up.expire(key, ttlSeconds);
      return count;
    } catch (err: any) { console.error(`[Redis] INCR ${key}:`, err.message); return null; }
  }
  if (!redis || !_ioredisAvailable) return null;
  try {
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, ttlSeconds);
    return count;
  } catch (err: any) { console.error(`[Redis] INCR ${key}:`, err.message); return null; }
}

export async function getRemainingTtl(key: string): Promise<number | null> {
  const up = getUpstashClient();
  if (up) {
    try { const t = await up.ttl(key); return t >= 0 ? t : null; }
    catch { return null; }
  }
  if (!redis || !_ioredisAvailable) return null;
  try { const t = await redis.ttl(key); return t >= 0 ? t : null; }
  catch { return null; }
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

export async function getJsonRedisValue<T>(key: string): Promise<T | null> {
  const up = getUpstashClient();
  if (up) {
    // Upstash automatically JSON-parses — but we want the raw string for compat.
    // Use get<string> to prevent double-parse.
    try {
      const raw = await up.get<string>(key);
      if (raw == null) return null;
      // Upstash may return already-parsed object when stored as JSON
      if (typeof raw === "object") return raw as unknown as T;
      return JSON.parse(raw) as T;
    } catch (err: any) { console.error(`[Redis] getJson ${key}:`, err.message); return null; }
  }
  const raw = await getRedisValue(key);
  if (!raw) return null;
  try { return JSON.parse(raw) as T; }
  catch { return null; }
}

export async function setJsonRedisValue<T>(
  key: string,
  value: T,
  ttl?: number,
): Promise<boolean> {
  try { return await setRedisValue(key, JSON.stringify(value), ttl); }
  catch { return false; }
}

export async function getJsonRedisValueWithTtl<T>(
  key: string,
): Promise<{ value: T; remainingTtl: number | null } | null> {
  const up = getUpstashClient();
  if (up) {
    try {
      // Parallel fetch: GET + TTL in one round-trip using Promise.all
      const [raw, ttl] = await Promise.all([up.get<string>(key), up.ttl(key)]);
      if (raw == null) return null;
      const value = typeof raw === "object" ? (raw as unknown as T) : JSON.parse(raw as string) as T;
      return { value, remainingTtl: ttl >= 0 ? ttl : null };
    } catch (err: any) { console.error(`[Redis] getJsonWithTtl ${key}:`, err.message); return null; }
  }
  if (!redis || !_ioredisAvailable) return null;
  try {
    const [raw, ttl] = await Promise.all([redis.get(key), redis.ttl(key)]);
    if (!raw) return null;
    const value = JSON.parse(raw) as T;
    return { value, remainingTtl: ttl >= 0 ? ttl : null };
  } catch (err: any) { console.error(`[Redis] getJsonWithTtl ${key}:`, err.message); return null; }
}

// ── Site settings cache (Redis L2 for cross-instance sharing on Vercel) ──────
// Keys: ss:{settingKey}   TTL: 60 s

const SS_PREFIX = "ss:";
const SS_TTL    = 60; // seconds

export async function getCachedSetting(key: string): Promise<string | null> {
  return getRedisValue(`${SS_PREFIX}${key}`);
}

export async function setCachedSetting(key: string, value: string): Promise<void> {
  await setRedisValue(`${SS_PREFIX}${key}`, value, SS_TTL);
}

export async function invalidateCachedSettings(): Promise<void> {
  await deleteRedisKeysByPattern(`${SS_PREFIX}*`);
}

// ── WHOIS lookup DB-backed L3 cache helpers ───────────────────────────────────
// When Redis is fully unavailable, lookups fall back to the whois_cache PG table.
// These helpers let lookup.ts store/retrieve from PG as L3.

export async function getWhoisDbCache(key: string): Promise<string | null> {
  try {
    const { one } = await import("@/lib/db-query");
    const row = await one<{ value: string }>(
      `SELECT value FROM whois_cache WHERE key = $1 AND expires_at > NOW()`,
      [key],
    );
    return row?.value ?? null;
  } catch { return null; }
}

export async function setWhoisDbCache(key: string, value: string, ttlSeconds: number): Promise<void> {
  try {
    const { run } = await import("@/lib/db-query");
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
    await run(
      `INSERT INTO whois_cache (key, value, expires_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE
         SET value = EXCLUDED.value, expires_at = EXCLUDED.expires_at`,
      [key, value, expiresAt],
    );
  } catch { /* ignore */ }
}
