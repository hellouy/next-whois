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

// ── Circuit breaker for Upstash ───────────────────────────────────────────────
// When Upstash returns "max requests limit exceeded", disable all Redis calls
// until the window resets. Persisted on globalThis so HMR reloads don't reset it.

const _cbg = globalThis as any;
if (_cbg.__upstashDisabledUntil === undefined) _cbg.__upstashDisabledUntil = 0;

const MAX_LIMIT_MSG = "max requests limit exceeded";
// Re-enable check interval: 1 hour. When the limit resets (daily/monthly),
// the next request after this interval will try Redis again automatically.
const CB_RETRY_MS = 60 * 60 * 1000; // 1 hour

function isUpstashCircuitOpen(): boolean {
  return Date.now() < (_cbg.__upstashDisabledUntil as number);
}

function tripUpstashCircuit() {
  if (isUpstashCircuitOpen()) return; // already tripped
  _cbg.__upstashDisabledUntil = Date.now() + CB_RETRY_MS;
  console.warn("[Redis] Upstash limit reached — disabling Redis calls for 1 hour to save quota.");
}

function handleUpstashError(err: any) {
  const msg: string = err?.message ?? String(err);
  if (msg.toLowerCase().includes(MAX_LIMIT_MSG)) {
    tripUpstashCircuit();
  }
}

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
  if (isUpstashCircuitOpen()) return null; // circuit tripped — skip Redis entirely
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
  // NOTE: ioredis is initialised even when Upstash HTTP is present so it can
  // act as a true hot-standby.  When Upstash is healthy all ops go through it;
  // if its circuit breaker trips (quota/outage) ioredis takes over seamlessly
  // without falling all the way to the PostgreSQL L3 cache.

  // Detect TLS requirement: rediss:// URLs (Aiven, Redis Cloud, etc.) need
  // explicit TLS options. rejectUnauthorized:false handles self-signed certs
  // that Aiven and similar managed services commonly use.
  const isTlsUrl = REDIS_URL?.startsWith("rediss://") ?? false;
  const tlsOpts = isTlsUrl ? { tls: { rejectUnauthorized: false } } : {};

  const opts = {
    maxRetriesPerRequest: 2,
    connectTimeout:       8_000,   // Aiven / cloud Redis can be slower to connect
    commandTimeout:       5_000,
    lazyConnect:          false,
    enableReadyCheck:     true,    // confirm server is fully ready before marking available
    enableOfflineQueue:   true,    // queue commands during brief reconnect windows
    keepAlive:            15_000,  // send TCP keepalive every 15 s to prevent idle drops
    retryStrategy(times: number) {
      if (times > 6) return null;  // give up after 6 attempts (~30 s total)
      return Math.min(times * 1_000, 5_000);
    },
    ...tlsOpts,
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

// Singleton ioredis instance (reused across HMR reloads in dev).
// Intentionally initialised even when Upstash is present — ioredis acts as a
// hot standby that activates automatically if the Upstash circuit breaker trips.
export const redis: import("ioredis").Redis | undefined = (() => {
  if (global.__redisClient !== undefined) return global.__redisClient ?? undefined;
  const client = createIoredisConn();
  global.__redisClient = client ?? null;
  return client;
})();

// ── Eager pre-initialisation (cold-start optimisation) ────────────────────────
// Kick off the Upstash HTTP client immediately at module load so the very first
// incoming request does not pay the one-time initialisation cost.
// ioredis is already connecting eagerly through the singleton above.
void getUpstashClient();

// ── Availability check ────────────────────────────────────────────────────────

/** Returns true when at least one Redis backend (Upstash or ioredis) is ready. */
export function isRedisAvailable(): boolean {
  // Upstash: available if circuit is not tripped and client was created.
  if (!isUpstashCircuitOpen() && getUpstashClient()) return true;
  // ioredis: fallback — active when Upstash is tripped or when only TCP is configured.
  return _ioredisAvailable || global.__redisAvailable;
}

/** Returns true when the ioredis TCP connection is ready (for diagnostics). */
export function isIoredisAvailable(): boolean {
  return _ioredisAvailable || global.__redisAvailable;
}

/** Returns the label of the currently active Redis backend (for diagnostics). */
export function activeRedisBackend(): "upstash" | "ioredis" | "none" {
  if (!isUpstashCircuitOpen() && getUpstashClient()) return "upstash";
  if (_ioredisAvailable || global.__redisAvailable) return "ioredis";
  return "none";
}

// ── Unified operations (Upstash preferred, ioredis fallback) ─────────────────

export async function getRedisValue(key: string): Promise<string | null> {
  const up = getUpstashClient();
  if (up) {
    try { return await up.get<string>(key) ?? null; }
    catch (err: any) { handleUpstashError(err); console.error(`[Redis] GET ${key}:`, err.message); return null; }
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
    } catch (err: any) { handleUpstashError(err); console.error(`[Redis] SET ${key}:`, err.message); return false; }
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
    catch (err: any) { handleUpstashError(err); console.error(`[Redis] DEL ${key}:`, err.message); return false; }
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
      handleUpstashError(err);
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
    } catch (err: any) { handleUpstashError(err); console.error(`[Redis] INCR ${key}:`, err.message); return null; }
  }
  if (!redis || !_ioredisAvailable) return null;
  try {
    const count = await redis.incr(key);
    if (count === 1) await redis.expire(key, ttlSeconds);
    return count;
  } catch (err: any) { console.error(`[Redis] INCR ${key}:`, err.message); return null; }
}

/**
 * Increment a counter and **always** refresh its TTL (rolling window).
 * Unlike `incrRedisValue`, this resets the expiry on every increment,
 * so the window slides forward each time the key is touched.
 * Use this when you want "N events within the last T seconds" semantics
 * rather than a fixed-window rate limit.
 */
export async function incrRedisValueRolling(key: string, ttlSeconds: number): Promise<number | null> {
  const up = getUpstashClient();
  if (up) {
    try {
      const count = await up.incr(key);
      await up.expire(key, ttlSeconds);
      return count;
    } catch (err: any) { handleUpstashError(err); console.error(`[Redis] INCR(rolling) ${key}:`, err.message); return null; }
  }
  if (!redis || !_ioredisAvailable) return null;
  try {
    const count = await redis.incr(key);
    await redis.expire(key, ttlSeconds);
    return count;
  } catch (err: any) { console.error(`[Redis] INCR(rolling) ${key}:`, err.message); return null; }
}

export async function getRemainingTtl(key: string): Promise<number | null> {
  const up = getUpstashClient();
  if (up) {
    try { const t = await up.ttl(key); return t >= 0 ? t : null; }
    catch (err: any) { handleUpstashError(err); return null; }
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
    } catch (err: any) { handleUpstashError(err); console.error(`[Redis] getJson ${key}:`, err.message); return null; }
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
    } catch (err: any) { handleUpstashError(err); console.error(`[Redis] getJsonWithTtl ${key}:`, err.message); return null; }
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

// ── WHOIS rate-limit tracker ──────────────────────────────────────────────────
// When a WHOIS server rate-limits a TLD, we record it in Redis so subsequent
// queries for the same TLD skip the WHOIS call for the cooldown window, avoiding
// repeated "too many requests" errors and saving timeout latency.
// Key:  whois_rl:{tld}   Value: "1"   TTL: configurable (default 60 s)

const WHOIS_RL_PREFIX = "whois_rl:";

/**
 * Record that a WHOIS server is currently rate-limiting queries for the given TLD.
 * Subsequent calls to checkWhoisRateLimit() will return true until the TTL expires.
 */
export async function setWhoisRateLimit(tld: string, ttlSeconds = 60): Promise<void> {
  if (!isRedisAvailable()) return;
  const key = `${WHOIS_RL_PREFIX}${tld.toLowerCase()}`;
  await setRedisValue(key, "1", ttlSeconds).catch(() => {});
}

/**
 * Returns true when the given TLD's WHOIS server is known to be rate-limiting.
 * Callers should skip the WHOIS query and go directly to RDAP / DNS probe.
 */
export async function checkWhoisRateLimit(tld: string): Promise<boolean> {
  if (!isRedisAvailable()) return false;
  const key = `${WHOIS_RL_PREFIX}${tld.toLowerCase()}`;
  const val = await getRedisValue(key).catch(() => null);
  return val === "1";
}
