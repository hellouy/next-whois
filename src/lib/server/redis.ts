import Redis from "ioredis";

// Support both unprefixed (REDIS_URL, KV_URL) and Vercel integration prefixed variants.
// Upstash for Vercel adds a custom prefix (e.g. xrw_, wr_) based on the database name.
export const REDIS_URL =
  (process.env.xrw_REDIS_URL as string | undefined) ||
  (process.env.wr_REDIS_URL as string | undefined) ||
  (process.env.wr_KV_URL as string | undefined) ||
  (process.env.KV_URL as string | undefined) ||
  (process.env.REDIS_URL as string | undefined);

export const REDIS_HOST    = process.env.REDIS_HOST as string | undefined;
export const REDIS_PORT    = parseInt(process.env.REDIS_PORT    || "6379");
export const REDIS_PASSWORD = process.env.REDIS_PASSWORD;
export const REDIS_DB      = parseInt(process.env.REDIS_DB      || "0");

// In Next.js dev mode, HMR re-imports modules and would create a second
// connection on every hot reload. Cache the client on `global` so it
// survives across module re-evaluations in the same Node process.
declare global {
  // eslint-disable-next-line no-var
  var __redisClient: Redis | undefined | null;
  // eslint-disable-next-line no-var
  var __redisAvailable: boolean;
}

if (global.__redisAvailable === undefined) global.__redisAvailable = false;

export const redis: Redis | undefined = (() => {
  if (global.__redisClient !== undefined) return global.__redisClient ?? undefined;
  const client = createRedisConn();
  global.__redisClient = client ?? null;
  return client;
})();

// Start unavailable — only flip to true once the "ready" event fires.
// Eager connect (lazyConnect:false) ensures the "ready" event fires
// reliably at module init. Commands are rejected until then via _available.
let _available = global.__redisAvailable;

function createRedisConn(): Redis | undefined {
  const opts = {
    maxRetriesPerRequest: 1,
    connectTimeout:       3_000,
    commandTimeout:       2_000,
    lazyConnect:          false,   // Eager connect — "ready" event fires reliably
    enableReadyCheck:     false,
    enableOfflineQueue:   false,
    keepAlive:            10_000,
    retryStrategy(times: number) {
      if (times > 3) return null;
      return Math.min(times * 500, 2_000);
    },
  } as const;

  let client: Redis | undefined;

  try {
    if (REDIS_URL) {
      client = new Redis(REDIS_URL, opts);
    } else if (REDIS_HOST) {
      client = new Redis({
        ...opts,
        host:     REDIS_HOST,
        port:     REDIS_PORT,
        password: REDIS_PASSWORD,
        db:       REDIS_DB,
      });
    }
  } catch (err) {
    console.error("[Redis] Failed to initialise client:", err);
    return undefined;
  }

  if (!client) return undefined;

  client.on("ready",        ()    => { _available = true;  global.__redisAvailable = true;  console.log("[Redis] Connected and ready"); });
  client.on("error",        (err) => { console.error("[Redis]", err.message); });
  client.on("close",        ()    => { _available = false; global.__redisAvailable = false; });
  client.on("reconnecting", ()    => { _available = false; global.__redisAvailable = false; });
  client.on("end",          ()    => { _available = false; global.__redisAvailable = false; });

  return client;
}

export function isRedisAvailable(): boolean {
  return _available || global.__redisAvailable;
}

export async function getRedisValue(key: string): Promise<string | null> {
  if (!redis || !_available) return null;
  try {
    return await redis.get(key);
  } catch (err) {
    console.error(`[Redis] GET error for ${key}:`, (err as Error).message);
    return null;
  }
}

export async function setRedisValue(
  key: string,
  value: string,
  ttl?: number,
): Promise<boolean> {
  if (!redis || !_available) return false;
  try {
    if (ttl && ttl > 0) {
      await redis.set(key, value, "EX", ttl);
    } else {
      await redis.set(key, value);
    }
    return true;
  } catch (err) {
    console.error(`[Redis] SET error for ${key}:`, (err as Error).message);
    return false;
  }
}

export async function deleteRedisValue(key: string): Promise<boolean> {
  if (!redis || !_available) return false;
  try {
    await redis.del(key);
    return true;
  } catch (err) {
    console.error(`[Redis] DEL error for ${key}:`, (err as Error).message);
    return false;
  }
}

/**
 * Deletes all Redis keys matching a glob pattern using SCAN (non-blocking).
 * Returns the number of keys deleted.
 */
export async function deleteRedisKeysByPattern(pattern: string): Promise<number> {
  if (!redis || !_available) return 0;
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
  } catch (err) {
    console.error(`[Redis] SCAN/DEL error for pattern ${pattern}:`, (err as Error).message);
    return 0;
  }
}

/**
 * Atomically increments a counter key and sets its TTL on first increment.
 * Returns the new count, or null if Redis is unavailable.
 * Safe from race conditions: uses Redis INCR (single atomic operation).
 */
export async function incrRedisValue(key: string, ttlSeconds: number): Promise<number | null> {
  if (!redis || !_available) return null;
  try {
    const count = await redis.incr(key);
    if (count === 1) {
      // Only set expire on first increment to avoid resetting the window
      await redis.expire(key, ttlSeconds);
    }
    return count;
  } catch (err) {
    console.error(`[Redis] INCR error for ${key}:`, (err as Error).message);
    return null;
  }
}

export async function getRemainingTtl(key: string): Promise<number | null> {
  if (!redis || !_available) return null;
  try {
    const ttl = await redis.ttl(key);
    return ttl >= 0 ? ttl : null;
  } catch {
    return null;
  }
}

export async function getJsonRedisValue<T>(key: string): Promise<T | null> {
  const raw = await getRedisValue(key);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as T;
  } catch (err) {
    console.error("[Redis] JSON parse error:", err);
    return null;
  }
}

export async function setJsonRedisValue<T>(
  key: string,
  value: T,
  ttl?: number,
): Promise<boolean> {
  try {
    return await setRedisValue(key, JSON.stringify(value), ttl);
  } catch (err) {
    console.error("[Redis] JSON stringify error:", err);
    return false;
  }
}

export async function getJsonRedisValueWithTtl<T>(
  key: string,
): Promise<{ value: T; remainingTtl: number | null } | null> {
  if (!redis || !_available) return null;
  try {
    const [raw, ttl] = await Promise.all([redis.get(key), redis.ttl(key)]);
    if (!raw) return null;
    const value = JSON.parse(raw) as T;
    return { value, remainingTtl: ttl >= 0 ? ttl : null };
  } catch (err) {
    console.error(`[Redis] getWithTtl error for ${key}:`, (err as Error).message);
    return null;
  }
}
