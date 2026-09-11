import { isDbReady, run } from "@/lib/db-query";
import { isRedisAvailable, incrRedisValue } from "@/lib/server/redis";

const DEFAULT_WINDOW_MS = 60_000;

// Local in-memory cache (within same warm lambda instance only).
// Holds either a REJECT marker copied from Redis (rejected=true, used as a
// zero-network fast-path 429) or a count+resetAt for the Redis-less fallback.
type LocalRateEntry =
  | { resetAt: number; rejected: true }
  | { resetAt: number; rejected: false; count: number };
const localCache = new Map<string, LocalRateEntry>();

setInterval(() => {
  const now = Date.now();
  localCache.forEach((val, key) => {
    if (now > val.resetAt) localCache.delete(key);
  });
}, 120_000).unref?.();

// ─── Redis backend (preferred for Vercel — survives across function instances) ─
// Uses atomic INCR to avoid GET→SET race conditions under concurrent requests.

async function checkRedisRateLimit(
  ip: string,
  maxRequests: number,
  windowMs: number,
): Promise<{ ok: boolean; remaining: number; resetMs: number } | null> {
  if (!isRedisAvailable()) return null;
  const windowKey = Math.floor(Date.now() / windowMs);
  const key = `rl:${ip}:${windowKey}`;
  const ttlSeconds = Math.ceil(windowMs / 1000);
  const count = await incrRedisValue(key, ttlSeconds);
  if (count === null) return null;
  if (count > maxRequests) return { ok: false, remaining: 0, resetMs: (windowKey + 1) * windowMs - Date.now() };
  return { ok: true, remaining: Math.max(0, maxRequests - count), resetMs: (windowKey + 1) * windowMs - Date.now() };
}

// ─── DB stats backend (fallback when Redis unavailable) ────────────────────
// When Redis is down, the allow/deny decision is made in local memory (fast,
// zero network).  The DB row is only kept fresh for the admin dashboard
// (system.ts counts/clears stale rows) — it is written ASYNC and never awaited
// on the hot path, because a synchronous Postgres round-trip on every request
// would add ~1-2 s of pre-lookup latency on Redis-less deployments.

async function writeDbRateStats(
  ip: string,
  windowMs: number,
  count: number,
): Promise<void> {
  if (!(await isDbReady())) return;
  const resetAt = new Date(Date.now() + windowMs);
  try {
    await run(
      `INSERT INTO rate_limit_records (key, count, reset_at)
       VALUES ($1, $2, $3)
       ON CONFLICT (key) DO UPDATE
         SET count    = rate_limit_records.count + $2,
             reset_at = CASE WHEN rate_limit_records.reset_at < NOW() THEN $3
                             ELSE rate_limit_records.reset_at END`,
      [ip, count, resetAt.toISOString()],
    );
  } catch {
    // Best-effort stats only — never fail the request.
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

export interface RateLimitResult {
  ok: boolean;
  remaining: number;
  /** Milliseconds until the current window resets (0 when already expired). */
  resetMs: number;
}

export async function checkRateLimit(
  ip: string,
  maxRequests = 5,
  windowMs = DEFAULT_WINDOW_MS,
): Promise<RateLimitResult> {
  const now = Date.now();

  // L1: fast-path REJECT cache only. Populated exclusively when the shared
  // Redis source reports the current window exhausted — subsequent requests
  // from the same warm instance get a zero-network 429 without re-touching
  // Redis. NEVER serves "allowed" decisions: positive counts always go to
  // Redis so the counter stays shared across function instances.
  const local = localCache.get(ip);
  if (local && now <= local.resetAt && local.rejected) {
    return { ok: false, remaining: 0, resetMs: Math.max(0, local.resetAt - now) };
  }

  // L2: Redis shared counter — consulted on EVERY request. Redis owns the
  // absolute window key (floor(now/windowMs)); caching positive counts here
  // previously skipped Redis INCRs (letting a multi-instance fleet multiply
  // the quota) and used a relative window (now+windowMs) that drifted from
  // Redis's absolute window edge, mis-limiting users at window boundaries.
  const redisResult = await checkRedisRateLimit(ip, maxRequests, windowMs);
  if (redisResult !== null) {
    if (!redisResult.ok) {
      localCache.set(ip, { rejected: true, resetAt: Date.now() + redisResult.resetMs });
    }
    return redisResult;
  }

  // L3: Redis unavailable → decide in local memory, write stats async.
  // This must never block: a synchronous DB round-trip here is what pushed
  // page latency past 2 s on deployments without Redis (measured on the
  // lookup-stream pre-lookup path).  Local-memory limiting is per-instance,
  // which is a fine trade-off when Redis is down; Redis is the shared source
  // of truth when it is available under L2.
  const entry = localCache.get(ip);
  if (!entry || now > entry.resetAt) {
    localCache.set(ip, { count: 1, resetAt: now + windowMs, rejected: false });
    // Async stats write for the admin dashboard (never awaited).
    void writeDbRateStats(ip, windowMs, 1);
    return { ok: true, remaining: maxRequests - 1, resetMs: windowMs };
  }
  if (entry.rejected) return { ok: false, remaining: 0, resetMs: Math.max(0, entry.resetAt - now) };
  if (entry.count >= maxRequests) return { ok: false, remaining: 0, resetMs: Math.max(0, entry.resetAt - now) };
  entry.count += 1;
  return { ok: true, remaining: maxRequests - entry.count, resetMs: Math.max(0, entry.resetAt - now) };
}

/**
 * Extract the best-guess IP address from a Next.js API request.
 * Shared by every rate-limited endpoint.
 */
export function getClientIp(req: import("next").NextApiRequest): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") {
    return forwarded.split(",")[0].trim();
  }
  return (req.socket as any)?.remoteAddress ?? "unknown";
}
