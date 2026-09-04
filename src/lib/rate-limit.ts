import { isDbReady, one, run } from "@/lib/db-query";
import { isRedisAvailable, incrRedisValue } from "@/lib/server/redis";

const DEFAULT_WINDOW_MS = 60_000;

// Local in-memory fallback (within same warm lambda instance only)
const localCache = new Map<string, { count: number; resetAt: number }>();

setInterval(() => {
  const now = Date.now();
  localCache.forEach((val, key) => {
    if (now > val.resetAt) localCache.delete(key);
  });
}, 120_000);

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

// ─── Supabase DB backend (fallback when Redis unavailable) ────────────────────

async function checkDbRateLimit(
  ip: string,
  maxRequests: number,
  windowMs: number,
): Promise<{ ok: boolean; remaining: number; resetMs: number } | null> {
  if (!(await isDbReady())) return null;
  const resetAt = new Date(Date.now() + windowMs);
  try {
    await run(
      `INSERT INTO rate_limit_records (key, count, reset_at)
       VALUES ($1, 1, $2)
       ON CONFLICT (key) DO UPDATE
         SET count    = CASE WHEN rate_limit_records.reset_at < NOW() THEN 1
                             ELSE rate_limit_records.count + 1 END,
             reset_at = CASE WHEN rate_limit_records.reset_at < NOW() THEN $2
                             ELSE rate_limit_records.reset_at END`,
      [ip, resetAt.toISOString()],
    );
    const row = await one<{ count: number; reset_at: string }>(
      "SELECT count, reset_at FROM rate_limit_records WHERE key = $1",
      [ip],
    );
    const count = row?.count ?? 1;
    const rowResetAt = row ? new Date(row.reset_at).getTime() : Date.now() + windowMs;
    localCache.set(ip, { count, resetAt: rowResetAt });
    if (count > maxRequests) return { ok: false, remaining: 0, resetMs: Math.max(0, rowResetAt - Date.now()) };
    return { ok: true, remaining: Math.max(0, maxRequests - count), resetMs: Math.max(0, rowResetAt - Date.now()) };
  } catch {
    return null;
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

  // L1: local in-memory (fastest — zero latency within same warm instance)
  const local = localCache.get(ip);
  if (local && now <= local.resetAt) {
    if (local.count >= maxRequests) return { ok: false, remaining: 0, resetMs: Math.max(0, local.resetAt - now) };
    local.count += 1;
    return { ok: true, remaining: maxRequests - local.count, resetMs: Math.max(0, local.resetAt - now) };
  }

  // L2: Redis
  const redisResult = await checkRedisRateLimit(ip, maxRequests, windowMs);
  if (redisResult !== null) {
    if (redisResult.ok) {
      const used = maxRequests - redisResult.remaining;
      localCache.set(ip, { count: used, resetAt: now + windowMs });
    }
    return redisResult;
  }

  // L3: Supabase DB
  const dbResult = await checkDbRateLimit(ip, maxRequests, windowMs);
  if (dbResult !== null) return dbResult;

  // L4: local in-memory only (no Redis, no DB)
  const entry = localCache.get(ip);
  if (!entry || now > entry.resetAt) {
    localCache.set(ip, { count: 1, resetAt: now + windowMs });
    return { ok: true, remaining: maxRequests - 1, resetMs: windowMs };
  }
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
