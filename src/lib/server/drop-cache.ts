/**
 * Cache helpers for the drop-calendar query layer.
 */

import { redis, isRedisAvailable } from "./redis";

export const DROP_CACHE_PREFIX = "drops:v1:";

/** Drop every cached drop-calendar response so the next read refetches. */
export async function invalidateDropCache(): Promise<void> {
  if (!isRedisAvailable() || !redis) return;
  try {
    const keys = await redis.keys(`${DROP_CACHE_PREFIX}*`);
    if (keys.length) await redis.del(...keys);
  } catch { /* cache is best-effort */ }
}
