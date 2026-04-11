interface CacheEntry<T> {
  data: T;
  fetchedAt: number;
}

const store = new Map<string, CacheEntry<unknown>>();

export function getCached<T>(key: string, ttlMs: number): T | null {
  const entry = store.get(key) as CacheEntry<T> | undefined;
  if (entry && Date.now() - entry.fetchedAt < ttlMs) return entry.data;
  return null;
}

export function setCached<T>(key: string, data: T): void {
  store.set(key, { data, fetchedAt: Date.now() });
}

export function invalidateCache(key: string): void {
  store.delete(key);
}

/** Invalidate all cache entries whose key starts with the given prefix. */
export function invalidateCachePrefix(prefix: string): void {
  for (const key of store.keys()) {
    if (key.startsWith(prefix)) store.delete(key);
  }
}
