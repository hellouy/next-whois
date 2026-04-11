/**
 * Module-level client-side cache.
 *
 * Because Next.js unmounts and remounts page components on route changes,
 * any React state is lost. This module keeps a process-level Map so that
 * data fetched once can be immediately restored when the user navigates back
 * to the same page — no blank loading spinners on revisits.
 *
 * Usage:
 *   const [data, setData] = useState(() => getPageCache<MyType>("my_key"));
 *
 *   useEffect(() => {
 *     if (data) return;           // already have fresh data, skip
 *     fetch("/api/...").then(r => r.json()).then(d => {
 *       setData(d);
 *       setPageCache("my_key", d, 120_000); // 2-min TTL
 *     });
 *   }, []);
 */

type CacheEntry<T = unknown> = { data: T; ts: number; ttl: number };
const _cache = new Map<string, CacheEntry>();

/** Return cached value if still fresh, or null if missing / expired. */
export function getPageCache<T>(key: string): T | null {
  const e = _cache.get(key) as CacheEntry<T> | undefined;
  if (!e) return null;
  if (Date.now() - e.ts > e.ttl) {
    _cache.delete(key);
    return null;
  }
  return e.data;
}

/** Store a value with the given TTL in milliseconds (default 2 minutes). */
export function setPageCache<T>(key: string, data: T, ttlMs = 120_000): void {
  _cache.set(key, { data, ts: Date.now(), ttl: ttlMs });
}

/** Evict one key (or all keys if none given). */
export function clearPageCache(key?: string): void {
  if (key) _cache.delete(key);
  else _cache.clear();
}

/** Returns true when a non-expired entry exists for the given key. */
export function hasPageCache(key: string): boolean {
  return getPageCache(key) !== null;
}
