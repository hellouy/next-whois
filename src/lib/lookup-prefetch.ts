/**
 * lookup-prefetch.ts
 *
 * Fires /api/lookup fetch requests as early as possible — the moment the user
 * submits a search — so the WHOIS query is already in-flight while Next.js
 * does its SSR + page hydration cycle (~400-700 ms).  By the time the result
 * page mounts and its useEffect runs, the response is often already waiting.
 *
 * Usage:
 *   1. Call `prefetchLookup(target)` right before `router.push(...)`.
 *   2. In the fetch useEffect, call `consumePrefetch(target)` to get the
 *      in-flight promise (or undefined if none exists).
 */

const MAX_ENTRIES = 10;
const TTL_MS = 30_000;

interface PrefetchEntry {
  promise: Promise<Response>;
  createdAt: number;
}

const cache = new Map<string, PrefetchEntry>();

function evict() {
  const now = Date.now();
  for (const [key, entry] of cache.entries()) {
    if (now - entry.createdAt > TTL_MS) cache.delete(key);
  }
  while (cache.size > MAX_ENTRIES) {
    cache.delete(cache.keys().next().value!);
  }
}

/**
 * Starts a /api/lookup fetch for `target` and caches the pending Promise.
 * Safe to call multiple times — a second call for the same target within the
 * TTL window is a no-op (the existing promise is reused).
 */
export function prefetchLookup(target: string): void {
  if (!target) return;
  evict();
  if (cache.has(target)) return;
  const promise = fetch(`/api/lookup?query=${encodeURIComponent(target)}`);
  cache.set(target, { promise, createdAt: Date.now() });
}

/**
 * Returns and removes the cached Promise for `target`, or undefined if none.
 * Call this in the fetch useEffect to use the pre-started request.
 */
export function consumePrefetch(target: string): Promise<Response> | undefined {
  const entry = cache.get(target);
  if (!entry) return undefined;
  cache.delete(target);
  if (Date.now() - entry.createdAt > TTL_MS) return undefined;
  return entry.promise;
}
