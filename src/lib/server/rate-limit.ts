/**
 * Lightweight in-process sliding-window rate limiter.
 * Works across route handlers in a single Node.js process.
 * When Redis is available it is not used here; the in-process store
 * is sufficient for a single-server deployment and adds zero I/O latency.
 */

interface Window {
  timestamps: number[];
}

const store = new Map<string, Window>();

// Housekeeping: clear stale entries every 5 minutes so the Map never grows unbounded.
// An entry is stale when its newest timestamp is older than the rate-limit window
// used by callers (lookup.ts: 60 s). Increase MAX_WINDOW_MS if new callers use longer windows.
const CLEANUP_INTERVAL_MS = 5 * 60 * 1_000;
const MAX_WINDOW_MS = 60_000;
if (typeof setInterval !== "undefined") {
  setInterval(() => {
    const now = Date.now();
    store.forEach((win, key) => {
      if (!win.timestamps.length || now - win.timestamps[win.timestamps.length - 1] > MAX_WINDOW_MS) {
        store.delete(key);
      }
    });
  }, CLEANUP_INTERVAL_MS).unref?.();
}

/**
 * Check whether the caller identified by `key` (typically an IP address) has
 * exceeded `limit` requests in the last `windowMs` milliseconds.
 *
 * @returns `{ allowed: boolean; remaining: number; resetMs: number }`
 */
export function rateLimit(
  key: string,
  limit: number,
  windowMs: number,
): { allowed: boolean; remaining: number; resetMs: number } {
  const now = Date.now();
  const cutoff = now - windowMs;

  let win = store.get(key);
  if (!win) {
    win = { timestamps: [] };
    store.set(key, win);
  }

  // Drop timestamps outside the window.
  win.timestamps = win.timestamps.filter((t) => t > cutoff);

  const count = win.timestamps.length;
  const allowed = count < limit;

  if (allowed) {
    win.timestamps.push(now);
  }

  const oldest = win.timestamps[0] ?? now;
  const resetMs = oldest + windowMs - now;

  return {
    allowed,
    remaining: Math.max(0, limit - win.timestamps.length),
    resetMs: Math.max(0, resetMs),
  };
}

/**
 * Extract the best-guess IP address from a Next.js API request.
 */
export function getClientIp(req: import("next").NextApiRequest): string {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string") {
    return forwarded.split(",")[0].trim();
  }
  return (req.socket as any)?.remoteAddress ?? "unknown";
}
