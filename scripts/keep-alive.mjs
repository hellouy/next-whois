/**
 * Keep-Alive — ping the database every 4 minutes to prevent Supabase connection pool from sleeping.
 */

import pg from "pg";

const INTERVAL_MS = 4 * 60 * 1000;

function deriveTransactionModeUrl(sessionUrl) {
  try {
    const u = new URL(sessionUrl);
    if (!u.hostname.includes(".pooler.supabase.com")) return null;
    if (u.port !== "5432") return null;
    u.port = "6543";
    return u.toString();
  } catch { return null; }
}

function resolveDbUrl() {
  const explicitUrl = process.env.POSTGRES_URL;
  const nonPoolingUrl = process.env.POSTGRES_URL_NON_POOLING;

  if (explicitUrl && nonPoolingUrl) {
    try {
      const eu = new URL(explicitUrl);
      const nu = new URL(nonPoolingUrl);
      if (eu.hostname === nu.hostname) return { url: explicitUrl, source: "POSTGRES_URL" };
    } catch { /* fall through */ }
  } else if (explicitUrl && !nonPoolingUrl) {
    return { url: explicitUrl, source: "POSTGRES_URL" };
  }

  if (nonPoolingUrl) {
    const txUrl = deriveTransactionModeUrl(nonPoolingUrl);
    if (txUrl) return { url: txUrl, source: "POSTGRES_URL_NON_POOLING→TX" };
    return { url: nonPoolingUrl, source: "POSTGRES_URL_NON_POOLING" };
  }

  if (process.env.SUPABASE_DATABASE_URL) {
    const txUrl = deriveTransactionModeUrl(process.env.SUPABASE_DATABASE_URL);
    if (txUrl) return { url: txUrl, source: "SUPABASE_DATABASE_URL→TX" };
    return { url: process.env.SUPABASE_DATABASE_URL, source: "SUPABASE_DATABASE_URL" };
  }
  if (process.env.DATABASE_URL) {
    const txUrl = deriveTransactionModeUrl(process.env.DATABASE_URL);
    if (txUrl) return { url: txUrl, source: "DATABASE_URL→TX" };
    return { url: process.env.DATABASE_URL, source: "DATABASE_URL" };
  }
  return null;
}

const resolved = resolveDbUrl();
const DB_URL = resolved?.url;

if (!DB_URL) {
  console.warn("[keep-alive] No database URL found. Set POSTGRES_URL or POSTGRES_URL_NON_POOLING to enable keep-alive pings.");
  console.warn("[keep-alive] Sleeping — no pings will be sent until a DB URL is configured.");
  setInterval(() => {}, 60 * 60 * 1000);
} else {
  let sslConfig;
  try {
    const u = new URL(DB_URL);
    const h = u.hostname;
    sslConfig = (h === "localhost" || h === "127.0.0.1" || h === "helium" || !h.includes("."))
      ? false
      : { rejectUnauthorized: false };
  } catch {
    sslConfig = { rejectUnauthorized: false };
  }

  const poolOpts = { connectionString: DB_URL, max: 1, ssl: sslConfig,
                     connectionTimeoutMillis: 15_000, idleTimeoutMillis: 30_000 };
  let pool = new pg.Pool(poolOpts);
  let consecutiveFails = 0;
  const MAX_FAILS_BEFORE_RESET = 3;

  async function ping() {
    const t0 = Date.now();
    try {
      await pool.query("SELECT 1");
      if (consecutiveFails > 0) {
        console.log(`[keep-alive] ${new Date().toISOString()} ✓ DB recovered after ${consecutiveFails} failure(s) (${Date.now() - t0}ms)`);
      } else {
        console.log(`[keep-alive] ${new Date().toISOString()} ✓ DB ping OK (${Date.now() - t0}ms)`);
      }
      consecutiveFails = 0;
    } catch (err) {
      consecutiveFails++;
      console.error(`[keep-alive] ${new Date().toISOString()} ✗ DB ping failed (#${consecutiveFails}):`, err.message);
      // Recreate the pool after repeated failures — clears stale connections
      if (consecutiveFails >= MAX_FAILS_BEFORE_RESET) {
        console.warn(`[keep-alive] ${new Date().toISOString()} ⚠ Recreating DB pool after ${consecutiveFails} consecutive failures`);
        await pool.end().catch(() => {});
        pool = new pg.Pool(poolOpts);
        consecutiveFails = 0;
      }
    }
  }

  console.log(`[keep-alive] Started, pinging DB every ${INTERVAL_MS / 1000}s… (source: ${resolved.source})`);
  await ping();
  setInterval(ping, INTERVAL_MS);
}
