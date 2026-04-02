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

  const fallback = process.env.SUPABASE_DATABASE_URL || process.env.DATABASE_URL;
  if (fallback) return { url: fallback, source: "DATABASE_URL" };
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

  const pool = new pg.Pool({ connectionString: DB_URL, max: 1, ssl: sslConfig });

  async function ping() {
    const t0 = Date.now();
    try {
      await pool.query("SELECT 1");
      console.log(`[keep-alive] ${new Date().toISOString()} ✓ DB ping OK (${Date.now() - t0}ms)`);
    } catch (err) {
      console.error(`[keep-alive] ${new Date().toISOString()} ✗ DB ping failed:`, err.message);
    }
  }

  console.log(`[keep-alive] Started, pinging DB every ${INTERVAL_MS / 1000}s… (source: ${resolved.source})`);
  await ping();
  setInterval(ping, INTERVAL_MS);
}
