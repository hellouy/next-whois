/**
 * Keep-Alive — 每隔 4 分钟 ping 一次数据库，防止 Supabase 连接池休眠。
 *
 * 用法:
 *   node scripts/keep-alive.mjs
 */

import pg from "pg";

const INTERVAL_MS = 4 * 60 * 1000; // 4 分钟

// Auto-derive Transaction Mode URL (port 6543) from Session Mode URL (port 5432).
// Transaction mode supports many more concurrent connections on Vercel/serverless.
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

  // Use POSTGRES_URL only if it matches the same host as NON_POOLING (same project)
  if (explicitUrl && nonPoolingUrl) {
    try {
      const eu = new URL(explicitUrl);
      const nu = new URL(nonPoolingUrl);
      if (eu.hostname === nu.hostname) return { url: explicitUrl, source: "POSTGRES_URL" };
    } catch { /* fall through */ }
  } else if (explicitUrl && !nonPoolingUrl) {
    return { url: explicitUrl, source: "POSTGRES_URL" };
  }

  // Auto-derive TX mode from NON_POOLING
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
  console.error("[keep-alive] 缺少数据库 URL 环境变量，退出。请设置 POSTGRES_URL 或 POSTGRES_URL_NON_POOLING。");
  process.exit(1);
}

// Disable SSL for internal hosts (e.g. helium), enable for cloud databases
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
    console.error(`[keep-alive] ${new Date().toISOString()} ✗ DB ping 失败:`, err.message);
  }
}

console.log(`[keep-alive] 启动，每 ${INTERVAL_MS / 1000}s ping 一次 DB… (source: ${resolved?.source ?? "none"})`);
await ping();
setInterval(ping, INTERVAL_MS);
