/**
 * Keep-Alive — 每隔 4 分钟 ping 一次数据库，防止 Supabase 连接池休眠。
 *
 * 用法:
 *   node scripts/keep-alive.mjs
 */

import pg from "pg";

const INTERVAL_MS = 4 * 60 * 1000; // 4 分钟
const DB_URL = process.env.POSTGRES_URL;

if (!DB_URL) {
  console.error("[keep-alive] 缺少 POSTGRES_URL 环境变量，退出。");
  process.exit(1);
}

const pool = new pg.Pool({ connectionString: DB_URL, max: 1 });

async function ping() {
  const t0 = Date.now();
  try {
    await pool.query("SELECT 1");
    console.log(`[keep-alive] ${new Date().toISOString()} ✓ DB ping OK (${Date.now() - t0}ms)`);
  } catch (err) {
    console.error(`[keep-alive] ${new Date().toISOString()} ✗ DB ping 失败:`, err.message);
  }
}

console.log(`[keep-alive] 启动，每 ${INTERVAL_MS / 1000}s ping 一次 DB…`);
await ping();
setInterval(ping, INTERVAL_MS);
