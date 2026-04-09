/**
 * Automated WHOIS query health checker — runs every hour.
 *
 * Analyses the `query_logs` table and fires a webhook alert when:
 *   1. Any TLD's failure rate exceeds FAILURE_RATE_THRESHOLD in the past hour
 *   2. Any TLD has slow cache-miss queries (avg uncached duration > SLOW_QUERY_MS)
 *   3. Any TLD shows a sharp duration spike (recent 30 min vs earlier 30 min)
 *
 * Config via environment variables:
 *   ALERT_WEBHOOK_URL  — Discord or Slack incoming webhook URL (required to send alerts)
 *   ALERT_INTERVAL_MS  — check interval in ms (default: 3 600 000 = 1 hour)
 *
 * Webhook format is auto-detected from the URL:
 *   discord.com  → { "content": "..." }
 *   everything else → { "text": "..." }   (Slack-compatible)
 */

import pg from "pg";

// ── Config ─────────────────────────────────────────────────────────────────
const INTERVAL_MS          = parseInt(process.env.ALERT_INTERVAL_MS || "3600000", 10);
const WEBHOOK_URL          = process.env.ALERT_WEBHOOK_URL || "";
const FAILURE_THRESHOLD    = 0.20;    // 20 % failure rate
const MIN_QUERIES          = 5;       // minimum total queries to trigger a failure alert
const SLOW_QUERY_MS        = 5000;    // avg uncached duration that counts as "slow"
const MIN_MISS_QUERIES     = 3;       // minimum cache-miss queries for slow-query alert
const TREND_MIN_QUERIES    = 5;       // minimum queries per window for trend alert
const TREND_RATIO          = 2.0;    // recent avg must be ≥ 2× earlier avg to alert

// ── DB connection (mirrors logic in db.ts / keep-alive.mjs) ────────────────
function deriveTransactionModeUrl(url) {
  try {
    const u = new URL(url);
    if (!u.hostname.includes(".pooler.supabase.com")) return null;
    if (u.port !== "5432") return null;
    u.port = "6543";
    return u.toString();
  } catch { return null; }
}

function resolveDbUrl() {
  const explicit    = process.env.POSTGRES_URL;
  const nonPooling  = process.env.POSTGRES_URL_NON_POOLING;
  if (explicit && nonPooling) {
    try {
      if (new URL(explicit).hostname === new URL(nonPooling).hostname)
        return explicit;
    } catch { /* fall through */ }
  }
  if (explicit && !nonPooling)  return explicit;
  if (nonPooling) return deriveTransactionModeUrl(nonPooling) ?? nonPooling;
  const supabaseUrl = process.env.SUPABASE_DATABASE_URL;
  if (supabaseUrl) return deriveTransactionModeUrl(supabaseUrl) ?? supabaseUrl;
  const dbUrl = process.env.DATABASE_URL;
  if (dbUrl) return deriveTransactionModeUrl(dbUrl) ?? dbUrl;
  return null;
}

const DB_URL = resolveDbUrl();

if (!DB_URL) {
  console.error("[alert] 无数据库 URL — 请设置 POSTGRES_URL 或 SUPABASE_DATABASE_URL。");
  process.exit(1);
}

function buildSslConfig(url) {
  try {
    const h = new URL(url).hostname;
    if (h === "localhost" || h === "127.0.0.1" || !h.includes(".")) return false;
  } catch { /* ignore */ }
  return { rejectUnauthorized: false };
}

const pool = new pg.Pool({
  connectionString: DB_URL,
  max: 2,
  ssl: buildSslConfig(DB_URL),
});

// ── Helpers ────────────────────────────────────────────────────────────────
function fmtMs(ms) {
  const n = Number(ms);
  return n >= 1000 ? `${(n / 1000).toFixed(1)}s` : `${Math.round(n)}ms`;
}

function tag(label) {
  return `[alert] ${new Date().toISOString()} ${label}`;
}

// ── Core analysis queries ──────────────────────────────────────────────────
// Each pool.query() acquires its own connection, so all three can safely run
// in parallel without triggering the pg "already executing" deprecation.
async function analyse() {
  const [failureRows, slowRows, trendRows] = await Promise.all([
    // 1. TLD failure rate in the past hour
    pool.query(`
      SELECT
        tld,
        COUNT(*)                                      AS total,
        COUNT(*) FILTER (WHERE NOT success)           AS failures,
        ROUND(
          COUNT(*) FILTER (WHERE NOT success)::numeric
          / COUNT(*) * 100, 1
        )                                             AS pct,
        MODE() WITHIN GROUP (ORDER BY error_code)     AS top_error
      FROM query_logs
      WHERE created_at > NOW() - INTERVAL '1 hour'
      GROUP BY tld
      HAVING
        COUNT(*) >= $1
        AND COUNT(*) FILTER (WHERE NOT success)::numeric / COUNT(*) >= $2
      ORDER BY pct DESC
      LIMIT 10
    `, [MIN_QUERIES, FAILURE_THRESHOLD]),

    // 2. Slow cache-miss TLDs in the past hour
    pool.query(`
      SELECT
        tld,
        COUNT(*)                AS miss_count,
        ROUND(AVG(duration_ms)) AS avg_ms,
        MAX(duration_ms)        AS max_ms
      FROM query_logs
      WHERE created_at > NOW() - INTERVAL '1 hour'
        AND NOT cached
        AND success
      GROUP BY tld
      HAVING
        COUNT(*) >= $1
        AND AVG(duration_ms) > $2
      ORDER BY avg_ms DESC
      LIMIT 10
    `, [MIN_MISS_QUERIES, SLOW_QUERY_MS]),

    // 3. Sharp duration spike: recent 30 min vs earlier 30 min
    pool.query(`
      WITH early AS (
        SELECT tld, AVG(duration_ms) AS avg_ms, COUNT(*) AS cnt
        FROM query_logs
        WHERE created_at BETWEEN NOW() - INTERVAL '1 hour' AND NOW() - INTERVAL '30 minutes'
        GROUP BY tld
        HAVING COUNT(*) >= $1
      ),
      recent AS (
        SELECT tld, AVG(duration_ms) AS avg_ms, COUNT(*) AS cnt
        FROM query_logs
        WHERE created_at > NOW() - INTERVAL '30 minutes'
        GROUP BY tld
        HAVING COUNT(*) >= $1
      )
      SELECT
        r.tld,
        ROUND(e.avg_ms)                           AS early_ms,
        ROUND(r.avg_ms)                           AS recent_ms,
        ROUND(r.avg_ms / NULLIF(e.avg_ms, 0), 2) AS ratio
      FROM recent r
      JOIN early e USING (tld)
      WHERE r.avg_ms / NULLIF(e.avg_ms, 0) >= $2
      ORDER BY ratio DESC
      LIMIT 5
    `, [TREND_MIN_QUERIES, TREND_RATIO]),
  ]);

  return {
    failures: failureRows.rows,
    slow:     slowRows.rows,
    trends:   trendRows.rows,
  };
}

// ── Alert formatting ───────────────────────────────────────────────────────
function buildMessage({ failures, slow, trends }) {
  const lines = [];
  const ts = new Date().toLocaleString("zh-CN", {
    timeZone: "Asia/Shanghai",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit",
  });

  lines.push(`🚨 **WHOIS 查询健康告警** | ${ts} CST`);

  if (failures.length > 0) {
    lines.push(`\n❌ **TLD 失败率 > ${FAILURE_THRESHOLD * 100}%（过去 1 小时）**`);
    for (const r of failures) {
      const errHint = r.top_error ? `  最常见错误: \`${r.top_error.slice(0, 50)}\`` : "";
      lines.push(`  \`.${r.tld}\` — ${r.pct}% 失败 (${r.failures}/${r.total} 次)${errHint}`);
    }
  }

  if (slow.length > 0) {
    lines.push(`\n🐌 **慢查询 TLD（未命中缓存，平均 > ${fmtMs(SLOW_QUERY_MS)}）**`);
    for (const r of slow) {
      lines.push(`  \`.${r.tld}\` — 平均 ${fmtMs(r.avg_ms)}，峰值 ${fmtMs(r.max_ms)} (${r.miss_count} 次未命中)`);
    }
    lines.push(`  ↳ 建议：延长该 TLD 缓存 TTL，或排查上游注册局限速。`);
  }

  if (trends.length > 0) {
    lines.push(`\n📈 **耗时骤增（最近 30 分钟 vs 前 30 分钟，翻倍以上）**`);
    for (const r of trends) {
      lines.push(`  \`.${r.tld}\` — ${fmtMs(r.early_ms)} → ${fmtMs(r.recent_ms)} (×${r.ratio})`);
    }
    lines.push(`  ↳ 建议：检查上游注册局是否在限流，必要时启用熔断。`);
  }

  return lines.join("\n");
}

// ── Webhook sender ─────────────────────────────────────────────────────────
async function sendWebhook(message) {
  if (!WEBHOOK_URL) {
    console.warn(tag("⚠  ALERT_WEBHOOK_URL 未配置，告警仅打印到日志。"));
    return;
  }

  const isDiscord = WEBHOOK_URL.includes("discord.com");
  const body      = isDiscord ? { content: message } : { text: message };

  try {
    const res = await fetch(WEBHOOK_URL, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(body),
    });
    if (res.ok) {
      console.log(tag("✓ 告警已发送至 Webhook。"));
    } else {
      const text = await res.text().catch(() => "");
      console.error(tag(`✗ Webhook 返回 ${res.status}: ${text.slice(0, 200)}`));
    }
  } catch (err) {
    console.error(tag(`✗ Webhook 发送失败: ${err.message}`));
  }
}

// ── Main check cycle ───────────────────────────────────────────────────────
async function runCheck() {
  try {
    const data = await analyse();
    const { failures, slow, trends } = data;
    const hasAlert = failures.length > 0 || slow.length > 0 || trends.length > 0;

    if (!hasAlert) {
      console.log(tag(`✓ 一切正常。失败 TLD: 0 | 慢 TLD: 0 | 骤增 TLD: 0`));
      return;
    }

    const message = buildMessage(data);
    console.log(tag("发现告警:"));
    console.log(message);
    await sendWebhook(message);
  } catch (err) {
    // query_logs table may not exist yet (migrations run on first HTTP request)
    if (err.message?.includes("query_logs")) {
      console.log(tag("✓ query_logs 表尚无数据（首次查询后将自动创建）。"));
    } else {
      console.error(tag(`✗ 分析失败: ${err.message}`));
    }
  }
}

// ── Entry point ─────────────────────────────────────────────────────────────
const intervalMin = Math.round(INTERVAL_MS / 60000);
console.log(`[alert] 启动告警检查器，每 ${intervalMin} 分钟执行一次。`);
if (!WEBHOOK_URL) {
  console.warn(`[alert] ⚠  未配置 ALERT_WEBHOOK_URL — 告警仅打印到控制台。`);
  console.warn(`[alert]    Discord: 在服务器设置 → 集成 → Webhooks 中创建，然后设置环境变量。`);
  console.warn(`[alert]    Slack:   在 api.slack.com/apps 中创建 Incoming Webhook，然后设置环境变量。`);
}

await runCheck();
setInterval(runCheck, INTERVAL_MS);
