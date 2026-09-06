/**
 * One-time backfill: replay real failures from query_logs into
 * tld_failure_events so the admin failure dashboard has genuine event
 * history (real timestamps, real domains, classified reasons) instead of
 * only the synthetic legacy-migration rows.
 *
 * Usage:  node scripts/backfill-failure-events.mjs
 * Depends on a DB URL env (SUPABASE_DATABASE_URL / DATABASE_URL / etc.),
 * which the script loads from .env.local at repo root.
 *
 * Idempotent: re-running skips rows that are already present (matched on
 * tld + domain + created_at + backfill context), so partial failures can be
 * safely retried without duplicating events.
 */

import fs from "node:fs";
import path from "node:path";
import pg from "pg";

function loadEnvFile(file) {
  const abs = path.resolve(file);
  if (!fs.existsSync(abs)) return;
  for (const line of fs.readFileSync(abs, "utf8").split("\n")) {
    const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
    if (m && !process.env[m[1]]) {
      process.env[m[1]] = m[2].replace(/^"|"$/g, "").replace(/^'|'$/g, "");
    }
  }
}
loadEnvFile(".env.local");
loadEnvFile(".env");

// ── Mirror of src/lib/server/classify-failure.ts (kept in sync) ────────────
const FAILURE_REASONS = [
  "no_server", "dns_failure", "connect_timeout", "socket_error", "http_blocked",
  "http_not_found", "http_server_error", "rdap_error", "empty_response",
  "parse_error", "rate_limited", "third_party_failed", "iana_fallback", "unknown",
];
function classifyFailure(errorMsg, legacyReason) {
  if (legacyReason) {
    if (FAILURE_REASONS.includes(legacyReason)) return legacyReason;
    if (legacyReason === "timeout") return "connect_timeout";
  }
  const m = (errorMsg ?? "").toLowerCase();
  if (!m) return legacyReason === "no_server" ? "no_server" : "unknown";
  if (/enotfound|eai_again|getaddrinfo|nxdomain| EAI_ /i.test(m)) return "dns_failure";
  if (/dns/i.test(m) && /timed out|timeout/i.test(m)) return "dns_failure";
  if (/etimedout|timed out|timeout/i.test(m)) return "connect_timeout";
  if (/econnrefused|econnreset|econnaborted|socket hang up|epipe|broken pipe/i.test(m)) return "socket_error";
  if (/forbidden|cloudflare|challenge|captcha|access denied|blocked/i.test(m) || /\b403\b/.test(m)) return "http_blocked";
  if (/not found|404/i.test(m)) return "http_not_found";
  if (/(^|\D)[5]\d\d(\D|$)/.test(m)) return "http_server_error";
  if (/rate|429|too many/i.test(m)) return "rate_limited";
  if (/empty response|empty whois|zero bytes|no content|returned no data|nothing to parse/i.test(m)) return "empty_response";
  if (/parse|unparseable|unrecognized|invalid json/i.test(m)) return "parse_error";
  return "unknown";
}
function isValidTld(tld) {
  if (!tld || tld.length < 2 || tld.length > 24) return false;
  return /^[a-zA-Z]/.test(tld) && !/^\d+$/.test(tld) && !tld.includes(".");
}

// ── DB connection (mirrors db.ts precedence) ───────────────────────────────
function deriveTransactionModeUrl(sessionUrl) {
  try {
    const u = new URL(sessionUrl);
    if (!u.hostname.includes(".pooler.supabase.com")) return null;
    if (u.port !== "5432") return null;
    u.port = "6543";
    return u.toString();
  } catch { return null; }
}
function getConnectionString() {
  const explicitUrl = process.env.POSTGRES_URL;
  const nonPooling  = process.env.POSTGRES_URL_NON_POOLING;
  if (explicitUrl && nonPooling) {
    try {
      if (new URL(explicitUrl).hostname === new URL(nonPooling).hostname) return explicitUrl;
    } catch { /* fall through */ }
  } else if (explicitUrl && !nonPooling) return explicitUrl;
  for (const varName of ["POSTGRES_URL_NON_POOLING", "SUPABASE_DATABASE_URL", "DATABASE_URL"]) {
    const raw = process.env[varName];
    if (!raw) continue;
    return deriveTransactionModeUrl(raw) || raw;
  }
  return null;
}

async function main() {
  const url = getConnectionString();
  if (!url) {
    console.error("No database URL found. Add POSTGRES_URL / DATABASE_URL to .env.local");
    process.exit(1);
  }
  const client = new pg.Client({
    connectionString: url,
    ssl: { rejectUnauthorized: false },
  });
  await client.connect();

  // Real failure rows from the metric fact source.
  // The anti-dupe check is row-level: a query_logs row is skipped when an
  // event with the same tld + domain + created_at already exists under the
  // backfill context. This stays correct even if a previous run was
  // interrupted mid-way (no unique constraint exists on the table).
  const { rows } = await client.query(
    `SELECT q.tld, q.domain, q.error_code, q.created_at
     FROM query_logs q
     WHERE NOT q.success
       AND char_length(q.tld) BETWEEN 2 AND 24
       AND q.tld ~ '^[a-zA-Z]'
       AND q.tld NOT LIKE '%.%'
       AND NOT EXISTS (
         SELECT 1 FROM tld_failure_events e
         WHERE e.tld = q.tld
           AND e.domain IS NOT DISTINCT FROM q.domain
           AND e.created_at = q.created_at
           AND e.context = 'query-log-backfill'
       )
     ORDER BY q.created_at`,
  );
  console.log(`Found ${rows.length} un-backfilled failure rows in query_logs`);

  let inserted = 0;
  let skipped = 0;
  for (const r of rows) {
    const tld = r.tld.toLowerCase().replace(/^\./, "");
    if (!isValidTld(tld)) { skipped++; continue; }
    const reason = classifyFailure(r.error_code);
    try {
      const res = await client.query(
        `INSERT INTO tld_failure_events (tld, fail_reason, reason_detail, domain, context, created_at)
         VALUES ($1, $2, $3, $4, 'query-log-backfill', $5)
         ON CONFLICT DO NOTHING`,
        [tld, reason, (r.error_code ?? "").slice(0, 300), (r.domain ?? "").slice(0, 253), r.created_at],
      );
      if (res.rowCount > 0) inserted++;
    } catch (e) {
      console.warn(`  skip .${tld}: ${e.message}`);
      skipped++;
    }
  }

  console.log(`Backfill complete: inserted=${inserted} skipped=${skipped}`);
  const chk = await client.query(
    `SELECT (SELECT COUNT(*) FROM tld_failure_events) AS events,
            (SELECT COUNT(*) FROM tld_failure_events WHERE context = 'query-log-backfill') AS backfilled,
            (SELECT COUNT(*) FROM tld_failure_events WHERE context = 'legacy-migration') AS legacy`,
  );
  console.log("State:", JSON.stringify(chk.rows[0]));
  await client.end();
}

main().catch((e) => { console.error(e); process.exit(1); });
