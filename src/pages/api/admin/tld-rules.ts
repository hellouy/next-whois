import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { one, run, many } from "@/lib/db-query";
import {
  isRedisAvailable,
  getRedisValue,
  setRedisValue,
  deleteRedisValue,
} from "@/lib/server/redis";
import { createLogger } from "@/lib/logger";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { invalidateLifecycleOverridesCache } from "@/lib/server/lifecycle-overrides";
import {
  scrapeTld,
  validatePublicUrl,
  SCRAPE_CACHE_KEY,
  hasLifecycleInfo,
} from "@/lib/server/tld-scrape";

const logger = createLogger("api/admin/tld-rules");

// ─── Local JSON file cache (best-effort, fails silently in read-only envs) ────
const LOCAL_CACHE_PATH = join(process.cwd(), "data", "tld-rules.json");

function updateLocalCache(tld: string, data: Record<string, unknown>): void {
  try {
    const dir = join(process.cwd(), "data");
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    let cache: { generated_at: string; count: number; rules: Record<string, unknown> } =
      { generated_at: "", count: 0, rules: {} };
    if (existsSync(LOCAL_CACHE_PATH)) {
      try { cache = JSON.parse(readFileSync(LOCAL_CACHE_PATH, "utf8")); } catch {}
    }
    cache.rules[tld] = { ...data, saved_at: new Date().toISOString() };
    cache.count = Object.keys(cache.rules).length;
    cache.generated_at = new Date().toISOString();
    writeFileSync(LOCAL_CACHE_PATH, JSON.stringify(cache, null, 2), "utf8");
  } catch (e) {
    // Silent: production (Vercel) has read-only FS; local backup is best-effort
    logger.warn("[tld-rules] local-cache write skipped:", (e as Error).message);
  }
}

// ─── Rate limiting ────────────────────────────────────────────────────────────
const RATE_LIMIT_KEY = (tld: string) => `tld_rules_rl:${tld}`;
const RATE_LIMIT_TTL_S = 60 * 60; // 1 request per TLD per hour

async function checkRateLimit(tld: string): Promise<boolean> {
  if (!isRedisAvailable()) return true; // skip if no Redis
  const key = RATE_LIMIT_KEY(tld);
  const val = await getRedisValue(key);
  if (val) return false;
  await setRedisValue(key, "1", RATE_LIMIT_TTL_S);
  return true;
}

// ─── Fetch runtime IANA root-zone non-IDN TLD count with 24h cache (R9) ───────
async function fetchIanaTotalLive(): Promise<number | null> {
  const key = "iana:root_zone_total_v2";
  if (isRedisAvailable()) {
    try {
      const cached = await getRedisValue(key);
      if (cached) {
        const n = parseInt(cached, 10);
        if (!Number.isNaN(n) && n > 1000) return n;
      }
    } catch { /* fall through */ }
  }
  try {
    const resp = await fetch("https://data.iana.org/TLD/tlds-alpha-by-domain.txt", {
      headers: { "User-Agent": "next-whois-ui/1.0 (domain lifecycle tool)" },
      signal: AbortSignal.timeout(8_000),
    });
    if (!resp.ok) return null;
    const text = await resp.text();
    const all = text
      .split(/\r?\n/)
      .map((l) => l.trim().toLowerCase())
      .filter((t) => t && !t.startsWith("#"));
    const n = all.filter((t) => !t.startsWith("xn--")).length;
    if (isRedisAvailable()) {
      await setRedisValue(key, String(n), 24 * 60 * 60).catch(() => {});
    }
    return n;
  } catch {
    return null;
  }
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse
) {
  // GET — list all saved rules (admin only); ?format=json|csv → download
  if (req.method === "GET") {
    const session = await requireAdmin(req, res);
    if (!session) return;
    const rows = await many<{
      tld: string; grace_period_days: number; redemption_period_days: number;
      pending_delete_days: number; total_release_days: number; source_url: string | null;
      confidence: string; drop_hour: number | null; drop_minute: number | null;
      drop_second: number | null; drop_timezone: string | null; pre_expiry_days: number | null;
      scraped_at: string | null; updated_at: string; model_used: string | null;
      ai_reasoning: string | null; manually_edited: boolean;
      scrape_status: string; failure_reason: string | null; fetch_strategy: string | null;
      fields_source: string | null;
      scrape_attempts: number; covered_by_override: boolean;
    }>(
      `SELECT r.tld, r.grace_period_days, r.redemption_period_days, r.pending_delete_days,
              r.grace_period_days + r.redemption_period_days + r.pending_delete_days AS total_release_days,
              r.source_url, r.confidence,
              r.drop_hour, r.drop_minute, r.drop_second, r.drop_timezone, r.pre_expiry_days,
              r.scraped_at, r.updated_at, r.model_used, r.ai_reasoning,
              COALESCE(r.manually_edited, FALSE) AS manually_edited,
              COALESCE(r.scrape_status, 'pending') AS scrape_status,
              COALESCE(r.needs_admin_review, FALSE) AS needs_admin_review,
              r.failure_reason, r.fetch_strategy, r.fields_source,
              COALESCE(r.scrape_attempts, 0) AS scrape_attempts,
              (o.tld IS NOT NULL) AS covered_by_override
       FROM tld_rules r
       LEFT JOIN tld_lifecycle_overrides o ON o.tld = r.tld
       ORDER BY r.tld`
    );

    const format = req.query.format as string | undefined;

    if (format === "json") {
      const date = new Date().toISOString().slice(0, 10);
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="tld-rules-${date}.json"`);
      return res.json({
        generated_at: new Date().toISOString(),
        count: rows.length,
        source: "tld_rules DB",
        rules: Object.fromEntries(rows.map((r) => [r.tld, r])),
      });
    }

    if (format === "csv") {
      const date = new Date().toISOString().slice(0, 10);
      res.setHeader("Content-Type", "text/csv; charset=utf-8");
      res.setHeader("Content-Disposition", `attachment; filename="tld-rules-${date}.csv"`);
      const header = "tld,grace_period_days,redemption_period_days,pending_delete_days,total_release_days,drop_hour,drop_minute,drop_second,drop_timezone,pre_expiry_days,confidence,source_url,scraped_at";
      const lines = rows.map((r) =>
        [r.tld, r.grace_period_days, r.redemption_period_days, r.pending_delete_days,
         r.total_release_days, r.drop_hour ?? "", r.drop_minute ?? "", r.drop_second ?? "",
         r.drop_timezone ?? "", r.pre_expiry_days ?? "", r.confidence,
         `"${r.source_url ?? ""}"`, r.scraped_at ?? ""].join(",")
      );
      return res.send([header, ...lines].join("\n"));
    }

    /* IANA root zone non-IDN total — fetched live (matches batch-scrape's
       fetchAllIanaTlds), cached 24h. Fallback: last crawl progress total. */
    let IANA_TOTAL = 1285;
    try {
      const live = await fetchIanaTotalLive();
      if (live) IANA_TOTAL = live;
      else {
        const prog = await one<{ total: number }>(
          `SELECT total FROM tld_crawl_progress WHERE run_key='iana' ORDER BY updated_at DESC LIMIT 1`
        );
        if (prog?.total) IANA_TOTAL = prog.total;
      }
    } catch { /* keep fallback */ }

    const stats = {
      total: rows.length,
      ianaTotal: IANA_TOTAL,
      remaining: Math.max(0, IANA_TOTAL - rows.length),
      ok: rows.filter(r => r.scrape_status === "ok" || r.manually_edited).length,
      warn_defaults: rows.filter(r => r.scrape_status === "warn_defaults" && !r.manually_edited).length,
      failed: rows.filter(r => r.scrape_status === "failed" && !r.manually_edited).length,
      pending: rows.filter(r => r.scrape_status === "pending" && !r.manually_edited).length,
      no_data: rows.filter(r => r.scrape_status === "no_data" && !r.manually_edited).length,
      manually_edited: rows.filter(r => r.manually_edited).length,
    };

    return res.json({ rules: rows, stats });
  }

  // POST — scrape + AI extract + save (via unified scrapeTld service, R6)
  if (req.method === "POST") {
    const session = await requireAdmin(req, res);
    if (!session) return;

    const { tld, source_url, force, model } = req.body as {
      tld?: string;
      source_url?: string;
      force?: boolean;
      model?: string;
    };
    if (!tld) {
      return res.status(400).json({ error: "tld is required" });
    }
    const cleanTld = tld.toLowerCase().replace(/^\./, "");
    // Default to IANA root-db page if no URL supplied; validate user-supplied URLs
    const rawUrl = (source_url ?? "").trim();
    if (rawUrl) {
      const check = validatePublicUrl(rawUrl);
      if (!check.ok) return res.status(400).json({ error: check.error });
    }
    const cleanUrl = rawUrl || `https://www.iana.org/domains/root/db/${cleanTld}.html`;

    // ── Skip check ────────────────────────────────────────────────────────
    // Skip only if: manually edited (always protected) or scrape_status='ok' (real data already scraped).
    // Records with warn_defaults / failed / pending are always re-attempted.
    if (!force) {
      const existing = await one<{
        scraped_at: Date | null; grace_period_days: number; redemption_period_days: number;
        pending_delete_days: number; drop_hour: number | null; drop_timezone: string | null;
        manually_edited: boolean; scrape_status: string;
      }>(
        `SELECT scraped_at, grace_period_days, redemption_period_days, pending_delete_days,
                drop_hour, drop_timezone,
                COALESCE(manually_edited, FALSE) AS manually_edited,
                COALESCE(scrape_status, 'pending') AS scrape_status
         FROM tld_rules WHERE tld = $1`,
        [cleanTld]
      ).catch(() => null);

      // Protect manually-edited records from being overwritten by scraper
      if (existing?.manually_edited) {
        return res.status(200).json({
          skipped: true,
          tld: cleanTld,
          reason: "manually_edited",
          grace_period_days: existing.grace_period_days,
          redemption_period_days: existing.redemption_period_days,
          pending_delete_days: existing.pending_delete_days,
          drop_hour: existing.drop_hour,
          drop_timezone: existing.drop_timezone,
        });
      }

      // Skip only if already successfully scraped (non-default data confirmed)
      if (existing?.scrape_status === "ok") {
        return res.status(200).json({
          skipped: true,
          tld: cleanTld,
          reason: "already_ok",
          scraped_at: existing.scraped_at?.toISOString() ?? null,
          grace_period_days: existing.grace_period_days,
          redemption_period_days: existing.redemption_period_days,
          pending_delete_days: existing.pending_delete_days,
          drop_hour: existing.drop_hour,
          drop_timezone: existing.drop_timezone,
        });
      }
      // Records with warn_defaults, failed, or pending fall through to re-scrape
    }

    // Rate limit (anti-spam: 1 scrape per TLD per hour)
    const allowed = await checkRateLimit(cleanTld);
    if (!allowed) {
      return res.status(429).json({
        error: `Rate limited: .${cleanTld} was already queried recently. Try again later.`,
      });
    }

    const result = await scrapeTld({
      tld: cleanTld,
      sourceUrl: rawUrl || undefined,
      preferredModel: model,
      force: !!force,
    });

    if (!result.ok || !result.extracted || !result.scrapeStatus) {
      // Release the rate-limit token on error so retries are possible
      deleteRedisValue(RATE_LIMIT_KEY(cleanTld)).catch(() => {});
      return res.status(500).json({ error: result.error ?? "Unknown error" });
    }

    const extracted = result.extracted;
    const total_release_days =
      extracted.grace_period_days +
      extracted.redemption_period_days +
      extracted.pending_delete_days;

    // ── Also persist to local JSON file (dual storage / backup) ──────────
    updateLocalCache(cleanTld, {
      grace_period_days: extracted.grace_period_days,
      redemption_period_days: extracted.redemption_period_days,
      pending_delete_days: extracted.pending_delete_days,
      total_release_days,
      drop_hour: extracted.drop_hour,
      drop_minute: extracted.drop_minute,
      drop_second: extracted.drop_second,
      drop_timezone: extracted.drop_timezone,
      pre_expiry_days: extracted.pre_expiry_days,
      confidence: extracted.confidence,
      source_url: result.finalUrl,
      reasoning: extracted.reasoning,
    });

    return res.json({
      ok: true,
      tld: cleanTld,
      ...extracted,
      total_release_days,
      source_url: result.finalUrl,
      source_url_requested: cleanUrl,
      has_lifecycle_info: result.hasLifecycleInfo,
      fetch_strategy: result.fetchStrategy ?? null,
      scrape_status: result.scrapeStatus,
      is_defaults: result.scrapeStatus === "warn_defaults",
    });
  }

  // PATCH — manual edit OR admin special actions (reset / bulk re-scrape)
  if (req.method === "PATCH") {
    const session = await requireAdmin(req, res);
    if (!session) return;

    // Special action: reset an exhausted no_data TLD back to pending for retry
    if (req.body?.action === "reset-to-pending") {
      const cleanTld = String(req.body.tld || "").toLowerCase().replace(/^\./, "");
      if (!cleanTld) return res.status(400).json({ error: "tld is required" });
      await run(
        `UPDATE tld_rules
         SET scrape_status='pending', needs_admin_review=FALSE,
             scrape_attempts=0, failure_reason=NULL, updated_at=NOW()
         WHERE tld=$1`,
        [cleanTld]
      );
      return res.json({ ok: true, message: `已将 .${cleanTld} 重置为待抓取状态` });
    }

    // Special action: bulk re-scrape selected TLDs (R13 AC2) — resets each
    // selected non-manual rule to pending, then runs scrapeTld one by one,
    // continuing past individual failures (R13 AC3).
    if (req.body?.action === "rescan-many") {
      const tlds: string[] = Array.isArray(req.body.tlds)
        ? req.body.tlds.map((t: unknown) => String(t).toLowerCase().replace(/^\./, "")).filter(Boolean)
        : [];
      if (tlds.length === 0) return res.status(400).json({ error: "tlds is required" });

      const results: Array<{ tld: string; ok: boolean; scrape_status?: string; error: string | null }> = [];
      for (const t of tlds) {
        // Reset to pending (skip manually-edited rows — R13 AC4)
        await run(
          `UPDATE tld_rules
           SET scrape_status='pending', needs_admin_review=FALSE,
               scrape_attempts=0, failure_reason=NULL, updated_at=NOW()
           WHERE tld=$1 AND COALESCE(manually_edited, FALSE) = FALSE`,
          [t]
        ).catch(() => {});
        const r = await scrapeTld({ tld: t, force: true });
        results.push({
          tld: t,
          ok: r.ok,
          scrape_status: r.scrapeStatus,
          error: r.ok ? null : (r.error ?? "Unknown error"),
        });
      }
      invalidateLifecycleOverridesCache();
      return res.json({ ok: true, processed: results.length, results });
    }

    const {
      tld, grace_period_days, redemption_period_days, pending_delete_days,
      drop_hour, drop_minute, drop_second, drop_timezone, pre_expiry_days, source_url,
    } = req.body as {
      tld?: string;
      grace_period_days?: number;
      redemption_period_days?: number;
      pending_delete_days?: number;
      drop_hour?: number | null;
      drop_minute?: number | null;
      drop_second?: number | null;
      drop_timezone?: string | null;
      pre_expiry_days?: number | null;
      source_url?: string | null;
    };

    if (!tld) return res.status(400).json({ error: "tld is required" });
    const cleanTld = tld.toLowerCase().replace(/^\./, "");

    const toInt = (v: unknown, fallback = 0) =>
      v === null || v === undefined || v === "" ? fallback : Math.max(0, parseInt(String(v)) || fallback);
    const toNullInt = (v: unknown, lo: number, hi: number): number | null => {
      if (v === null || v === undefined || v === "") return null;
      const n = parseInt(String(v));
      return isNaN(n) ? null : Math.min(hi, Math.max(lo, n));
    };

    await run(
      `INSERT INTO tld_rules
         (tld, grace_period_days, redemption_period_days, pending_delete_days,
          source_url, confidence, manually_edited, drop_hour, drop_minute, drop_second,
          drop_timezone, pre_expiry_days, updated_at, created_at)
       VALUES ($1,$2,$3,$4,$5,'high',TRUE,$6,$7,$8,$9,$10,NOW(),NOW())
       ON CONFLICT (tld) DO UPDATE SET
         grace_period_days      = EXCLUDED.grace_period_days,
         redemption_period_days = EXCLUDED.redemption_period_days,
         pending_delete_days    = EXCLUDED.pending_delete_days,
         source_url             = COALESCE(EXCLUDED.source_url, tld_rules.source_url),
         confidence             = 'high',
         manually_edited        = TRUE,
         drop_hour              = EXCLUDED.drop_hour,
         drop_minute            = EXCLUDED.drop_minute,
         drop_second            = EXCLUDED.drop_second,
         drop_timezone          = EXCLUDED.drop_timezone,
         pre_expiry_days        = EXCLUDED.pre_expiry_days,
         ai_reasoning           = COALESCE(tld_rules.ai_reasoning, '手动录入'),
         updated_at             = NOW()`,
      [
        cleanTld,
        toInt(grace_period_days, 30),
        toInt(redemption_period_days, 30),
        toInt(pending_delete_days, 5),
        source_url ?? null,
        toNullInt(drop_hour, 0, 23),
        toNullInt(drop_minute, 0, 59),
        toNullInt(drop_second, 0, 59),
        typeof drop_timezone === "string" && drop_timezone ? drop_timezone.slice(0, 50) : null,
        toNullInt(pre_expiry_days, 0, 365),
      ]
    );

    // Update local JSON cache
    updateLocalCache(cleanTld, {
      grace_period_days: toInt(grace_period_days, 30),
      redemption_period_days: toInt(redemption_period_days, 30),
      pending_delete_days: toInt(pending_delete_days, 5),
      total_release_days: toInt(grace_period_days, 30) + toInt(redemption_period_days, 30) + toInt(pending_delete_days, 5),
      confidence: "high",
      manually_edited: true,
      source_url: source_url ?? null,
    });

    // Immediately invalidate lifecycle override cache so manual edit is live
    invalidateLifecycleOverridesCache();

    return res.json({ ok: true, tld: cleanTld, manually_edited: true });
  }

  // DELETE — remove a rule, or purge all failed records
  if (req.method === "DELETE") {
    const session = await requireAdmin(req, res);
    if (!session) return;

    const body = req.body as { tld?: string; action?: string };

    // ── Purge all failed/no_data non-manual records ──────────────────────────
    if (body.action === "purge_failed") {
      const result = await run(
        `DELETE FROM tld_rules WHERE scrape_status IN ('failed','no_data','warn_defaults') AND manually_edited = FALSE`
      );
      invalidateLifecycleOverridesCache();
      return res.json({ ok: true, deleted: (result as any).rowCount ?? 0 });
    }

    const { tld } = body;
    if (!tld) return res.status(400).json({ error: "tld is required" });
    const cleanTld = tld.toLowerCase().replace(/^\./, "");
    await run("DELETE FROM tld_rules WHERE tld=$1", [cleanTld]);
    // Also clear the raw-page scrape cache so a fresh re-scrape fetches live data
    deleteRedisValue(SCRAPE_CACHE_KEY(
      `https://www.iana.org/domains/root/db/${cleanTld}.html`
    )).catch(() => {});
    // Invalidate lifecycle cache so deletion takes effect immediately
    invalidateLifecycleOverridesCache();
    return res.json({ ok: true });
  }

  res.setHeader("Allow", "GET, POST, PATCH, DELETE");
  res.status(405).json({ error: "Method not allowed" });
}
