/**
 * Vercel Cron — Automatic TLD Lifecycle Batch Scraper
 *
 * Scheduled in vercel.json. Picks the next batch of pending/failed TLDs
 * from the database and scrapes them using the existing AI extraction pipeline.
 *
 * Priority queue:
 *   1. pending        — never scraped
 *   2. warn_defaults  — only got ICANN defaults last time (worth retrying)
 *   3. failed         — network/parse errors under the retry threshold
 *
 * Skipped: manually_edited=true, scrape_status='ok', scrape_status='no_data'
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { one, run, many } from "@/lib/db-query";
import { fetchPageText, extractWithAI } from "@/pages/api/admin/tld-rules";
import { invalidateLifecycleOverridesCache } from "@/lib/server/lifecycle-overrides";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/cron/tld-scrape");

const BATCH_SIZE = 5;
const MAX_WARN_ATTEMPTS = 3;
const MAX_FAILED_ATTEMPTS = 5;

interface TldQueueRow {
  tld: string;
  scrape_status: string;
  scrape_attempts: number;
}

function isAllDefaults(r: {
  grace_period_days: number;
  redemption_period_days: number;
  pending_delete_days: number;
}) {
  return (
    r.grace_period_days === 30 &&
    r.redemption_period_days === 30 &&
    r.pending_delete_days === 5
  );
}

async function saveTldRule(
  tld: string,
  extracted: {
    grace_period_days: number;
    redemption_period_days: number;
    pending_delete_days: number;
    drop_hour: number | null;
    drop_minute: number | null;
    drop_second: number | null;
    drop_timezone: string | null;
    pre_expiry_days: number | null;
    reasoning: string;
    model_used: string;
  },
  finalUrl: string,
  scrapeStatus: string
) {
  await run(
    `INSERT INTO tld_rules
       (tld, grace_period_days, redemption_period_days, pending_delete_days,
        source_url, confidence, ai_reasoning, model_used,
        drop_hour, drop_minute, drop_second, drop_timezone, pre_expiry_days,
        scraped_at, updated_at, scrape_status, failure_reason, needs_admin_review, scrape_attempts)
     VALUES ($1,$2,$3,$4,$5,'ai',$6,$7,$8,$9,$10,$11,$12,NOW(),NOW(),$13,NULL,$14,1)
     ON CONFLICT (tld) DO UPDATE SET
       grace_period_days      = EXCLUDED.grace_period_days,
       redemption_period_days = EXCLUDED.redemption_period_days,
       pending_delete_days    = EXCLUDED.pending_delete_days,
       source_url             = EXCLUDED.source_url,
       confidence             = 'ai',
       ai_reasoning           = EXCLUDED.ai_reasoning,
       model_used             = EXCLUDED.model_used,
       drop_hour              = EXCLUDED.drop_hour,
       drop_minute            = EXCLUDED.drop_minute,
       drop_second            = EXCLUDED.drop_second,
       drop_timezone          = EXCLUDED.drop_timezone,
       pre_expiry_days        = EXCLUDED.pre_expiry_days,
       scraped_at             = NOW(),
       updated_at             = NOW(),
       scrape_status          = EXCLUDED.scrape_status,
       failure_reason         = NULL,
       needs_admin_review     = EXCLUDED.needs_admin_review,
       scrape_attempts        = COALESCE(tld_rules.scrape_attempts, 0) + 1`,
    [
      tld,
      extracted.grace_period_days,
      extracted.redemption_period_days,
      extracted.pending_delete_days,
      finalUrl,
      extracted.reasoning,
      extracted.model_used || null,
      extracted.drop_hour,
      extracted.drop_minute,
      extracted.drop_second,
      extracted.drop_timezone,
      extracted.pre_expiry_days ?? 0,
      scrapeStatus,
      scrapeStatus !== "ok",
    ]
  );
}

async function saveFailure(tld: string, reason: string) {
  await run(
    `INSERT INTO tld_rules
       (tld, grace_period_days, redemption_period_days, pending_delete_days,
        scrape_status, failure_reason, scraped_at, updated_at,
        needs_admin_review, confidence, scrape_attempts)
     VALUES ($1,30,30,5,'failed',$2,NOW(),NOW(),TRUE,'low',1)
     ON CONFLICT (tld) DO UPDATE SET
       scrape_status      = 'failed',
       failure_reason     = $2,
       scraped_at         = NOW(),
       updated_at         = NOW(),
       needs_admin_review = TRUE,
       scrape_attempts    = COALESCE(tld_rules.scrape_attempts, 0) + 1`,
    [tld, reason.slice(0, 500)]
  ).catch((e: Error) =>
    logger.warn(`[cron/tld-scrape] DB write failure for ${tld}:`, e.message)
  );
}

async function markNoData(tld: string, reason: string) {
  await run(
    `UPDATE tld_rules
     SET scrape_status='no_data', needs_admin_review=TRUE,
         failure_reason=$2, updated_at=NOW()
     WHERE tld=$1`,
    [tld, reason.slice(0, 500)]
  ).catch(() => {});
}

async function getNextBatch(): Promise<TldQueueRow[]> {
  const rows = await many<TldQueueRow>(
    `SELECT tld, COALESCE(scrape_status,'pending') AS scrape_status,
            COALESCE(scrape_attempts,0) AS scrape_attempts
     FROM tld_rules
     WHERE COALESCE(manually_edited, FALSE) = FALSE
       AND COALESCE(scrape_status,'pending') IN ('pending','warn_defaults','failed')
       AND COALESCE(scrape_status,'pending') != 'no_data'
     ORDER BY
       CASE COALESCE(scrape_status,'pending')
         WHEN 'pending'       THEN 1
         WHEN 'warn_defaults' THEN 2
         WHEN 'failed'        THEN 3
         ELSE 4
       END,
       COALESCE(scrape_attempts,0) ASC,
       tld ASC
     LIMIT $1`,
    [BATCH_SIZE]
  );
  return rows;
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST") {
    return res.status(405).end();
  }

  const cronSecret = process.env.CRON_SECRET;
  if (cronSecret) {
    const auth = req.headers.authorization;
    const legacy = req.headers["x-cron-secret"] as string | undefined;
    const provided = auth?.startsWith("Bearer ") ? auth.slice(7) : legacy;
    if (provided !== cronSecret) {
      return res.status(401).json({ error: "unauthorized" });
    }
  } else {
    // Fail-closed: without CRON_SECRET only an admin session may run the
    // AI scrape pipeline (it consumes AI quota and writes tld_rules).
    const { requireAdmin } = await import("@/lib/admin");
    const session = await requireAdmin(req, res);
    if (!session) return;
  }

  const batch = await getNextBatch();

  if (batch.length === 0) {
    logger.info("[cron/tld-scrape] No pending TLDs — all done or exhausted.");
    return res.json({ ok: true, processed: 0, message: "No pending TLDs" });
  }

  logger.info(`[cron/tld-scrape] Processing ${batch.length} TLDs: ${batch.map(r => r.tld).join(", ")}`);

  const results: Array<{
    tld: string;
    status: "ok" | "warn_defaults" | "failed" | "no_data" | "skipped";
    model?: string;
    error?: string;
  }> = [];

  for (const row of batch) {
    const { tld, scrape_status, scrape_attempts } = row;

    if (
      (scrape_status === "warn_defaults" && scrape_attempts >= MAX_WARN_ATTEMPTS) ||
      (scrape_status === "failed" && scrape_attempts >= MAX_FAILED_ATTEMPTS)
    ) {
      const reason = `已连续 ${scrape_attempts} 次 ${scrape_status}，自动标记为 no_data`;
      await markNoData(tld, reason);
      results.push({ tld, status: "no_data" });
      logger.info(`[cron/tld-scrape] .${tld} → no_data (exhausted ${scrape_attempts} attempts)`);
      continue;
    }

    const ianaUrl = `https://www.iana.org/domains/root/db/${tld}.html`;

    try {
      const { text: pageText, finalUrl } = await fetchPageText(ianaUrl);

      if (!pageText || pageText.length < 50) {
        throw new Error("页面内容为空");
      }

      const extracted = await extractWithAI(tld, pageText, finalUrl);

      const scrapeStatus = isAllDefaults(extracted) ? "warn_defaults" : "ok";
      await saveTldRule(tld, extracted, finalUrl, scrapeStatus);
      invalidateLifecycleOverridesCache();

      results.push({ tld, status: scrapeStatus, model: extracted.model_used });
      logger.info(
        `[cron/tld-scrape] .${tld} → ${scrapeStatus} | grace=${extracted.grace_period_days}d redemption=${extracted.redemption_period_days}d pending=${extracted.pending_delete_days}d [${extracted.model_used}]`
      );
    } catch (err: any) {
      const reason = (err.message ?? String(err)).slice(0, 400);
      await saveFailure(tld, reason);
      results.push({ tld, status: "failed", error: reason.slice(0, 120) });
      logger.error(`[cron/tld-scrape] .${tld} → failed: ${reason.slice(0, 120)}`);
    }
  }

  const summary = {
    ok: results.filter(r => r.status === "ok").length,
    warn_defaults: results.filter(r => r.status === "warn_defaults").length,
    failed: results.filter(r => r.status === "failed").length,
    no_data: results.filter(r => r.status === "no_data").length,
  };

  logger.info(`[cron/tld-scrape] Done. ok=${summary.ok} warn=${summary.warn_defaults} failed=${summary.failed} no_data=${summary.no_data}`);

  return res.json({
    ok: true,
    processed: results.length,
    summary,
    results,
    ts: new Date().toISOString(),
  });
}
