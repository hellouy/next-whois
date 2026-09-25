/**
 * Vercel Cron — Automatic TLD Lifecycle Batch Scraper
 *
 * Scheduled in vercel.json. Picks the next batch of pending/failed/warn_defaults
 * TLDs (plus stale 'ok' rows past their 180-day refresh TTL — R13) from the
 * database and scrapes them through the unified `scrapeTld` service.
 *
 * Priority queue:
 *   1. pending        — never scraped
 *   2. ok (stale)     — scraped successfully but older than 180 days (R13)
 *   3. warn_defaults  — only got ICANN defaults last time (worth retrying)
 *   4. failed         — network/parse errors under the retry threshold
 *
 * Skipped: manually_edited=true, scrape_status='no_data'
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { run, many } from "@/lib/db-query";
import { scrapeTld } from "@/lib/server/tld-scrape";
import { createLogger } from "@/lib/logger";
import { verifySecretTimingSafe } from "@/lib/admin";

const logger = createLogger("api/cron/tld-scrape");

const BATCH_SIZE = 5;
const MAX_WARN_ATTEMPTS = 3;
const MAX_FAILED_ATTEMPTS = 5;
const STALE_OK_DAYS = 180; // R13 AC1: refresh successfully-scraped rules past this age

interface TldQueueRow {
  tld: string;
  scrape_status: string;
  scrape_attempts: number;
}

async function markNoData(tld: string, reason: string) {
  await run(
    `UPDATE tld_rules
     SET scrape_status='no_data', needs_admin_review=TRUE,
         failure_reason=$2, updated_at=NOW(),
         processing_at=NULL, processing_from=NULL
     WHERE tld=$1`,
    [tld, reason.slice(0, 500)]
  ).catch(() => {});
}

async function getNextBatch(): Promise<TldQueueRow[]> {
  // Atomic claim: mark the picked rows as processing in the SAME statement that
  // selects them. Two overlapping cron runs can therefore never pick the same
  // TLD — the second run's UPDATE matches no rows still in a queued status.
  // Returns the pre-claim status per row so the caller keeps its queued-state logic.
  const rows = await many<TldQueueRow>(
    `WITH candidates AS (
       SELECT tld, COALESCE(scrape_status,'pending') AS scrape_status,
              COALESCE(scrape_attempts,0) AS scrape_attempts
       FROM tld_rules
       WHERE COALESCE(manually_edited, FALSE) = FALSE
         AND (
           COALESCE(scrape_status,'pending') IN ('pending','warn_defaults','failed')
           OR (scrape_status = 'ok' AND updated_at < NOW() - ($2 || ' days')::INTERVAL)
         )
         AND COALESCE(scrape_status,'pending') != 'no_data'
       ORDER BY
         CASE
           WHEN COALESCE(scrape_status,'pending') = 'pending'       THEN 1
           WHEN scrape_status = 'ok'                                THEN 2
           WHEN COALESCE(scrape_status,'pending') = 'warn_defaults' THEN 3
           WHEN COALESCE(scrape_status,'pending') = 'failed'        THEN 4
           ELSE 5
         END,
         COALESCE(scrape_attempts,0) ASC,
         tld ASC
       LIMIT $1
     )
     UPDATE tld_rules t
     SET    scrape_status = 'processing',
            processing_at = NOW(),
            processing_from = c.scrape_status
     FROM   candidates c
     WHERE  t.tld = c.tld
       AND  t.processing_at IS NULL
       AND  (
         COALESCE(t.scrape_status,'pending') IN ('pending','warn_defaults','failed')
         OR (t.scrape_status = 'ok' AND t.updated_at < NOW() - ($2 || ' days')::INTERVAL)
       )
     RETURNING t.tld,
               c.scrape_status,
               c.scrape_attempts`,
    [BATCH_SIZE, STALE_OK_DAYS]
  );
  return rows;
}

/**
 * Reclaim rows left in 'processing' by a crashed/overlong run (older than
 * 30 min). Their original queued status is restored from processing_from so the
 * next batch can pick them up again instead of being stuck forever.
 */
async function reclaimStaleProcessing(): Promise<void> {
  await run(
    `UPDATE tld_rules
     SET scrape_status = COALESCE(processing_from, 'failed'),
         processing_from = NULL,
         processing_at = NULL
     WHERE scrape_status = 'processing'
       AND processing_at IS NOT NULL
       AND processing_at < NOW() - INTERVAL '30 minutes'`,
  ).catch((e: Error) =>
    logger.warn("[cron/tld-scrape] stale processing reclaim failed:", e.message)
  );
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
    if (!verifySecretTimingSafe(provided, cronSecret)) {
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

  // Reclaim rows stuck in 'processing' by a crashed earlier run so they rejoin
  // the queue on subsequent invocations instead of blocking forever.
  await reclaimStaleProcessing();

  // Best-effort maintenance: prune diagnostic failure events older than 90d.
  // Fire-and-forget — never blocks the scrape queue.
  import("@/lib/server/failure-events")
    .then(m => m.pruneFailureEvents(90).catch(() => {}))
    .catch(() => {});

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

    const result = await scrapeTld({ tld, force: true });

    if (result.ok && result.scrapeStatus) {
      results.push({ tld, status: result.scrapeStatus, model: result.extracted?.model_used });
      logger.info(
        `[cron/tld-scrape] .${tld} → ${result.scrapeStatus} | grace=${result.extracted?.grace_period_days}d redemption=${result.extracted?.redemption_period_days}d pending=${result.extracted?.pending_delete_days}d [${result.extracted?.model_used}]`
      );
    } else {
      const reason = (result.error ?? "Unknown error").slice(0, 400);
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
