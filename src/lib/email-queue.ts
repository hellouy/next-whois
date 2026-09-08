/**
 * email-queue.ts
 * Persistent email queue backed by PostgreSQL.
 *
 * Flow:
 *   sendEmail() fails  →  enqueueEmail()  →  email_queue (status='pending')
 *   cron triggers      →  processEmailQueue()  →  sendEmailDirect() per row
 *                            success  →  status='sent'
 *                            failure  →  attempts++, next_retry_at += backoff
 *                            attempts >= max_attempts  →  status='failed'
 *
 * Retry back-off (minutes): 2 · 2^(attempt-1)
 *   attempt 1 → 2 min, 2 → 4, 3 → 8, 4 → 16, 5 → final failure
 */

import { run as dbQuery, many, one } from "@/lib/db-query";
import { createLogger } from "@/lib/logger";

const logger = createLogger("email-queue");

export interface QueuedEmail {
  id: number;
  to_email: string;
  subject: string;
  html: string;
  status: string;
  attempts: number;
  max_attempts: number;
  next_retry_at: Date;
  last_error: string | null;
  created_at: Date;
  sent_at: Date | null;
}

export interface QueueStats {
  pending: number;
  sent: number;
  failed: number;
  total: number;
}

function retryDelayMinutes(attempt: number): number {
  return Math.pow(2, attempt);
}

export async function enqueueEmail(
  to: string,
  subject: string,
  html: string,
): Promise<void> {
  try {
    await dbQuery(
      `INSERT INTO email_queue (to_email, subject, html) VALUES ($1, $2, $3)`,
      [to, subject, html],
    );
    logger.info(`[email-queue] Queued → ${to} | "${subject}"`);
  } catch (err: any) {
    logger.error("[email-queue] Failed to enqueue:", err.message);
  }
}

export interface ProcessResult {
  processed: number;
  sent: number;
  retried: number;
  failed: number;
  errors: string[];
}

/**
 * Process the pending email queue.
 * Must be called with a `sender` function to avoid circular imports.
 * Pass `sendEmailDirect` from email.ts.
 */
export async function processEmailQueue(
  sender: (to: string, subject: string, html: string) => Promise<void>,
  limit = 50,
): Promise<ProcessResult> {
  const result: ProcessResult = { processed: 0, sent: 0, retried: 0, failed: 0, errors: [] };

  const { getDbReady } = await import("@/lib/db");
  const db = await getDbReady();
  if (!db) return result;

  // Two-phase processing:
  //   Phase 1 — claim a batch atomically (status='processing' + processing_at).
  //              COMMIT immediately so the long SMTP loop holds no row locks.
  //   Phase 2 — send each email, then persist its outcome with individual
  //              autocommit UPDATEs. A crash mid-batch only re-runs the unclaimed
  //              rows + possibly the single in-flight one (recovered below).

  // Recover stale 'processing' rows from a previous crashed run first.
  try {
    await db.query(
      `UPDATE email_queue SET status = 'pending', processing_at = NULL
        WHERE status = 'processing' AND processing_at < NOW() - interval '15 minutes'`,
    );
  } catch (err: any) {
    result.errors.push(`recovery error: ${err.message}`);
    logger.error("[email-queue] recovery update failed:", err.message);
  }

  // ── Phase 1: atomically claim up to `limit` rows ───────────────────────────
  let client: any = null;
  let claimed: QueuedEmail[] = [];
  try {
    client = await db.connect();
    await client.query("BEGIN");
    const { rows } = await client.query(
      `UPDATE email_queue
          SET status = 'processing', processing_at = NOW()
        WHERE id IN (
          SELECT id FROM email_queue
           WHERE status = 'pending' AND next_retry_at <= NOW()
           ORDER BY created_at ASC, id ASC
           LIMIT $1
           FOR UPDATE SKIP LOCKED
        )
        RETURNING id, to_email, subject, html, status, attempts, max_attempts,
                  next_retry_at, last_error, created_at, sent_at`,
      [limit],
    );
    claimed = rows;
    await client.query("COMMIT");
    client.release();
    client = null;
  } catch (err: any) {
    if (client) try { await client.query("ROLLBACK").catch(() => {}); client.release(); } catch {}
    result.errors.push(`fetch error: ${err.message}`);
    logger.error("[email-queue] claim error:", err.message);
    return result;
  }

  if (claimed.length === 0) return result;

  // ── Phase 2: send one by one, persisting each outcome immediately ───────────
  for (const row of claimed) {
    result.processed++;
    try {
      await sender(row.to_email, row.subject, row.html);
      await db.query(
        `UPDATE email_queue SET status = 'sent', sent_at = NOW(), processing_at = NULL,
                last_error = NULL WHERE id = $1`,
        [row.id],
      );
      result.sent++;
      logger.info(`[email-queue] Sent #${row.id} → ${row.to_email}`);
    } catch (err: any) {
      const errMsg = err?.message || "unknown error";
      const nextAttempt = row.attempts + 1;

      // Per-row bookkeeping; never abort the whole batch loop.
      try {
        if (nextAttempt >= row.max_attempts) {
          await db.query(
            `UPDATE email_queue
                SET status = 'failed', attempts = $2, last_error = $3, processing_at = NULL
              WHERE id = $1`,
            [row.id, nextAttempt, errMsg.slice(0, 500)],
          );
          result.failed++;
          logger.error(`[email-queue] Permanently failed #${row.id} → ${row.to_email}: ${errMsg}`);
          result.errors.push(`#${row.id} failed: ${errMsg}`);
        } else {
          const delay = retryDelayMinutes(nextAttempt);
          const nextAt = new Date(Date.now() + delay * 60 * 1000);
          await db.query(
            `UPDATE email_queue
                SET attempts = $2, last_error = $3, next_retry_at = $4,
                    status = 'pending', processing_at = NULL
              WHERE id = $1`,
            [row.id, nextAttempt, errMsg.slice(0, 500), nextAt.toISOString()],
          );
          result.retried++;
          logger.warn(`[email-queue] Retry scheduled #${row.id} in ${delay}min → ${row.to_email}: ${errMsg}`);
        }
      } catch (dbErr: any) {
        logger.error(`[email-queue] DB update failed for #${row.id}:`, dbErr.message);
        result.errors.push(`#${row.id} db update failed: ${dbErr.message}`);
      }
    }
  }

  return result;
}

export async function getQueueStats(): Promise<QueueStats> {
  const row = await one<QueueStats>(
    `SELECT
       COUNT(*) FILTER (WHERE status = 'pending') AS pending,
       COUNT(*) FILTER (WHERE status = 'sent')    AS sent,
       COUNT(*) FILTER (WHERE status = 'failed')  AS failed,
       COUNT(*)                                    AS total
     FROM email_queue`,
  ).catch(() => null);
  return row ?? { pending: 0, sent: 0, failed: 0, total: 0 };
}

export async function getQueueEntries(
  status?: string,
  limit = 50,
): Promise<QueuedEmail[]> {
  if (status) {
    return many<QueuedEmail>(
      `SELECT id, to_email, subject, status, attempts, max_attempts,
              next_retry_at, last_error, created_at, sent_at
         FROM email_queue
        WHERE status = $1
        ORDER BY created_at DESC
        LIMIT $2`,
      [status, limit],
    );
  }
  return many<QueuedEmail>(
    `SELECT id, to_email, subject, status, attempts, max_attempts,
            next_retry_at, last_error, created_at, sent_at
       FROM email_queue
      ORDER BY created_at DESC
      LIMIT $1`,
    [limit],
  );
}

export async function requeueFailed(): Promise<number> {
  const r = await dbQuery(
    `UPDATE email_queue
        SET status        = 'pending',
            attempts      = 0,
            last_error    = NULL,
            next_retry_at = NOW()
      WHERE status = 'failed'`,
  );
  return r;
}
