/**
 * POST /api/admin/process-email-queue
 *
 * Processes the pending email_queue table: retries queued emails in
 * chronological order using sendEmailDirect (which throws on failure so
 * the queue can track attempts and apply exponential back-off).
 *
 * Called by the cron job (remind/process already runs on a schedule) or
 * triggered manually from the admin panel.
 *
 * Query params:
 *   ?limit=50   — max emails to process per invocation (default 50)
 *   ?requeue=1  — reset all 'failed' rows back to 'pending' before processing
 *
 * Returns: { processed, sent, retried, failed, errors, stats }
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { sendEmailDirect } from "@/lib/email";
import {
  processEmailQueue,
  getQueueStats,
  requeueFailed,
} from "@/lib/email-queue";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "POST") return res.status(405).end();

  const session = await requireAdmin(req, res);
  if (!session) return;

  const limit   = Math.min(parseInt(String(req.query.limit  ?? 50)), 200);
  const requeue = req.query.requeue === "1" || req.body?.requeue === true;

  let requeued = 0;
  if (requeue) {
    requeued = await requeueFailed().catch(() => 0);
    console.log(`[process-email-queue] Re-queued ${requeued} failed emails`);
  }

  const result = await processEmailQueue(sendEmailDirect, limit);
  const stats  = await getQueueStats().catch(() => null);

  return res.status(200).json({
    ok: true,
    requeued,
    ...result,
    stats,
  });
}
