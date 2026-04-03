/**
 * GET  /api/admin/process-email-queue  — called by Vercel Cron (CRON_SECRET Bearer auth)
 * POST /api/admin/process-email-queue  — called from the admin dashboard (session auth)
 *
 * Processes the pending email_queue table: retries queued emails in
 * chronological order using sendEmailDirect (which throws on failure so
 * the queue can track attempts and apply exponential back-off).
 *
 * Query params:
 *   ?limit=50   — max emails to process per invocation (default 50)
 *   ?requeue=1  — reset all 'failed' rows back to 'pending' before processing
 *
 * Returns: { processed, sent, retried, failed, errors, stats }
 */

import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { isAdminEmail } from "@/lib/admin-server";
import { sendEmailDirect } from "@/lib/email";
import {
  processEmailQueue,
  getQueueStats,
  requeueFailed,
} from "@/lib/email-queue";

async function isAuthorized(req: NextApiRequest, res: NextApiResponse): Promise<boolean> {
  const cronSecret = process.env.CRON_SECRET;
  if (cronSecret) {
    const authHeader = req.headers.authorization ?? "";
    const bearer = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : undefined;
    if (bearer === cronSecret) return true;
  }
  try {
    const session = await getServerSession(req, res, authOptions);
    const email = (session?.user as any)?.email;
    return await isAdminEmail(email);
  } catch {
    return false;
  }
}

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET" && req.method !== "POST") return res.status(405).end();

  if (!(await isAuthorized(req, res))) {
    return res.status(403).json({ error: "Forbidden" });
  }

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
