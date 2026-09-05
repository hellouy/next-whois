import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { one, isDbReady } from "@/lib/db-query";
import { checkRateLimit } from "@/lib/rate-limit";
import { isAdminEmail } from "@/lib/admin-server";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/user/delete-account");

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "DELETE") return res.status(405).end();

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "Unauthorized" });

  const ip = String(
    req.headers["x-forwarded-for"] || req.socket?.remoteAddress || "unknown"
  ).split(",")[0].trim();
  const rl = await checkRateLimit(`delete-account:${ip}`, 3, 60 * 60 * 1000);
  if (!rl.ok) return res.status(429).json({ error: "Too many attempts, please try again later" });

  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  const email = session.user.email;

  // Guard against deleting the admin account — check both the env-var fallback
  // and the DB-backed admin email (which may differ from the env var).
  if (await isAdminEmail(email)) {
    return res.status(403).json({ error: "The founder account cannot be deleted" });
  }

  const { confirmEmail } = req.body as { confirmEmail?: string };
  if (!confirmEmail || confirmEmail.toLowerCase().trim() !== email.toLowerCase()) {
    return res.status(400).json({ error: "Email confirmation does not match, please try again" });
  }

  try {
    const result = await one<{
      email: string | null; reminders: string; emails: string; stamps: string;
    }>(
      `WITH del AS (
         DELETE FROM users WHERE email = $1 RETURNING email
       ),
       rem AS (
         UPDATE reminders
         SET active = false, cancelled_at = NOW(), cancel_reason = 'account_deleted'
         WHERE email = (SELECT email FROM del) AND active = true
         RETURNING id
       ),
       eq AS (
         DELETE FROM email_queue
         WHERE to_email = (SELECT email FROM del) AND status = 'pending'
         RETURNING id
       ),
       st AS (
         DELETE FROM stamps WHERE email = (SELECT email FROM del) RETURNING id
       )
       SELECT
         (SELECT email FROM del)                          AS email,
         (SELECT COUNT(*) FROM rem)::text                 AS reminders,
         (SELECT COUNT(*) FROM eq)::text                  AS emails,
         (SELECT COUNT(*) FROM st)::text                  AS stamps`,
      [email],
    );
    if (!result?.email) return res.status(404).json({ error: "User not found" });

    return res.status(200).json({
      ok: true,
      cleaned: {
        reminders: parseInt(result.reminders, 10) || 0,
        emails: parseInt(result.emails, 10) || 0,
        stamps: parseInt(result.stamps, 10) || 0,
      },
    });
  } catch (err: any) {
    logger.error("[delete-account]", err.message);
    return res.status(500).json({ error: "Deletion failed, please try again" });
  }
}
