import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { one, many, isDbReady } from "@/lib/db-query";
import { markNotificationRead, markAllNotificationsRead } from "@/lib/notifications";
import { createLogger } from "@/lib/logger";

const logger = createLogger("api/user/notifications");

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(401).json({ error: "Unauthorized" });
  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  const email = session.user.email;

  if (req.method === "GET") {
    try {
      const limit = Math.min(Math.max(parseInt(String(req.query.limit ?? "50"), 10) || 50, 1), 100);
      const rows = await many<{
        id: string; type: string; title: string; body: string | null; domain: string | null;
        read_at: string | null; created_at: string;
      }>(
        `SELECT id, type, title, body, domain, read_at, created_at
         FROM user_notifications WHERE email = $1
         ORDER BY created_at DESC LIMIT $2`,
        [email, limit],
      );
      const unreadRow = await one<{ count: string }>(
        `SELECT COUNT(*)::text AS count FROM user_notifications WHERE email = $1 AND read_at IS NULL`,
        [email],
      );
      return res.status(200).json({
        notifications: rows.map(r => ({
          id: r.id,
          type: r.type,
          title: r.title,
          body: r.body,
          domain: r.domain,
          read: r.read_at !== null,
          created_at: r.created_at,
        })),
        unread: parseInt(unreadRow?.count ?? "0", 10),
      });
    } catch (err) {
      logger.error("[notifications] GET error:", err instanceof Error ? err.message : String(err));
      return res.status(500).json({ error: "Failed to retrieve notifications" });
    }
  }

  if (req.method === "POST") {
    const { id, markAll } = req.body ?? {};
    try {
      if (markAll) {
        await markAllNotificationsRead(email);
      } else if (id) {
        await markNotificationRead(String(id), email);
      } else {
        return res.status(400).json({ error: "Missing id or markAll" });
      }
      return res.status(200).json({ ok: true });
    } catch (err) {
      logger.error("[notifications] POST error:", err instanceof Error ? err.message : String(err));
      return res.status(500).json({ error: "Failed to update notifications" });
    }
  }

  return res.status(405).end();
}
