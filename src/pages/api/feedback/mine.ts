import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { many, isDbReady } from "@/lib/db-query";

/**
 * GET /api/feedback/mine — the signed-in user's own feedback history,
 * including any admin inline replies. Anonymous callers get an empty list.
 */
export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();

  const session = await getServerSession(req, res, authOptions);
  if (!session?.user?.email) return res.status(200).json({ feedback: [] });

  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  try {
    const rows = await many(
      `SELECT id, query, query_type, issue_types, description,
              created_at, handled, reply, replied_at
       FROM feedback
       WHERE email = $1
       ORDER BY created_at DESC
       LIMIT 50`,
      [session.user.email],
    );
    return res.status(200).json({ feedback: rows });
  } catch {
    return res.status(500).json({ error: "加载反馈历史失败" });
  }
}
