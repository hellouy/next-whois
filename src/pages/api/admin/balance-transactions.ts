import type { NextApiRequest, NextApiResponse } from "next";
import { requireAdmin } from "@/lib/admin";
import { many, isDbReady } from "@/lib/db-query";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const session = await requireAdmin(req, res);
  if (!session) return;
  if (!(await isDbReady())) return res.status(503).json({ error: "数据库暂不可用" });

  const userId = String(req.query.userId ?? "").trim();
  if (!userId) return res.status(400).json({ error: "Missing userId" });

  const rows = await many<{
    id: number;
    amount_cents: number;
    type: string;
    description: string | null;
    created_at: string;
  }>(
    `SELECT id, amount_cents, type, description, created_at
     FROM balance_transactions
     WHERE user_id = $1
     ORDER BY created_at DESC
     LIMIT 100`,
    [userId]
  );

  return res.json({ transactions: rows });
}
