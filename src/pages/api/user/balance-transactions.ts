import type { NextApiRequest, NextApiResponse } from "next";
import { getServerSession } from "next-auth/next";
import { authOptions } from "@/pages/api/auth/[...nextauth]";
import { many, one, isDbReady } from "@/lib/db-query";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== "GET") return res.status(405).end();
  if (!(await isDbReady())) return res.status(503).json({ error: "Service temporarily unavailable" });

  const session = await getServerSession(req, res, authOptions);
  if (!(session?.user as any)?.id) return res.status(401).json({ error: "Unauthorized" });

  const userId = (session!.user as any).id as string;

  try {
    const [transactions, balanceRow] = await Promise.all([
      many<{
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
         LIMIT 30`,
        [userId]
      ),
      one<{ balance_cents: number }>(
        `SELECT balance_cents FROM users WHERE id = $1`,
        [userId]
      ).catch(() => null),
    ]);

    return res.json({
      transactions,
      balanceCents: balanceRow?.balance_cents ?? 0,
    });
  } catch (err: any) {
    console.error("[user/balance-transactions]", err.message);
    return res.status(500).json({ error: "Failed to retrieve balance records" });
  }
}
